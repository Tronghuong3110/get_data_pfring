#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <pfring.h>
#include <stdlib.h>
#include <signal.h>

// #define _GNU_SOURCE 
#define BURST_SIZE              32
#define DEFAULT_DEVICE          "eth0"
#define NO_ZC_BUFFER_LEN        9000
#define MAX_NUM_THREADS         64

volatile int keep_running = 1;
typedef unsigned char u_char;
typedef unsigned int u_int;
typedef unsigned long u_long;


struct app_stats {
    u_int64_t numpkts[MAX_NUM_THREADS];
    u_int64_t numBytes[MAX_NUM_THREADS];
    u_int64_t numStringMatches[MAX_NUM_THREADS];
    volatile u_int64_t do_shutdown;
};

struct app_stats *stats;
pfring *ring;
int num_threads = 1;
u_int8_t wait_for_packet = 1;
int bind2core(u_long core_id);

void signal_handler(int signum)
{
    keep_running = 0;
}

void* dummyProcessPacket(struct pfring_pkthdr* h, u_char* p, u_char *thread_id) {
    long threadId = (long) thread_id;
    struct pkt_parsing_info *hdr = &h->extended_hdr.parsed_pkt;
    if(!h->ts.tv_sec) 
        pfring_parse_pkt((u_char*)p, (struct pfring_pkthdr*)h, 4, 0, 1);
    // if(!hdr) {
        printf("Ip version: %d \n", hdr->ip_version);
        if(hdr->ip_version == 4) {
            char ipv4[INET_ADDRSTRLEN];
            if(inet_ntop(AF_INET, &hdr->ip_dst.v4, ipv4, sizeof(ipv4)) == NULL) {
                perror("Inet_ntop, IPV4");
            }
            printf("Ipv4: %s \n", ipv4);
        }
        else if(hdr -> ip_version == 6) {
            char ipv6[INET6_ADDRSTRLEN];
            if(inet_ntop(AF_INET6, &hdr->ip_src.v6, ipv6, sizeof(ipv6)) == NULL) {
                perror("Inet_ntop, IPV6");
            }
            printf("Ipv6: %s \n", ipv6);
        }
        // else {
        //     printf("Khong phai Ipv4 hoac Ipv6 \n");
        // }
    // }
    // else {
    //     printf("Loi khong hop le");
    // }

}

void* packet_consumer_thread(void* id) {
    long thread_id = (long) id;
    u_int numCpu = sysconf(_SC_NPROCESSORS_ONLN); // LAY SO CPU TRONG MAY
    // u_char buffer[65536];
    u_char* buffer = malloc(65536 * sizeof(int));
    u_char *buffer_p = buffer;
    u_long core_id = thread_id % numCpu;
    struct pfring_pkthdr hdr;

    // gan thread vao core id
    if(num_threads > 1 && numCpu > 1) {
        if(bind2core(core_id) == 0) { // gan thread chay tren core co id la core_id
            printf("Gan thread %lu vao core %lu/%u \n", thread_id, core_id, numCpu);
        }
    }

    memset(&hdr, 0, sizeof(hdr));
    while(keep_running) {
        int rc = pfring_recv(ring, &buffer_p, NO_ZC_BUFFER_LEN, &hdr, 1);
        // printf("RC = %d \n", rc);
        if(rc > 0) {
            // printf("Capture duoc ban tin");
            dummyProcessPacket(&hdr, buffer, (u_char*) thread_id);
            // printf("Goi tin bat duoc co do dai: %d byte \n", hdr.len);
        } 
        else {
            if(keep_running == 1) {
                break;
            }
            if(wait_for_packet == 0) {
                sched_yield(); // nha cpu
            }
        }

        // kiem tra cpu thread dang chay
        u_long current_cpu = sched_getcpu();
        if(current_cpu != core_id) {
            printf("Thread %ld dang chay tren cpu %lu, khong phai cpu %ld \n", thread_id, current_cpu, core_id);
        }  
    }
    return (NULL);
}

void* chunk_consumer_thread(void* id) {
    long thread_id = (long) id;
    u_int numCpu = sysconf( _SC_NPROCESSORS_ONLN);
    void* chunk_p = NULL;
    pfring_chunk_info chunk_info;
    u_long core_id = thread_id % numCpu;
    struct pfring_pkthdr hdr;

    if(num_threads > 1 && numCpu > 1) {
        if(bind2core(core_id) == 0) {
            printf("Thread %ld chay tren core %lu \n", thread_id, core_id);
        }
    }

    while (1)
    {
        if(keep_running == 0) {
            break;
        }

        int rc = pfring_recv_chunk(ring, &chunk_p, &chunk_info, 1);
        if(rc > 0) {
            // xu ly paclet nhan duoc
            //printf("")
        }
    }
    
}
int bind2core(u_long core_id) {
    // #ifdef HAVE_PTHREAD_SETAFFINITY_NP
    cpu_set_t cpuSet;
    CPU_ZERO(&cpuSet); // thiet lap cpuset la danh sach khong co cpu nao duoc chon
    CPU_SET(core_id, &cpuSet); // thiet lap bit tuong ung voi core_id trong cpuset 
    pthread_t currentThread = pthread_self(); // lay ra ID cua thread hien tai
    return pthread_setaffinity_np(currentThread, sizeof(cpu_set_t), &cpuSet); // thiet lap CPU affinity cho thread hien tai, thanh cong ==> return 0, loi return != 0
    // #endif
}

int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        printf("Su dung: %s <interface> \n", argv[0]);
        return -1;
    }

    char *interface = argv[1];
    printf("Interface %s \n", interface);
    int rc;
    // u_int8_t buffer[65536];
    u_char* buffer = malloc(65536 * sizeof(int));
    struct pfring_pkthdr hdr;
    u_int64_t packet_count = 0;
    ring = pfring_open(interface, 1500, PF_RING_PROMISC);

    if (!ring)
    {
        printf("Loi: khong doc duoc interface %s \n", interface);
        return -1;
    }

    signal(SIGINT, signal_handler);

    pfring_enable_ring(ring);
    // while (keep_running)
    // {
    //     rc = pfring_recv(ring, &buffer, sizeof(buffer), &hdr, 1);
    //     if (rc > 0)
    //     {
    //         packet_count++;
    //         printf("Goi tin bat duoc co do dai: %d byte \n", hdr.len);
    //     }
    //     else if (rc < 0)
    //     {
    //         printf("Loi khi bat goi tin %d \n", rc);
    //         break;
    //     }
    // }
    // printf("Tong so goi tin capture duoc: %ld \n", packet_count);
    num_threads = 8;
    pthread_t myThread;
    for(long i = 0; i < num_threads; i++) {
        pthread_create(&myThread, NULL, packet_consumer_thread, (void* ) i);
    }
    for(long i = 0; i < num_threads; i++) {
        pthread_join(myThread, NULL);
    }
    pfring_close(ring);
    printf("Dong chuong trinh \n");
    return 0;
}