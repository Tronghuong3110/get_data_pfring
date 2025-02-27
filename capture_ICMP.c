#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <pfring.h>
#include <pfring_zc.h>
#include <sched.h>
#include <signal.h>
#include <pthread.h>
#include <time.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <string.h>
#include <ctype.h>
#include <cjson/cJSON.h>
#include <math.h>
#include <stdint.h>
#include <stdbool.h>
// #include <pfring_utils.h>
#include <glib.h>
#include <assert.h>

// #define BURST_SIZE          32
// #define DEFAULT_DEVICE      "eth0"
// #define NO_ZC_BUFFER_LEN    9000
// #define MAX_NUM_THREADS     1
// #define HASH_TABLE_SIZE     1024
#define ROWS                2

typedef unsigned char u_char;
typedef unsigned long u_long;
typedef unsigned int u_int;
bool first_packet_found = FALSE;
time_t time_first_req = 0;
int index_hash = 0;
time_t time_dump_json = 0;
double time_statistic_droped_packet = 0;
int core_dump_id = 0;
// int last_times[4] = {0};
// u_int64_t numPkts = 0;

typedef struct Packet_capture {
    u_int32_t src_ip;
    u_int32_t dest_ip;
    char* os;
    char* hop;
    char* flag;
    u_int8_t* mac_addr_src;
    u_int8_t* mac_addr_dest;
    u_int type;
    u_int16_t sequence;
    u_int16_t sequence_be;
    u_int16_t id;
    u_int8_t ttl;
    double time_send;
    double time_recive;
    double rtt;
    u_int drop;
    // struct Packet_capture* next;
} PacketCapture;

// PacketCapture* hash_packet_capture[HASH_TABLE_SIZE];
// PacketCapture* hash_packet_capture2[HASH_TABLE_SIZE];
// PacketCapture** hash_packet_capture_actrive = hash_packet_capture;
// GHashTable* hash_packet_capture_lib;
// GHashTable* hash_packet_capture2_lib;
// GHashTable* hash_packet_capture_actrive_lib;
// GHashTable* hash_packet_capture_inactive_lib;
GHashTable** hash_table;
// GHashTable* hash_table_tmp;

pfring* ring;
// pfring_zc_cluster* zc;
// pfring_zc_worker* zw;
// pfring_zc_queue** inzq;
// pfring_zc_queue** outzq;
// pfring_zc_multi_queue* outzmp;
// pfring_zc_buffer_pool* wsp;
// pfring_zc_pkt_buff** buffers;

char* mac_router;
// pthread_mutex_t hash_table_mutex = PTHREAD_MUTEX_INITIALIZER;
void* dump_to_json(void* arg);
static char* etheraddr_string(const u_char *ep, char* buf);
PacketCapture* find_request(u_int32_t ip_src, u_int32_t ip_dest, u_int16_t sequence, u_int16_t sequence_be, u_int16_t id);
// int find_insert_last_time_min(double time) {
//     // double min = insert_last_time[0];
//     int idx = 0;
//     double last_time = __DBL_MIN__;
//     // if(insert_last_time[1] < min) {
//     //     min = insert_last_time[1];
//     //     idx = 1;
//     // }
//     // if(insert_last_time[2] < min) {
//     //     min = insert_last_time[2];
//     //     idx = 2;
//     // }
//     for(int i = 0; i < 3; i++) {
//         if(fabs(time - last_times[i]) > last_time) {
//             idx = i;
//         }
//     }
//     return idx;
// }
void sigproc(int sig) {
    static int called = 0;
    fprintf(stderr, "Leaving...");
    if(called) return;
    called = 1;
    for(int i = 0; i < ROWS; i++) {
        dump_to_json((void*)hash_table[i]);
    }
    pfring_breakloop(ring);
}

// void switch_hash_table_active() {
//     // struct timeval time_start;
//     // gettimeofday(&time_start, NULL);
//     // double time_start_dou = time_start.tv_sec * 1000.0 + time_start.tv_usec / 1000.0;
//     pthread_mutex_lock(&hash_table_mutex);
//     if(hash_packet_capture_actrive_lib == hash_packet_capture_lib) {
//         hash_packet_capture_actrive_lib = hash_packet_capture2_lib;
//         hash_packet_capture_inactive_lib = hash_packet_capture_lib;
//     }  
//     else {
//         hash_packet_capture_actrive_lib = hash_packet_capture_lib;
//         hash_packet_capture_inactive_lib = hash_packet_capture2_lib;
//     }
//     pthread_mutex_unlock(&hash_table_mutex);
//     // struct timeval time_end;
//     // gettimeofday(&time_end, NULL);
//     // double time_end_dou = time_end.tv_sec * 1000.0 + time_end.tv_usec / 1000.0;
//     // double duration = fabs(time_end_dou - time_start_dou);
//     // printf("Time taken to lock and switch hash table: %lf\n", duration);
// }

guint hash(gconstpointer key) {
    // PacketCapture* packet = (PacketCapture*)key;
    // guint result = packet->src_ip ^ packet->dest_ip ^ packet->sequence ^ packet->id;
    // printf("HASH: src_ip = %u, dest_ip = %u, sequence = %u, id = %u\n",
    //        packet->src_ip, packet->dest_ip, packet->sequence, packet->id);
    // printf("Hash result = %u\n", result);
    // return result;

    PacketCapture* rkey = (PacketCapture*)key;
    if (rkey == NULL) {
        printf("PacketCapture pointer is NULL\n");
        return 0;
    }
    guint key_tmp = 17;
    key_tmp = key_tmp * 31 + (rkey->src_ip); 
    key_tmp = (key_tmp ^ (key_tmp >> 16)) * 31; 

    key_tmp = key_tmp ^ (rkey->dest_ip); 
    key_tmp = (key_tmp ^ (key_tmp >> 13)) * 31;

    key_tmp = key_tmp ^ (rkey->sequence); 
    key_tmp = (key_tmp ^ (key_tmp >> 8)) * 31;

    key_tmp = key_tmp ^ (rkey->id);

    key_tmp = key_tmp ^ (rkey->sequence_be);
    key_tmp = (key_tmp ^ (key_tmp >> 8)) * 31;
    return key_tmp;
}

char* parse_ip(const u_int32_t* ip, int ip_version, u_int type){
    char* ip_str = (char* )malloc(INET6_ADDRSTRLEN);
    // static char ip_str[INET6_ADDRSTRLEN];
    u_char bytes[4];
    if(ip_version == 4) {
        // if(inet_ntop(AF_INET, ip, ip_str, INET_ADDRSTRLEN) != NULL) {
        //     return ip_str;
        // }
        u_int32_t ip_value = *ip;
        if (type == 1) {
            ip_value = ntohl(ip_value);
        }
        bytes[0] = ip_value & 0xFF;
        bytes[1] = (ip_value >> 8) & 0xFF;
        bytes[2] = (ip_value >> 16) & 0xFF;
        bytes[3] = (ip_value >> 24) & 0xFF;
        snprintf(ip_str, INET_ADDRSTRLEN, "%u.%u.%u.%u", bytes[0], bytes[1], bytes[2], bytes[3]);
        return ip_str;
    }
    else {
        // static char ip6[INET6_ADDRSTRLEN];
        if(inet_ntop(AF_INET6, ip, ip_str, INET6_ADDRSTRLEN) != NULL) {
            return ip_str;
        }
    }
    // free(ip_str);
    return NULL;
}

gboolean equal_func(gconstpointer key1, gconstpointer key2) {
    PacketCapture* rkey1 = (PacketCapture*)key1;
    PacketCapture* rkey2 = (PacketCapture*)key2;
    // printf("Key1: src = %u, dest = %u, sequence = %u, id = %u \n", rkey1->src_ip, rkey1->dest_ip, rkey1->sequence, rkey1->id);
    // printf("Key2: src = %u, dest = %u, sequence = %u, id = %u \n", rkey2->src_ip, rkey2->dest_ip, rkey2->sequence, rkey2->id);
    // return (rkey1->src_ip == rkey2->src_ip &&
    //         rkey1->dest_ip == rkey2->dest_ip &&
    //         rkey1->sequence == rkey2->sequence &&
    //         rkey1->id == rkey2->id);
    return hash(rkey1) == hash(rkey2);
}

void insert_request_to_hash_table(u_int32_t ip_src, u_int32_t ip_dest, u_int16_t sequence, u_int8_t* ether_shost, u_int8_t* ether_dhost, 
                                    double time, u_int8_t ip_version, u_int8_t ttl, u_int16_t id, u_int type, char* ip_hop, char* os, u_int16_t sequence_be) {
    PacketCapture* new_request = malloc(sizeof(PacketCapture));
    // printf("OS: %s \n", os);
    if(type == 0) { // tracert
        new_request = find_request(ip_src, ip_dest, sequence, sequence_be, id);
        // if(new_request && strstr(new_request->hop, ip_hop) == NULL) {
        if(new_request != NULL) {
            // strcat(new_request->hop, "->");
            // strcat(new_request->hop, ip_hop);
            if(strcmp(os, "Other")) {
                new_request->os = os;
            }
            // printf("Detect new hop !! \n");
            // printf("IP hop: %s \n", ip_hop);
        }
    }
    // printf("Type: %d \n \n", type);
    // char* ip_addr_src = parse_ip(ip_src, ip_version);
    // char* ip_addr_dest = parse_ip(ip_dest, ip_version);
    // char buf[32];
    // char buf2[32];
    // char* mac_str_src = etheraddr_string(eth->ether_shost, buf);
    // char* mac_str_dest = etheraddr_string(ether_dhost, buf2);
    // printf("Mac dest: %s\n", mac_str_dest);
    if(type == 1 || new_request == NULL) {
        // printf("Src = %u, dest = %u, sequence = %u, id = %u \n", ip_src, ip_dest, sequence, id);
        new_request = malloc(sizeof(PacketCapture));
        new_request->src_ip = ip_src;
        new_request->dest_ip = ip_dest;
        new_request->sequence = sequence;
        new_request->time_send = time;
        new_request->rtt = 0.0;
        new_request->ttl = ttl;
        new_request->drop = 0;
        new_request->id = id;
        new_request->type = type;
        new_request->hop = ip_hop;
        new_request->os = os;
        new_request->sequence_be = sequence_be;
        new_request->mac_addr_src = ether_shost;
        new_request->mac_addr_dest = ether_dhost;
        // printf("Hash index: %d \n", index_hash);
        if(g_hash_table_insert(hash_table[index_hash], new_request, new_request)) {
            // printf("Insert packet with type: %d \n", type);
            // printf("Insert packet success !! \n");
            // printf("Insert packet success with type: %d !!\n \n", type);
            // printf("src: %d, dest: %d, sequence: %d, id: %d \n", ip_src, ip_dest, sequence, id);
            // insert_last_time[index_hash] = (double)(time.tv_sec * 1000.0 + time.tv_usec / 1000.0);
        }
    }
}   

PacketCapture* find_request(u_int32_t ip_src, u_int32_t ip_dest, u_int16_t sequence, u_int16_t sequence_be, u_int16_t id) {
    
    PacketCapture* new_response = malloc(sizeof(PacketCapture));
    new_response->src_ip = ip_src;
    new_response->dest_ip = ip_dest;
    new_response->sequence = sequence;
    new_response->sequence_be = sequence_be;
    // new_request->time_send = time;
    // new_request->rtt = 0.0;
    // new_request->ttl = ttl;
    // new_request->drop = 0;
    new_response->id = id;
    for(int i = 0; i < ROWS; i++) {
        // GList* keys = g_hash_table_get_keys(hash_table[i]);
        // for(GList* iter = keys; iter != NULL; iter = iter->next) {
        //     guint* rkey = (guint*)iter->data;
        //     PacketCapture* packet = (PacketCapture*)g_hash_table_lookup(hash_table[i], rkey);
        //     if(packet == NULL) continue;
        //     // printf("Key trong hash: %u \n", *rkey);
        //     printf("(Hash table): src = %u, dest = %u \n", packet->src_ip, packet->dest_ip);
        //     if(ip_src == packet->src_ip && ip_dest == packet->dest_ip) {
        //         printf("Found \n\n");
        //         return packet;
        //     }
        //     // printf("Ip co trong hash table: src = %u, dest = %u \n", packet->src_ip, packet->dest_ip);
        // }
        // gconstpointer pointer = GUINT_TO_POINTER(key);
        // // printf("Pointer: %u \n", *pointer);
        PacketCapture* current_packet = (PacketCapture*)g_hash_table_lookup(hash_table[i], new_response);
        if(current_packet != NULL) {
            free(new_response);
            return current_packet;
        }
    }
    // printf("Can not find \n");
    // printf("================================================================================== \n \n");
    // PacketCapture* previous_packet = NULL;
    // char* ip_addr_src = parse_ip(ip_src, ip_version);
    // char* ip_addr_dest = parse_ip(ip_dest, ip_version);
    // char buf[32];
    // char buf2[32];
    // char* mac_str_src = etheraddr_string(eth->ether_shost, buf);
    // char* mac_str_dest = etheraddr_string(ether_dhost, buf2);
    // while (current_packet)
    // {
    //     if(strcmp(ip_addr_src, current_packet->src_ip) && strcmp(ip_addr_dest, current_packet->dest_ip)
    //         && current_packet->sequence == sequence) {
    //         // if(previous_packet) {
    //         //     previous_packet->next = current_packet->next;
    //         // }
    //         // else {
    //         //     hash_packet_capture[index] = current_packet;
    //         // }
    //         // pthread_mutex_unlock(&hash_table_mutex);
    //         return current_packet;
    //     }
    //     // previous_packet = current_packet;
    //     current_packet = current_packet->next;
    // }
    // pthread_mutex_unlock(&hash_table_mutex);
    // if(ip_src->v4 == current_packet->src_ip && ip_dest->v4 == current_packet->dest_ip && sequence == current_packet->sequence && id == current_packet->id) {
    return NULL;
}

// dia chi mac
static char* etheraddr_string(const u_char *ep, char* buf) {
    char* hex = "0123456789ABCDEF";
    u_int i, j;
    char* cp;
    cp = buf;
    if((j = *ep >> 4) != 0) {
        *cp++ = tolower(hex[j]);
    }
    else {
        *cp++ = '0';
    }
    *cp++ = tolower(hex[*ep++ & 0xf]);

    for(i = 5; (int)--i >= 0;) {
        *cp++ = ':';
        if((j = *ep>>4) != 0) {
            *cp++ = tolower(hex[j]);
        }
        else {
            *cp++ = '0';
        }
        *cp++ = tolower(hex[*ep++ & 0xf]);
    }
    *cp = '\0';
    return buf;
}

int bin2core(int core_id, pthread_t thread) {
    cpu_set_t cpuSet;
    CPU_ZERO(&cpuSet);
    CPU_SET(core_id, &cpuSet);
    return pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuSet);
}

void dummyProcessPacket(const struct pfring_pkthdr* h, const u_char* p, const u_char* thread_id) {
    memset((void *)&h->extended_hdr.parsed_pkt, 0, sizeof(struct pkt_parsing_info));
    // memset((void*) &h->ts, 0, sizeof(struct timecval));
    const struct pkt_parsing_info *info = &h->extended_hdr.parsed_pkt;
    pfring_parse_pkt_ppp((u_char*)p, (struct pfring_pkthdr*)h, 4, 0, 1);
    // pfring_parse_pkt_ppp((u_char*)p, (struct pfring_pkthdr*)h, 4, 0, 1);
    if(info->ip_version == 4) {
        if(info->l3_proto == IPPROTO_ICMP) {
            // ================== calculate time =================================================
            struct timeval time_req = h->ts;
            double time_packet_req = time_req.tv_sec * 1000.0 + time_req.tv_usec / 1000.0;
            if(!first_packet_found) {
                time_first_req = time_packet_req;
                first_packet_found = TRUE;
                time_statistic_droped_packet = time_packet_req;
            }
            double denta = fabs(time_packet_req - time_first_req);
            if(time_packet_req - time_dump_json >= 32000.0) {
                printf("Index hash: %d \n", index_hash);
                int index_dump = index_hash == 0 ? 1 : 0;

                GHashTable* hash_table_tmp = hash_table[index_dump];
                hash_table[index_dump] = g_hash_table_new(hash, equal_func);
                printf("Index dump json: %d \n", (index_dump));

                time_dump_json = time_packet_req;
                pthread_t thread_dump_file;
                pthread_create(&thread_dump_file, NULL, dump_to_json, (void*)hash_table_tmp);
                bin2core(core_dump_id, thread_dump_file);
            }
            if(denta >= 30000.0) {
                index_hash = (index_hash + 1) >= 2 ? 0 : (index_hash + 1);
                time_first_req = time_packet_req;
            }

            // statistic packet
            if(time_packet_req - time_statistic_droped_packet >= 10000.0) {
                pfring_stat pfringStat;
                if(pfring_stats(ring, &pfringStat) >= 0) {
                    printf("Packets: %ld, Dropped: %ld \n", pfringStat.recv, pfringStat.drop);
                    time_statistic_droped_packet = time_packet_req;
                }
            }
            // ===================================================================================
            ip_addr ip_src = info->ip_src;
            ip_addr ip_dest = info->ip_dst;

            struct ether_header* eth = (struct ether_header*)p;
            
            struct icmphdr* icmp_hdr = (struct icmphdr*)(p + info->offset.l4_offset);
            ip_addr tmp_ip_src = info->ip_src;
            ip_addr tmp_ip_dest = info->ip_dst;
            struct iphdr* ip_header = (struct iphdr*)(p + info->offset.l3_offset);

            // const u_char* payload = (u_char*)(p + info->offset.payload_offset);
            // char* ip_src_t = parse_ip(&tmp_ip_src.v4, info->ip_version, 1);
            // char* ip_dest_t = parse_ip(&tmp_ip_dest.v4, info->ip_version, 1);

            u_char* payload = (u_char*)icmp_hdr + sizeof(struct icmphdr);
            int payload_len = h->len - info->offset.l4_offset - (ip_header->ihl * 4);
            char* os;
            u_int packet_type = 1;
            // Tracert windows
            if(strncmp(payload, "", strlen(payload)) == 0 && icmp_hdr->type != 11 && icmp_hdr->type != 3) {
                // printf("Packet have payload equal 0 !! \n");
                // printf("Src: %s, Dest: %s \n", ip_src_t, ip_dest_t);
                packet_type = 0;
                os = "Windows";
            }
            // Ping windows
            else if(strncmp(payload, "abc", 3) == 0) {
                os = "Windows";
                // for(int i = 0 ; i < payload_len; i++) {
                //     printf("%c ", payload[i]);
                //     if((i + 1) % 16 == 0) {
                //         printf("\n");
                //     }
                // }
                // printf("\n\n");
            }
            else {
                payload += 28;
                payload_len -= 8;
                // char tmp[8] = {0};
                // strncpy(tmp, (char*)(payload + payload_len - 7), 7);
                // for(int i = 0; i < payload_len; i++) {
                //     printf("%02x ", payload[i]);
                //     if((i + 1) % 16 == 0) {
                //         printf("\n");
                //     }
                // }
                // printf("\n\n");
                // printf("%s \n", payload);
                if(strstr(payload, "@ABC") != NULL || strstr(payload, "01234567") != NULL) {
                    os = "Ubuntu";
                }
                else {
                    os = "Other";
                }
            }
            // time == 0
            double time = (double)(h->ts.tv_sec*1000.0) + (double)(h->ts.tv_usec/1000.0);
            u_int16_t seq_be = ntohs(icmp_hdr->un.echo.sequence);
            if(icmp_hdr->type == 8) {
                // printf("Src: %u, Dest: %u \n", tmp_ip_src.v4, tmp_ip_dest.v4);
                // check tracert
                u_int ttl = ip_header->ttl;
                // printf("Packet type: %d \n", packet_type);
                // u_int16_t sequence = ntohs(icmp_hdr->un.echo.sequence);
                // u_int16_t id = ntohs(icmp_hdr->un.echo.id);
                // printf("Sequence: %d \n", seq_be);
                if(packet_type == 0) {
                    tmp_ip_dest.v4 = ntohl(tmp_ip_dest.v4);
                    tmp_ip_src.v4 = ntohl(tmp_ip_src.v4);
                    // icmp_hdr->un.echo.sequence = 0;
                    // icmp_hdr->un.echo.id = 0;
                    insert_request_to_hash_table(tmp_ip_src.v4, tmp_ip_dest.v4, 
                                        0, eth->ether_shost, eth->ether_dhost,
                                        time, info->ip_version, ttl, 0, packet_type, "Unknow", os, 0);
                    // free(ip_src_t);
                    // printf("Tracert \n");
                }
                else {
                    insert_request_to_hash_table(tmp_ip_src.v4, tmp_ip_dest.v4, 
                                            icmp_hdr->un.echo.sequence, eth->ether_shost, eth->ether_dhost,
                                            time, info->ip_version, ttl, icmp_hdr->un.echo.id, 
                                            packet_type, NULL, os, seq_be);
                    // printf("Squence be: %d \n", seq_be);
                    // numPkts++;
                }
                    // printf("Request: src = %s --> dest = %s, seq = %u, id = %u \n", ip_src_t, ip_dest_t, icmp_hdr->un.echo.sequence, icmp_hdr->un.echo.id);
                    // printf("Payload: %s\n", payload);
                // }
                // char* test = parse_ip(&tmp_ip_src, info->ip_version);
                // printf("SRC: %s\n", test);
                // printf("TTL: %u\n", ip_header->ttl);
                // printf("");
            }
            else if(icmp_hdr->type == 0) {
                PacketCapture* matched_request = find_request(tmp_ip_dest.v4, tmp_ip_src.v4, 
                                        icmp_hdr->un.echo.sequence, seq_be, icmp_hdr->un.echo.id);
                if(matched_request) {
                    double rtt = (double)fabs(matched_request->time_send - time);
                    // over 2s ==> drop
                    // ip_src, ip_dest, sequence, sequence be, id;
                    if(rtt > 2000.0) {
                        matched_request->rtt = -1;
                        matched_request->drop = 1;
                    }
                    else {
                        matched_request->rtt = (double)fabs(matched_request->time_send - time);
                    }
                    matched_request->time_recive = time;

                    // matched_request->ttl = ttl;
                    // char* ip_src_res = parse_ip(&matched_request->src_ip, 4, 1);
                    // char* ip_dest_res = parse_ip(&matched_request->dest_ip, info->ip_version, 1);
                    // printf("ICMP: TTL = %u, ID = %u, src = %s --> dest = %s, seq = %u, rtt = %.3lf \n", matched_request->ttl, matched_request->id,
                    //                                                                     ip_src_res,
                    //                                                                     ip_dest_res, 
                    //                                                                     matched_request->sequence,
                    //                                                                     matched_request->rtt);
                    // double t = (double)round(time * 1000)/1000;
                    // printf("Time: %lf\n", time);
                    // printf("Time send: %lf\n", time_send_request);
                    // printf("RTT: %lf\n", (double)abs(time - time_send_request));
                    // printf("Response: src = %s --> dest = %s, seq = %u, id = %u \n", ip_dest_t, ip_src_t, icmp_hdr->un.echo.sequence, icmp_hdr->un.echo.id);
                }
                else {
                    // char* ip_src = parse_ip(&tmp_ip_dest.v4, info->ip_version);
                    // char* ip_dest = parse_ip(&tmp_ip_src.v4, info->ip_version);
                    // printf("Unmatched ICMP Response: src = %s --> dest = %s, seq = %u \n", ip_dest_t,
                    //                                                                     ip_src_t, 
                    //                                                                     icmp_hdr->un.echo.sequence);
                }
            }
            else if(icmp_hdr->type == 11 || icmp_hdr->type == 3) {
                packet_type = 0;
                struct iphdr* ip_hdr_icmp = (struct iphdr*)((u_char*)icmp_hdr + sizeof(struct icmphdr));
                char* ip_src_ip_icmp = parse_ip(&ip_hdr_icmp->saddr, 4, 0);
                char* ip_dest_ip_icmp = parse_ip(&ip_hdr_icmp->daddr, 4, 0);
                // char buf1[32];
                // char buf2[32];
                // char* mac_dest = etheraddr_string(eth->ether_dhost, buf1);
                // char* mac_src = etheraddr_string(eth->ether_shost, buf2);
                // printf("MAC SRC: %s, MAC dest: %s \n", mac_dest, mac_src);
                // printf("SRC: %s, Dest: %s \n", ip_src_ip_icmp, ip_dest_ip_icmp);
                // printf("Index hash: %d \n", index_hash);
                // insert_last_time[index_hash] = time_packet_req;
                // printf("src: %u, dest: %u \n", ip_hdr_icmp->saddr, ip_hdr_icmp->daddr);
                insert_request_to_hash_table(ip_hdr_icmp->saddr, ip_hdr_icmp->daddr, 
                                            0, eth->ether_dhost, eth->ether_shost, time, info->ip_version, 
                                            ip_hdr_icmp->ttl, 0, packet_type, "Unknow", os, 0);
                // free(ip_src_t);
                // printf("Tracert, src = %s --> dest = %s \n", ip_src_ip_icmp, ip_dest_ip_icmp);
            }
            // ip_src_t = NULL;
            // co the se can free ip_src_t
            // free(ip_src_t);
            // free(os);
            // ip_src_t = NULL;
            // os = NULL;
            // free(ip_src_t);
        }
    }
}   

void get_current_time(char* buf, size_t buf_size) {
    time_t current_time = time(NULL);
    snprintf(buf, buf_size, "%ld", current_time);
}

void callback_dum_file(gpointer key, gpointer value, gpointer user_data) {
    // printf("DUMP json \n");
    PacketCapture* current_packet = (PacketCapture*)value;
    FILE* file = (FILE*)user_data;
    if(current_packet == NULL) return;
    if(current_packet->rtt == 0 && current_packet->type != 0) { // type = 1: ping, type = 0: tracert
        current_packet->drop = 1;
    }
    char* ip_addr_src = parse_ip(&current_packet->src_ip, 4, current_packet->type);
    char* ip_addr_dest = parse_ip(&current_packet->dest_ip, 4, current_packet->type);
    char buf[32];
    char buf2[32];
    char* mac_str_src = etheraddr_string(current_packet->mac_addr_src, buf);
    char* mac_str_dest = etheraddr_string(current_packet->mac_addr_dest, buf2);
    // printf("Mac src: %s, Mac dest: %s \n", mac_str_src, mac_str_dest);
    if(strcmp(mac_str_src, mac_router) == 0) {
        current_packet->flag = "External";
    }
    else if(strcmp(mac_str_dest, mac_router) == 0){
        current_packet->flag = "Client";
    }
    else {
        current_packet->flag = "Uknown";
    }
    fprintf(file, "  {\n");
    fprintf(file, "    \"source_ip\": \"%s\",\n", current_packet->src_ip ? ip_addr_src : "N/A");
    fprintf(file, "    \"destination_ip\": \"%s\",\n", current_packet->dest_ip ? ip_addr_dest : "N/A");
    fprintf(file, "    \"mac_address_source\": \"%s\",\n", mac_str_src);
    fprintf(file, "    \"mac_address_dest\": \"%s\",\n", mac_str_dest);
    fprintf(file, "    \"sequence\": %u,\n", current_packet->sequence);
    fprintf(file, "     \"sequence_be\": %u, \n", current_packet->sequence_be ? current_packet->sequence_be : -1);
    fprintf(file, "    \"time_send_request\": %lf,\n", current_packet->time_send ? current_packet->time_send : 0.0);
    fprintf(file, "    \"time_receive_response\": %lf,\n", current_packet->time_recive ? current_packet->time_recive : 0.0);
    fprintf(file, "    \"ttl\": %u,\n", current_packet->ttl);
    fprintf(file, "    \"rtt\": %.2f,\n", current_packet->rtt);
    fprintf(file, "    \"drop\": %u, \n", current_packet->drop);
    fprintf(file, "    \"id\": %u, \n", current_packet->id);
    fprintf(file, "    \"type\": %d, \n", current_packet->type);
    fprintf(file, "     \"direction_flag\": \"%s\", \n", current_packet->flag);
    fprintf(file, "     \"hop\": \"%s\", \n", current_packet->hop ? current_packet->hop : "NULL");
    fprintf(file, "     \"os\": \"%s\" \n", current_packet->os ? current_packet->os : "NULL");
    fprintf(file, "  }");
    // fprintf(file, "\n");
    free(current_packet);
    // free(ip_addr_src);
    // free(ip_addr_dest);
    // free(mac_str_src);
    // free(mac_str_dest);
    return;
}

void* dump_to_json(void* arg) {
    GHashTable* hash_table_tmp = (GHashTable*) arg;
    if(g_hash_table_size(hash_table_tmp) > 0) {
        printf("Sizeof: %d \n", g_hash_table_size(hash_table_tmp));
        sleep(1);
        char filename[200];
        char timestamp[32];
        get_current_time(timestamp, sizeof(timestamp));
        snprintf(filename, sizeof(filename), "./output/result_icmp_%s.json", timestamp);
        FILE* file = fopen(filename, "w");
        if(file == NULL) {
            perror("Error opening file");
            return NULL;
        }
        fprintf(file, "[\n");
        // g_hash_table_foreach(hash_table_tmp, callback_dum_file, file);
        GList* keys = g_hash_table_get_keys(hash_table_tmp);
        int total_items = g_list_length(keys);
        int count = 0;

        for (GList* iter = keys; iter != NULL; iter = iter->next) {
            const guint* key = (const guint*) iter->data; 
            gpointer value = g_hash_table_lookup(hash_table_tmp, key);
            callback_dum_file((void*)key, value, file);
            count++;
            if (count < total_items) {
                fprintf(file, ",\n");
            }
        }
        // for(int i = 0; i < HASH_TABLE_SIZE; i++) {
        //     PacketCapture* current_packet = hash_packet_capture_inactive[i];
        //     if(current_packet == NULL) continue;
        //     while (current_packet != NULL) {
        //         if(current_packet->rtt == 0) {
        //             current_packet->drop = 1;
        //         }
        //         fprintf(file, "  {\n");
        //         fprintf(file, "    \"source_ip\": \"%s\",\n", current_packet->src_ip ? current_packet->src_ip : "N/A");
        //         fprintf(file, "    \"destination_ip\": \"%s\",\n", current_packet->dest_ip ? current_packet->dest_ip : "N/A");
        //         fprintf(file, "    \"mac_address_source\": \"%s\",\n", current_packet->mac_addr_src ? current_packet->mac_addr_src : "N/A");
        //         fprintf(file, "    \"mac_address_dest\": \"%s\",\n", current_packet->mac_addr_dest ? current_packet->mac_addr_dest : "N/A");
        //         fprintf(file, "    \"sequence\": %u,\n", current_packet->sequence);
        //         fprintf(file, "    \"ttl\": %u,\n", current_packet->ttl);
        //         fprintf(file, "    \"rtt\": %.2f,\n", current_packet->rtt);
        //         fprintf(file, "    \"drop\": %u, \n", current_packet->drop);
        //         fprintf(file, "  }");
        //         if (current_packet->next != NULL) {
        //             fprintf(file, ",\n");
        //         } else {
        //             fprintf(file, "\n");
        //         }
        //         current_packet = current_packet->next;
        //     }
        //     free(hash_packet_capture_inactive[i]);
        //     hash_packet_capture_inactive[i] = NULL;
        // }
        fprintf(file, "]\n");
        fclose(file);
        g_hash_table_remove_all(hash_table_tmp);
        // free(hash_table_tmp);
    }
   
}

int main(int argc, char* argv[]) {
    if(argc < 2) {
        printf("Use: %s <interface> \n", argv[0]);
        return -1;
    }
    // ./capture_icmp -i ens33 -b 94:e6:f7:6a:5a:45 
    char* interface = argv[2]; // -i interface
    mac_router = argv[4]; // -b mac router
    int main_core = atoi(argv[6]); // -c1 (main_core)
    core_dump_id = atoi(argv[8]); // -c2 (core_dump_file)
    printf("Capture on interface: %s \n", interface);
    u_int32_t flags = 0;
    flags |= PF_RING_PROMISC;
    flags |= PF_RING_HW_TIMESTAMP;
    if(strstr(interface, "zc:")) {
        printf("ZC interface enable flags \n");
        flags |= PF_RING_TIMESTAMP;
    }
    // printf("Core_id_main: %d, Core_id_dump: %d \n", main_core, core_dump_id);
    ring = pfring_open(interface, 9000, flags);
    if(!ring) {
        printf("Error: Cannot capture on Interface %s \n", interface);
        return -1;
    }
    signal(SIGINT, sigproc);
    signal(SIGTERM, sigproc);

    cpu_set_t cpu_set;
    CPU_ZERO(&cpu_set);
    CPU_SET(main_core, &cpu_set);
    if(sched_setaffinity(0, sizeof(cpu_set_t), &cpu_set) == -1) {
        perror("Sched_setaffinity !!");
        assert(false);
    }

    // init array hash table
    hash_table = malloc(ROWS * sizeof(GHashTable*));
    for(int i = 0; i < ROWS; i++) {
        hash_table[i] = g_hash_table_new(hash, equal_func);
    }
    // pfring_zc_recv_pkt
    pfring_enable_ring(ring);
    pfring_loop(ring, dummyProcessPacket,(u_char*) NULL, 1);
    pfring_close(ring);

    return 0;
}