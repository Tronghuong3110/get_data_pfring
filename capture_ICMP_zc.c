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
#include <pfring_mod_sysdig.h>
#include <glib.h>

#define ROWS                2
#define DEFAULT_CLUSTER_ID  99
#define MAX_CARD_SLOTS      32768
#define PREFETCH_BUFFERS    8
#define QUEUE_LEN           8192

typedef unsigned char u_char;
typedef unsigned long u_long;
typedef unsigned int u_int;

bool first_packet_found = FALSE;
time_t time_first_req = 0;
int index_hash = 0;
time_t time_dump_json = 0;
double time_statistic_droped_packet = 0;

typedef struct Packet_capture {
    u_int32_t src_ip;
    u_int32_t dest_ip;
    char* os;
    char* hop;
    char* flag;
    uint8_t mac_addr_src[6];
    uint8_t mac_addr_dest[6];
    u_int type;
    uint16_t sequence;
    uint16_t sequence_be;
    uint16_t id;
    u_int8_t ttl;
    double time_send;
    double time_recive;
    double rtt;
    u_int drop;
    // struct Packet_capture* next;
} PacketCapture;

typedef struct {
    uint8_t test;
    u_int32_t src_ip;
    u_int32_t dest_ip;
    uint16_t sequence;
    uint16_t id;
} PacketKey;


GHashTable** hash_table;

pfring* ring;
pfring_zc_cluster* zc;
pfring_zc_worker* zw;
pfring_zc_queue** inzq;
pfring_zc_queue** outzq;
pfring_zc_buffer_pool* wsp;
pfring_zc_pkt_buff* buffer;

char* mac_router;
u_int8_t wait_for_packet =1, do_shutdown = 0;
int bind_worker_core = 0;
int bind_worker_dump_file_core = 1;
int num_response = 0;
void* dump_to_json(void* arg);
static char* etheraddr_string(const u_char *ep, char* buf);
PacketCapture* find_request(u_int32_t ip_src, u_int32_t ip_dest, uint16_t sequence, uint16_t id);
void sigproc(int sig) {
    static int called = 0;
    fprintf(stderr, "Leaving...");
    if(called) return;
    called = 1;
    do_shutdown = 1;
    for(int i = 0; i < ROWS; i++) {
        dump_to_json((void*)hash_table[i]);
    }
    // pfring_breakloop(ring);
    pfring_zc_queue_breakloop(outzq[0]);
}
/*========================================================= */
guint hash(gconstpointer key) {
    const PacketKey* k = (const PacketKey*)key;
    guint hash = 17;
    hash = hash * 31 + k->src_ip;
    hash = hash * 31 + k->dest_ip;
    hash = hash * 31 + k->sequence;
    hash = hash * 31 + k->id;
    return hash;
}
// guint hash_uint8_array_37(gconstpointer key) {
//     const uint32_t* k = (const uint32_t*)key;  
//     guint hash = 17;
//     hash = hash * 31 + k[0];
//     hash = hash * 31 + k[1];
//     hash = hash * 31 + k[2];
//     hash = hash * 31 + k[3];
//     return hash;
// }

char* parse_ip(u_int32_t* ip, int ip_version, u_int type){
    char* ip_str = (char* )malloc(INET6_ADDRSTRLEN);
    // char ip_str[INET6_ADDRSTRLEN];
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
    // else if (ip_version == 6) {
    //     const u_int8_t* ip6_addr = (const u_int8_t*)ip;
    //     snprintf(ip_str, INET6_ADDRSTRLEN, 
    //              "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
    //              ip6_addr[0], ip6_addr[1], ip6_addr[2], ip6_addr[3],
    //              ip6_addr[4], ip6_addr[5], ip6_addr[6], ip6_addr[7],
    //              ip6_addr[8], ip6_addr[9], ip6_addr[10], ip6_addr[11],
    //              ip6_addr[12], ip6_addr[13], ip6_addr[14], ip6_addr[15]);
    // }
    return ip_str;
}

gboolean equal_func(gconstpointer key1, gconstpointer key2) {
    PacketKey* k1 = (PacketKey*)key1;
    PacketKey* k2 = (PacketKey*)key2;
    // printf("Key_1: Src: %u, Dest: %u, Seq: %d, ID: %d %u\n",
    //     k1->src_ip, k1->dest_ip, k1->sequence, k1->id, k1->test);

    // printf("Key_2: Src: %u, Dest: %u, Seq: %d, ID: %d %u\n",
    //     k2->src_ip, k2->dest_ip, k2->sequence, k2->id,k2->test);
    return k1->src_ip == k2->src_ip &&
           k1->dest_ip == k2->dest_ip &&
           k1->sequence == k2->sequence &&
           k1->id == k2->id;
}


void insert_request_to_hash_table(u_int32_t ip_src, u_int32_t ip_dest, uint16_t sequence, uint8_t ether_shost[6], uint8_t ether_dhost[6], 
                                    double time, u_int8_t ip_version, u_int8_t ttl, uint16_t id, u_int type, char* ip_hop, char* os) {
    PacketCapture* new_request = find_request(ip_src, ip_dest, sequence, id);
    if (type == 0 && new_request != NULL) {
        if (os && strcmp(os, "Other") != 0) { 
            if (new_request->os) free(new_request->os); 
            new_request->os = strdup(os);
        }
        return;
    }
    if (type == 1) {
        if(new_request == NULL) {
            new_request = malloc(sizeof(PacketCapture));
        }
        new_request->src_ip = ip_src;
        new_request->dest_ip = ip_dest;
        new_request->sequence = sequence;
        new_request->time_send = time;
        new_request->rtt = 0.0;
        new_request->ttl = ttl;
        new_request->drop = 0;
        new_request->id = id;
        new_request->type = type;
        new_request->sequence_be = ntohs(sequence);
        memcpy(new_request->mac_addr_src, ether_shost, 6);
        memcpy(new_request->mac_addr_dest, ether_dhost, 6);
        new_request->hop = ip_hop ? strdup(ip_hop) : NULL;
        new_request->os = os ? strdup(os) : NULL;

        PacketKey* key =malloc(sizeof(PacketKey));
        memset(key, 0, sizeof(PacketKey));
        key->src_ip = ip_src;
        key->dest_ip = ip_dest;
        key->sequence = sequence;
        key->id = id;

        g_hash_table_insert(hash_table[index_hash], key, new_request);
        // if (!g_hash_table_insert(hash_table[index_hash], key, new_request)) {
        // }
        // else {
        //     free(new_request);
        // }
    }
}

void print_hash_entry(gpointer key, gpointer value, gpointer user_data) {
    PacketKey* k = (PacketKey*) key;
    PacketCapture* p = (PacketCapture*) value;
    printf("Hash Entry: Src: %u, Dest: %u, Seq: %d, ID: %d\n",
           p->src_ip, p->dest_ip, p->sequence, p->id);
}

PacketCapture* find_request(u_int32_t ip_src, u_int32_t ip_dest, uint16_t sequence, uint16_t id) {
    PacketKey search_key;
    memset(&search_key, 0, sizeof(PacketKey));
    search_key.test=100;
    search_key.src_ip = ip_src;
    search_key.dest_ip = ip_dest;
    search_key.sequence = sequence;
    search_key.id = id;

    // printf("Looking for: Src: %u, Dest: %u, Seq: %d, ID: %d \n", search_key.src_ip, search_key.dest_ip, search_key.sequence, search_key.id);
    for (int i = 0; i < ROWS; i++) {
        PacketCapture* current_packet = (PacketCapture*)g_hash_table_lookup(hash_table[i], &search_key);
        // g_hash_table_foreach(hash_table[i], (GHFunc)print_hash_entry, NULL);
        if (current_packet != NULL) {
            // printf("Found packet! Src: %u, Dest: %u, Seq: %d, ID: %d \n", 
            //     current_packet->src_ip, current_packet->dest_ip, 
            //     current_packet->sequence_be, current_packet->id);
            return current_packet;
        }
    }
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

void dummyProcessPacket(pfring_zc_pkt_buff* b) {
    struct pfring_pkthdr h;
    memset(&h, 0, sizeof(struct pfring_pkthdr));
    
    h.caplen = b->len;
    h.len = b->len;
    h.ts.tv_sec = b->ts.tv_sec;
    h.ts.tv_usec = b->ts.tv_nsec / 1000;

    const u_char* p = (const u_char*)pfring_zc_pkt_buff_data(b, outzq[0]);
    int ret = pfring_parse_pkt_ppp((u_char*)p, (struct pfring_pkthdr*)&h, 4, 0, 1);
    const struct pkt_parsing_info *info = &h.extended_hdr.parsed_pkt;
    // printf("Capture \n");
    if(info->ip_version == 4) {
        // ================== calculate time =================================================
        time_t time_packet_req = h.ts.tv_sec;
        if(!first_packet_found) {
            time_first_req = time_packet_req;
            first_packet_found = TRUE;
            // time_dump_json = time_packet_req;
            time_statistic_droped_packet = time_packet_req;
        }
        double delta = fabs(time_packet_req - time_first_req);
        if(time_packet_req - time_dump_json >= 32) {
            // printf("Index hash: %d \n", index_hash);
            int index_dump = index_hash == 0 ? 1 : 0;

            GHashTable* hash_table_tmp = hash_table[index_dump];
            hash_table[index_dump] = g_hash_table_new_full(hash, equal_func, NULL, NULL);
            // printf("Index dump json: %d \n", (index_dump));

            time_dump_json = time_packet_req;
            pthread_t thread_dump_file;
            pthread_create(&thread_dump_file, NULL, dump_to_json, (void*)hash_table_tmp);
            bin2core(bind_worker_dump_file_core, thread_dump_file);
            pthread_detach(thread_dump_file);
            // printf("Dump file success !");
        }
        if(delta >= 30) {
            index_hash = (index_hash + 1) >= 2 ? 0 : (index_hash + 1);
            time_first_req = time_packet_req;
        }
        // statistic packet
        if(time_packet_req - time_statistic_droped_packet >= 10) {
            pfring_zc_stat stats;
            // printf("Statistic \n");
            if(pfring_zc_stats(outzq[0], &stats) == 0) {
                printf("Packets: %ld, Dropped: %ld \n", stats.recv, stats.drop);
                time_statistic_droped_packet = time_packet_req;
            }
        }
        // ===================================================================================
        if(info->l3_proto == IPPROTO_ICMP) {
            // ip_addr ip_src = info->ip_src;
            // ip_addr ip_dest = info->ip_dst;
            struct ether_header* eth = (struct ether_header*)p;
            struct iphdr* ip_header = (struct iphdr*)(p + info->offset.l3_offset);
            struct icmphdr* icmp_hdr = (struct icmphdr*)(p + info->offset.l4_offset);
            
            // uint16_t data_len = h.len - ip_header->ihl * 4;
            // uint16_t l4_data = info->offset.l4_offset;
            // uint16_t id = ntohs(*(uint16_t*)(l4_data + 4));
            // uint16_t sequence_be = ntohs(*(uint16_t*)(l4_data + 6));
            // uint8_t icmp_data_len = data_len - 8;
            // uint8_t *icmp_data_ = l4_data + 8;
            // for(int i = 0; i < icmp_data_len; i++) {
            //     printf("%02x ", icmp_data_[i]);
            //     if((i + 1) % 16 == 0) {
            //         printf("\n");
            //     }
            // }
            // printf("Sequence be: %d, Identifier: %d \n", sequence_be, id);
            // printf("\n");

            ip_addr tmp_ip_src = info->ip_src;
            ip_addr tmp_ip_dest = info->ip_dst;
            u_char* payload = (u_char*)icmp_hdr + sizeof(struct icmphdr);
            int payload_len = h.len - info->offset.l4_offset - (ip_header->ihl * 4);
            char* os;
            // u_int packet_type = 1;
            // Tracert windows
            if(strncmp(payload, "abc", 3) == 0) {
                // packet_type = 0;
                os = "Windows";
            }
            // Ping windows
            // else if(strncmp(payload, "abc", 3) == 0) {
            //     os = "Windows";
            // }
            else {
                payload += 28;
                payload_len -= 8;
                if(strstr(payload, "@ABC") != NULL || strstr(payload, "01234567") != NULL) {
                    os = "Ubuntu";
                }
                else {
                    os = "Other";
                }
            }
            // time == 0
            // if(b->ts.tv_sec == 0 && (double)b->ts.tv_nsec / 1000000.0 == 0) {
            //     printf("Time is zero \n");
            // }
            double time = (double)(b->ts.tv_sec * 1000.0) + (double)(b->ts.tv_nsec / 1000000.0);
            u_int16_t seq_be = ntohs(icmp_hdr->un.echo.sequence);
            u_int16_t seq = icmp_hdr->un.echo.sequence;
            // struct timeval time_tmp = h.ts;
            if(icmp_hdr->type == 8) {
                // check tracert
                u_int ttl = ip_header->ttl;
                if(ttl <= 20) {
                    tmp_ip_dest.v4 = ntohl(tmp_ip_dest.v4);
                    tmp_ip_src.v4 = ntohl(tmp_ip_src.v4);
                    insert_request_to_hash_table(tmp_ip_src.v4, tmp_ip_dest.v4, 
                                        -1, eth->ether_shost, eth->ether_dhost,
                                        time, info->ip_version, ttl, -1, 0, "Unknow", os);
                    // printf("IP src = %u, IP dest = %u \n", tmp_ip_src.v4, tmp_ip_dest.v4);
                }
                else {
                    insert_request_to_hash_table(tmp_ip_src.v4, tmp_ip_dest.v4, 
                                            seq, eth->ether_shost, eth->ether_dhost,
                                            time, info->ip_version, ttl, icmp_hdr->un.echo.id, 
                                            1, NULL, os);
                    // printf("Squence be: %d \n", seq_be);
                    // char buf[32];
                    // char buf2[32];
                    // char* mac_str_src = etheraddr_string(eth->ether_shost, buf);
                    // char* mac_str_dest = etheraddr_string(eth->ether_dhost, buf2);
                    // printf("Mac src = %s, Mac dest = %s \n", mac_str_src, mac_str_dest);
                }
            }
            else if(icmp_hdr->type == 0) {
                PacketCapture* matched_request = find_request(tmp_ip_dest.v4, tmp_ip_src.v4, 
                                        seq, icmp_hdr->un.echo.id);
                // num_response++;
                // printf("Time: %lf \n", time);
                // printf("Number response: %d \n", num_response);
                // if(strcmp(ip_dest_res, "14.231.236.64") == 0) {
                //     char buf[32];
                //     char buf2[32];
                //     char* mac_str_src = etheraddr_string(eth->ether_shost, buf);
                //     char* mac_str_dest = etheraddr_string(eth->ether_dhost, buf2);
                //     printf("Mac src: %s, Mac dest: %s \n", mac_str_src, mac_str_dest);
                //     printf("Sequence_be: %d \n", seq_be);
                // }
                // printf("Response \n");
                if(matched_request) {
                    // if (h.ts.tv_sec < 0 || h.ts.tv_usec < 0) {
                    //     printf("Warning: Invalid timestamp detected! tv_sec: %ld, tv_usec: %ld\n", h.ts.tv_sec, h.ts.tv_usec);
                    // }
                        double rtt = (double)fabs(matched_request->time_send - time);
                    // if(matched_request->rtt <= 0) {
                        // printf("RTT: %lf \n", rtt);
                    // double rtt = delta_time(&time_tmp, &matched_request->time_send);
                    // char* ip_src_res = parse_ip(&matched_request->src_ip, 4, 1);
                    // char* ip_dest_res = parse_ip(&matched_request->dest_ip, 4, 1);
                    // printf("Time send: %lf, Time receive %lf \n", matched_request->time_send, time);
                    // printf("RTT: %lf \n", rtt);
                    // char* ip_src_req = parse_ip(&tmp_ip_src.v4, 4, 1);
                    // char* ip_dest_req = parse_ip(&tmp_ip_dest.v4, 4, 1);
                        if(rtt > 3000.0) {
                            // printf("Request time out \n");
                            // printf("RTT: %lf \n", rtt);
                            // printf("============================================================================\n");
                            // printf("Dia chi ip cua response can map: *******************************************\n");
                            // printf("Ip src res: %u, IP dest res: %u, sequence: %d, Id: %d \n", tmp_ip_dest.v4, tmp_ip_src.v4, ntohs(seq), icmp_hdr->un.echo.id);
                            // printf("Dia chi ip cua request map duoc voi response: ******************************\n");
                            // printf("Src: %u, Dest: %u, Sequence: %d, Id: %d \n", matched_request->src_ip, matched_request->dest_ip, matched_request->sequence_be, matched_request->id);
                            // printf("============================================================================\n\n");
                            matched_request->rtt = -1;
                            matched_request->drop = 1;
                        }
                        else {
                            matched_request->rtt = rtt;
                        }
                        matched_request->time_recive = time;
                        // char* ip_src_res = parse_ip(&matched_request->src_ip, 4, 1);
                        // char* ip_dest_res = parse_ip(&matched_request->dest_ip, 4, 1);
                    // printf("==================================================================================\n");
                    // printf("ICMP: TTL = %u, ID = %u, src = %s --> dest = %s, seq = %u, rtt = %.3lf \n", matched_request->ttl, matched_request->id,
                    //     ip_src_res,
                    //     ip_dest_res, 
                    //     matched_request->sequence_be,
                    //     matched_request->rtt);
                    // }
                }
                else {
                    // cmp_hdr->un.echo.sequence);
                    // printf("Unmatch \n");
                }
            }
            // else if(icmp_hdr->type == 11 || icmp_hdr->type == 3) {
            //     // packet_type = 0;
            //     struct iphdr* ip_hdr_icmp = (struct iphdr*)((u_char*)icmp_hdr + sizeof(struct icmphdr));
            //     char* ip_src_ip_icmp = parse_ip(&ip_hdr_icmp->saddr, 4, 0);
            //     char* ip_dest_ip_icmp = parse_ip(&ip_hdr_icmp->daddr, 4, 0);
            //     insert_request_to_hash_table(ip_hdr_icmp->saddr, ip_hdr_icmp->daddr, 
            //                                 0, eth->ether_dhost, eth->ether_shost, time, info->ip_version, 
            //                                 ip_hdr_icmp->ttl, 0, 0, "Unknow", os, 0);
            //     free(ip_src_ip_icmp);
            //     free(ip_dest_ip_icmp);
            // }
        }
    }
}

void get_current_time(char* buf, size_t buf_size) {
    time_t current_time = time(NULL);
    snprintf(buf, buf_size, "%ld", current_time);
}

void callback_dum_file(gpointer key, gpointer value, gpointer user_data) {
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
    // if(strcmp(ip_addr_src, "14.231.236.64") == 0) {
    //     printf("Mac src: %s, Mac dest: %s \n", mac_str_src, mac_str_dest);
    // }
    if(strcmp(mac_str_src, mac_router) == 0) {
        current_packet->flag = "External";
    }
    else if(strcmp(mac_str_dest, mac_router) == 0){
        current_packet->flag = "Client";
    }
    else {
        current_packet->flag = "Uknown";
    }
    // double time_send_d = current_packet->time_send.tv_sec * 1000.0 + current_packet->time_send.tv_usec / 1000.0;
    // double time_receive_d = current_packet->time_recive.tv_sec * 1000.0 + current_packet->time_recive.tv_usec / 1000.0;
    fprintf(file, "  {\n");
    fprintf(file, "    \"source_ip\": \"%s\",\n", current_packet->src_ip ? ip_addr_src : "N/A");
    fprintf(file, "    \"destination_ip\": \"%s\",\n", current_packet->dest_ip ? ip_addr_dest : "N/A");
    fprintf(file, "    \"mac_address_source\": \"%s\",\n", mac_str_src);
    fprintf(file, "    \"mac_address_dest\": \"%s\",\n", mac_str_dest);
    fprintf(file, "    \"sequence\": %d,\n", current_packet->sequence);
    fprintf(file, "     \"sequence_be\": %d, \n", current_packet->sequence_be);
    fprintf(file, "    \"time_send_request\": %lf,\n", current_packet->time_send);
    fprintf(file, "    \"time_receive_response\": %lf,\n", current_packet->time_recive);
    fprintf(file, "    \"ttl\": %u,\n", current_packet->ttl);
    fprintf(file, "    \"rtt\": %.2f,\n", current_packet->rtt);
    fprintf(file, "    \"drop\": %u, \n", current_packet->drop);
    fprintf(file, "    \"id\": %d, \n", current_packet->id);
    fprintf(file, "    \"type\": %d, \n", current_packet->type);
    fprintf(file, "     \"direction_flag\": \"%s\", \n", current_packet->flag ? current_packet->flag : "Unknow");
    fprintf(file, "     \"hop\": \"%s\", \n", current_packet->hop ? current_packet->hop : "NULL");
    if(current_packet->os == NULL) {
        printf("OS is null \n");
    }
    else {
        fprintf(file, "     \"os\": \"%s\" \n", current_packet->os ? current_packet->os : "NULL");
    }
    fprintf(file, "  }");
    free(ip_addr_src);
    free(ip_addr_dest);
    return;
}

void* dump_to_json(void* arg) {
    GHashTable* hash_table_tmp = (GHashTable*) arg;
    if(g_hash_table_size(hash_table_tmp) > 0) {
        printf("Sizeof: %d \n", g_hash_table_size(hash_table_tmp));
        // printf("Number response: %d \n", num_response);
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
        fprintf(file, "]\n");
        fclose(file);
        // g_hash_table_remove_all(hash_table_tmp);
        g_hash_table_destroy(hash_table_tmp);
    }
}

int max_packet_len(char *device) { 
  char ifname_buff[32], path[256];
  char *ifname = ifname_buff, *ptr;
  FILE *proc_net_pfr;
  u_int32_t max_packet_size = 0;

  /* Remove prefix (e.g. 'zc:') and queue (@0) if any */
  snprintf(ifname, sizeof(ifname_buff), "%s", device);
  ptr = strchr(ifname, ':');
  if (ptr) ifname = ++ptr;
  ptr = strchr(ifname, '@');  
  if (ptr) *ptr = '\0';

  /* Try reading from /proc */
  snprintf(path, sizeof(path), "/proc/net/pf_ring/dev/%s/info", ifname);
  proc_net_pfr = fopen(path, "r");
  if (proc_net_pfr != NULL) {
    while (fgets(path, sizeof(path), proc_net_pfr) != NULL) {
      char *p = &path[0];
      const char *slot_size = "RX Slot Size:";
      if (!strncmp(p, slot_size, strlen(slot_size))) {
        max_packet_size = atoi(&p[strlen(slot_size)]);
        break;
      }
    }
    fclose(proc_net_pfr);
  }

  if (!max_packet_size) {
    /* Try opening socket */
    pfring *ring;
    pfring_card_settings settings;

    ring = pfring_open(device, 1536, PF_RING_ZC_NOT_REPROGRAM_RSS);

    if (!ring) {
      max_packet_size = 1536;
    } else {
      int mtu = pfring_get_mtu_size(ring);
      pfring_get_card_settings(ring, &settings);
      if (settings.max_packet_size < mtu + 14 /* eth */)
        max_packet_size = mtu + 14 /* eth */ + 4 /* vlan */;
      else
        max_packet_size = settings.max_packet_size;
      pfring_close(ring);
    }
  }

  return max_packet_size;
}

void* consumer_thread() {
    pfring_zc_pkt_buff *b = buffer;
    while(!do_shutdown) {
        if(pfring_zc_recv_pkt(outzq[0], &b, wait_for_packet) > 0) {
            dummyProcessPacket(b);
        }
    }
    pfring_zc_sync_queue(outzq[0], rx_only);
    return NULL;
}

int main(int argc, char* argv[]) {
    int cluster_id = DEFAULT_CLUSTER_ID + 3;
    char* device = NULL, c;
    hash_table = malloc(ROWS * sizeof(GHashTable*));
    for(int i = 0; i < ROWS; i++) {
        hash_table[i] = g_hash_table_new_full(hash, equal_func, NULL, NULL);
    }
    int hash_mode = 0;
    char* bind_mask = NULL;
    while((c = getopt(argc, argv, "ac:g:hi:r:m:b:123456")) != '?') {
        if(c == 255 || c == -1) break;
        switch (c){
            case 'a':
                wait_for_packet = 0;
                break;
            case 'c':
                cluster_id = atoi(optarg);
                break;
            case 'm':
                hash_mode = atoi(optarg);
            case 'i':
                device = strdup(optarg);
                break;
            case 'g':
                bind_worker_dump_file_core = atoi(optarg); // chỉ định cpu cho dump file
                break;
            case 'r':
                bind_worker_core = atoi(optarg); // chỉ định cpu
                break;
            case 'b':
                mac_router = strdup(optarg);
            default:
                break;
        }
    }
    u_int32_t flags = 0;
    // flags |= PF_RING_ZC_DEVICE_HW_TIMESTAMP;
    // if (strstr(device, "zc:")) {
    //     printf("ZC interface enable flags \n");
    flags |= PF_RING_ZC_DEVICE_SW_TIMESTAMP;
    // }
    // flags |= PF_RING_ZC_DEVICE_NOT_PROMISC;

    // printf("Cluster id: %d, bind_worker_core: %d \n", cluster_id, bind_worker_core);
    zc = pfring_zc_create_cluster(
        cluster_id,
        max_packet_len(device),
        0,
        (MAX_CARD_SLOTS) + (QUEUE_LEN) + 1 + PREFETCH_BUFFERS,
        pfring_zc_numa_get_cpu_node(bind_worker_core),
        NULL,
        0
    );

    // printf("Max_packet_len: %d \n", max_packet_len(device));
    if(zc == NULL) {
        fprintf(stderr, "pfring_zc_create_cluster error [%s]. Pleade check your hugetlb configuration \n",
            strerror(errno));
        return -1;
    }

    // buffers = calloc(1, sizeof(pfring_zc_pkt_buff*));
    inzq = calloc(1, sizeof(pfring_zc_queue*));
    outzq = calloc(1, sizeof(pfring_zc_queue*));

    buffer = pfring_zc_get_packet_handle(zc);
    if(buffer == NULL) {
        fprintf(stderr, "pfring_zc_get_packet_handle error \n");
        return -1;
    }

    inzq[0] = pfring_zc_open_device(zc, device, rx_only, flags);
    if(inzq[0] == NULL) {
        fprintf(stderr, "pfring_zc_open_device error [%s]. Please check that %s is up and not already used \n",
            strerror(errno), device);
        return -1;
    }

    outzq[0] = pfring_zc_create_queue(zc, QUEUE_LEN);
    if(outzq[0] == NULL) {
        fprintf(stderr, "pfring_zc_create_queue error [%s] \n", strerror(errno));
        return -1;
    }
    
    wsp = pfring_zc_create_buffer_pool(zc, PREFETCH_BUFFERS);
    if(wsp == NULL) {
        fprintf(stderr, "pfring_zc_create_buffer_poll error \n");
        return -1;
    }
    zw = pfring_zc_run_balancer(
        inzq, 
        outzq, 
        1, 
        1, 
        wsp,
        round_robin_bursts_policy, 
        NULL,
        NULL,
        (void *) ((long) 1),
        !wait_for_packet, 
        bind_worker_core
        );

    printf("Start capture \n");
    printf("Flag: %d\n", flags);
    consumer_thread();
    signal(SIGINT, sigproc);
    signal(SIGTERM, sigproc);
    for(int i = 0; i < ROWS; i++) {
        g_hash_table_destroy(hash_table[i]);
    }
    free(hash_table);
    free(inzq);
    free(outzq);
    free(mac_router);
    free(device);
    // pfring_zc_destroy_buffer_pool(wsp);
    // pfring_zc_destroy_queue(outzq[0]);
    pfring_zc_close_device(inzq[0]);
    pfring_zc_close_device(outzq[0]);
    pfring_zc_destroy_cluster(zc);
    return 0;
}