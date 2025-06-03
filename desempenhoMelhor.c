#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>    
#include <sys/time.h>  
#ifdef _WIN32
#include <winsock2.h>  
#include <windows.h>    
#else
#include <arpa/inet.h>  
#endif


#define ETHERNET_HEADER_SIZE 14

#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20

#define HASH_TABLE_SIZE 1021 

typedef struct ip_header {
    unsigned char  ihl : 4;
    unsigned char  version : 4;
    unsigned char  tos;
    unsigned short tot_len;
    unsigned short id;
    unsigned short frag_off;
    unsigned char  ttl;
    unsigned char  protocol;
    unsigned short check;
    unsigned int   saddr;
    unsigned int   daddr;
} ip_header_t;

typedef struct tcp_header {
    unsigned short source;
    unsigned short dest;
    unsigned int   seq;
    unsigned int   ack_seq;
    unsigned char  reserved : 4; 
    unsigned char  doff : 4;
    unsigned char  flags;
    unsigned short window;
    unsigned short check;
    unsigned short urg_ptr;
} tcp_header_t;

typedef struct {
    uint32_t ip_src;
    uint32_t ip_dst;
    uint16_t port_src;
    uint16_t port_dst;
} tcp_connection_key_t;

typedef struct handshake_data {
    int syn_seen;
    int synack_seen;
    struct timeval ts_syn;
    struct timeval ts_synack;
    int mss;
} handshake_data_t;

typedef struct rtt_pending_segment {
    uint32_t seq;
    uint32_t len;
    struct timeval send_ts;
    int is_retransmission_sample;
    struct rtt_pending_segment *next;
} rtt_pending_segment_t;

typedef struct rtt_sample_data {
    double rtt_milliseconds;
    struct rtt_sample_data *next;
} rtt_sample_data_t;

typedef struct cwnd_sample {
    struct timeval timestamp;
    uint32_t bytes_in_flight;
    struct cwnd_sample *next;
} cwnd_sample_t;

typedef struct seq_entry {
    uint32_t seq;
    uint32_t len;
    struct timeval ts;
    struct seq_entry *next;
} seq_entry_t;

typedef struct segment_size_node {
    int size;
    int count;
    struct segment_size_node *next;
} segment_size_node_t;

typedef struct connection_data {
    tcp_connection_key_t key;

    char src_ip_str[16]; 
    char dst_ip_str[16];

    struct timeval start_time;
    struct timeval end_time;

    uint64_t total_bytes;
    int packet_count;

    handshake_data_t handshake;

    rtt_pending_segment_t *rtt_pending_segments;
    rtt_sample_data_t *rtt_measurements;

    seq_entry_t *sent_seq_list; 
    int retransmissions;

    uint32_t isn_key_src;
    int isn_key_src_set;
    uint32_t rel_highest_seq_sent;
    uint32_t rel_highest_ack_received;
    cwnd_sample_t *cwnd_evolution_samples;

    segment_size_node_t *segment_sizes;

    int is_elephant_flow;

    struct connection_data *next; 
} connection_data_t;

connection_data_t *connections[HASH_TABLE_SIZE]; 

int port_counts_array[65536]; 

static uint64_t g_packets_processed = 0;

uint32_t calculate_key_hash(const tcp_connection_key_t *key);
int connection_key_equal(const tcp_connection_key_t *a, const tcp_connection_key_t *b);
void timeval_diff(const struct timeval *start, const struct timeval *end, struct timeval *result);
int parse_mss_option(const u_char *tcp_options, int options_len);
connection_data_t *find_connection(const tcp_connection_key_t *key);
connection_data_t *find_or_create_connection(const tcp_connection_key_t *key, struct timeval ts, uint32_t payload_len_this_pkt);
void add_segment_size(connection_data_t *conn, int size);
void add_port_count(uint16_t port);
void update_handshake_info(connection_data_t *conn_syn_sender, connection_data_t *conn_synack_sender, const tcp_header_t *tcp, const u_char* tcp_options_ptr, int tcp_options_len, struct timeval ts, const tcp_connection_key_t* flow_key_of_packet);
void process_rtt_sample_collection(connection_data_t *conn_data_path, uint32_t data_seq, uint32_t data_len, struct timeval data_ts, int is_retrans_sample);

void process_ack_for_segments(connection_data_t *conn_data_sender, uint32_t ack_seq_val, struct timeval ack_ts);
void update_cwnd_evolution(connection_data_t *conn_data_path, const tcp_header_t* tcp_packet, struct timeval pkt_ts, int payload_len, int is_ack_for_this_path_data, int is_data_from_this_path);
int check_and_log_retransmission(connection_data_t *conn, uint32_t seq, uint32_t len, struct timeval ts);

void cleanup_rtt_pending_segments(rtt_pending_segment_t *head);
void cleanup_rtt_measurements(rtt_sample_data_t *head);
void cleanup_sent_seq_list(seq_entry_t *head);
void cleanup_cwnd_evolution_samples(cwnd_sample_t *head);
void cleanup_segment_sizes(segment_size_node_t *head);
void cleanup_connections_and_ports();


uint32_t calculate_key_hash(const tcp_connection_key_t *key) {
    uint32_t hash = key->ip_src ^ key->ip_dst;
    hash ^= ((uint32_t)key->port_src << 16) | key->port_dst;
    hash ^= (hash >> 10);
    hash += (hash << 3);
    hash ^= (hash >> 6);
    hash += (hash << 14);
    return hash % HASH_TABLE_SIZE;
}

int connection_key_equal(const tcp_connection_key_t *a, const tcp_connection_key_t *b) {
    return (a->ip_src == b->ip_src && a->ip_dst == b->ip_dst &&
            a->port_src == b->port_src && a->port_dst == b->port_dst);
}

void timeval_diff(const struct timeval *start, const struct timeval *end, struct timeval *result) {
    result->tv_sec = end->tv_sec - start->tv_sec;
    result->tv_usec = end->tv_usec - start->tv_usec;
    if (result->tv_usec < 0) {
        result->tv_sec--;
        result->tv_usec += 1000000;
    }
}

int parse_mss_option(const u_char *tcp_options, int options_len) {
    int offset = 0;
    while (offset < options_len) {
        uint8_t kind = tcp_options[offset];
        if (kind == 0) break;
        if (kind == 1) { offset++; continue; } 

        if (offset + 1 >= options_len) break; 
        uint8_t length = tcp_options[offset + 1];
        if (length < 2 || offset + length > options_len) break; 

        if (kind == 2 && length == 4) { 
            uint16_t mss = (tcp_options[offset + 2] << 8) | tcp_options[offset + 3];
            return mss;
        }
        offset += length;
    }
    return -1; 
}


connection_data_t *find_connection(const tcp_connection_key_t *key) {
    uint32_t hash_index = calculate_key_hash(key);
    connection_data_t *curr = connections[hash_index];
    while (curr) {
        if (connection_key_equal(&curr->key, key)) return curr;
        curr = curr->next;
    }
    return NULL;
}

connection_data_t *find_or_create_connection(const tcp_connection_key_t *key, struct timeval ts, uint32_t payload_len_this_pkt) {
    connection_data_t *conn = find_connection(key);
    if (conn) {
        if (timercmp(&ts, &conn->end_time, >)) conn->end_time = ts;
        conn->total_bytes += payload_len_this_pkt;
        conn->packet_count++;
        return conn;
    }

    conn = (connection_data_t *)calloc(1, sizeof(connection_data_t));
    if (!conn) {
        perror("Falha ao alocar memória para connection_data_t");
        exit(EXIT_FAILURE);
    }

    conn->key = *key;
    conn->start_time = ts;
    conn->end_time = ts;
    conn->total_bytes = payload_len_this_pkt;
    conn->packet_count = 1;
    conn->handshake.mss = -1; 

    sprintf(conn->src_ip_str, "%u.%u.%u.%u", (key->ip_src >> 24) & 0xFF, (key->ip_src >> 16) & 0xFF, (key->ip_src >> 8) & 0xFF, key->ip_src & 0xFF);
    sprintf(conn->dst_ip_str, "%u.%u.%u.%u", (key->ip_dst >> 24) & 0xFF, (key->ip_dst >> 16) & 0xFF, (key->ip_dst >> 8) & 0xFF, key->ip_dst & 0xFF);

    uint32_t hash_index = calculate_key_hash(key);
    conn->next = connections[hash_index];
    connections[hash_index] = conn;
    return conn;
}

int check_and_log_retransmission(connection_data_t *conn, uint32_t seq, uint32_t len, struct timeval ts) {
    if (len == 0) return 0; 

    seq_entry_t *curr = conn->sent_seq_list;
    while (curr) {
        if (curr->seq == seq && curr->len == len) {
            if (timercmp(&ts, &curr->ts, >)) {
                conn->retransmissions++;
                return 1; 
            }
            return 0;
        }
        curr = curr->next;
    }

    seq_entry_t *new_entry = (seq_entry_t *)calloc(1, sizeof(seq_entry_t));
    if (!new_entry) { perror("Falha na alocação de malloc para seq_entry"); return 0; }
    new_entry->seq = seq;
    new_entry->len = len;
    new_entry->ts = ts;
    new_entry->next = conn->sent_seq_list;
    conn->sent_seq_list = new_entry;
    
    return 0; 
}


void add_segment_size(connection_data_t *conn, int size) {
    segment_size_node_t *curr = conn->segment_sizes;
    while (curr) {
        if (curr->size == size) {
            curr->count++;
            return;
        }
        curr = curr->next;
    }
    segment_size_node_t *new_node = (segment_size_node_t *)calloc(1, sizeof(segment_size_node_t));
    if (!new_node) { perror("Falha na alocação de malloc para segment_size_node"); return; }
    new_node->size = size;
    new_node->count = 1;
    new_node->next = conn->segment_sizes; 
    conn->segment_sizes = new_node;
}

void add_port_count(uint16_t port) {
    port_counts_array[port]++;
}

void update_handshake_info(connection_data_t *conn_syn_sender,
                            connection_data_t *conn_synack_sender,
                            const tcp_header_t *tcp, 
                            const u_char* tcp_options_ptr, int tcp_options_len, 
                            struct timeval ts, 
                            const tcp_connection_key_t* flow_key_of_packet) {
    int is_syn = (tcp->flags & TH_SYN) != 0;
    int is_ack = (tcp->flags & TH_ACK) != 0;

    if (conn_syn_sender && connection_key_equal(&conn_syn_sender->key, flow_key_of_packet)) {
        if (is_syn && !is_ack && !conn_syn_sender->handshake.syn_seen) {
            conn_syn_sender->handshake.syn_seen = 1;
            conn_syn_sender->handshake.ts_syn = ts;
            if (conn_syn_sender->handshake.mss == -1) {
                int mss_val = parse_mss_option(tcp_options_ptr, tcp_options_len);
                if (mss_val > 0) conn_syn_sender->handshake.mss = mss_val;
            }
        }
    }
    else if (conn_synack_sender && connection_key_equal(&conn_synack_sender->key, flow_key_of_packet)) {
        if (is_syn && is_ack && conn_syn_sender && conn_syn_sender->handshake.syn_seen && !conn_syn_sender->handshake.synack_seen) {
            conn_syn_sender->handshake.synack_seen = 1;
            conn_syn_sender->handshake.ts_synack = ts;
            if (conn_syn_sender->handshake.mss == -1) {
                int mss_val = parse_mss_option(tcp_options_ptr, tcp_options_len);
                if (mss_val > 0) conn_syn_sender->handshake.mss = mss_val;
            }
            if (conn_synack_sender->handshake.mss == -1) {
                int mss_val = parse_mss_option(tcp_options_ptr, tcp_options_len);
                if (mss_val > 0) conn_synack_sender->handshake.mss = mss_val;
            }
        }
    }
}


void process_rtt_sample_collection(connection_data_t *conn_data_path,
                                         uint32_t data_seq, uint32_t data_len, struct timeval data_ts, int is_retrans_sample) {
    if (data_len == 0) return; 

    rtt_pending_segment_t *new_pending = (rtt_pending_segment_t *)calloc(1, sizeof(rtt_pending_segment_t));
    if (!new_pending) { perror("Falha na alocação de malloc para rtt_pending_segment"); return; }
    new_pending->seq = data_seq;
    new_pending->len = data_len;
    new_pending->send_ts = data_ts;
    new_pending->is_retransmission_sample = is_retrans_sample;
    new_pending->next = conn_data_path->rtt_pending_segments;
    conn_data_path->rtt_pending_segments = new_pending;
}

void process_ack_for_segments(connection_data_t *conn_data_sender, uint32_t ack_seq_val, struct timeval ack_ts) {
    rtt_pending_segment_t *p_rtt = conn_data_sender->rtt_pending_segments;
    rtt_pending_segment_t *prev_p_rtt = NULL;

    while (p_rtt) {
        if (ack_seq_val >= (p_rtt->seq + p_rtt->len)) { 
            if (!p_rtt->is_retransmission_sample) {
                struct timeval rtt_diff;
                timeval_diff(&p_rtt->send_ts, &ack_ts, &rtt_diff);
                double rtt_ms = rtt_diff.tv_sec * 1000.0 + rtt_diff.tv_usec / 1000.0;
                if (rtt_ms >= 0) {
                    rtt_sample_data_t *new_rtt = (rtt_sample_data_t *)calloc(1, sizeof(rtt_sample_data_t));
                    if (new_rtt) {
                        new_rtt->rtt_milliseconds = rtt_ms;
                        new_rtt->next = conn_data_sender->rtt_measurements;
                        conn_data_sender->rtt_measurements = new_rtt;
                    }
                }
            }
            if (prev_p_rtt) prev_p_rtt->next = p_rtt->next;
            else conn_data_sender->rtt_pending_segments = p_rtt->next;
            
            rtt_pending_segment_t *to_free = p_rtt;
            p_rtt = p_rtt->next; 
            free(to_free);
        } else {
            prev_p_rtt = p_rtt;
            p_rtt = p_rtt->next;
        }
    }

    seq_entry_t *p_seq = conn_data_sender->sent_seq_list;
    seq_entry_t *prev_p_seq = NULL;

    while (p_seq) {
        if (ack_seq_val >= (p_seq->seq + p_seq->len)) {
            if (prev_p_seq) prev_p_seq->next = p_seq->next;
            else conn_data_sender->sent_seq_list = p_seq->next;
            
            seq_entry_t *to_free = p_seq;
            p_seq = p_seq->next; 
            free(to_free);
        } else {
            prev_p_seq = p_seq;
            p_seq = p_seq->next;
        }
    }
}


void update_cwnd_evolution(connection_data_t *conn_data_path,
                            const tcp_header_t* tcp_packet,
                            struct timeval pkt_ts,
                            int payload_len,
                            int is_ack_for_this_path_data,
                            int is_data_from_this_path) {

    if (!conn_data_path->isn_key_src_set && is_data_from_this_path && (tcp_packet->flags & TH_SYN)) {
        conn_data_path->isn_key_src = ntohl(tcp_packet->seq);
        conn_data_path->isn_key_src_set = 1;
        conn_data_path->rel_highest_seq_sent = (tcp_packet->flags & TH_FIN || tcp_packet->flags & TH_SYN) ? 1 : 0; 
        conn_data_path->rel_highest_ack_received = 0;
    }

    if (!conn_data_path->isn_key_src_set) return; 

    if (is_data_from_this_path) {
        uint32_t current_abs_seq_end = ntohl(tcp_packet->seq) + payload_len;
        if (tcp_packet->flags & TH_FIN || tcp_packet->flags & TH_SYN) current_abs_seq_end++; 

        uint32_t current_rel_seq_end = current_abs_seq_end - conn_data_path->isn_key_src;
        if (current_rel_seq_end > conn_data_path->rel_highest_seq_sent) {
            conn_data_path->rel_highest_seq_sent = current_rel_seq_end;
        }
    }

    if (is_ack_for_this_path_data) {
        uint32_t current_rel_ack = ntohl(tcp_packet->ack_seq) - conn_data_path->isn_key_src;
        if (current_rel_ack > conn_data_path->rel_highest_ack_received) {
            conn_data_path->rel_highest_ack_received = current_rel_ack;
        }
    }

    uint32_t bytes_flight = 0;
    if (conn_data_path->rel_highest_seq_sent > conn_data_path->rel_highest_ack_received) {
        bytes_flight = conn_data_path->rel_highest_seq_sent - conn_data_path->rel_highest_ack_received;
    }
    
    cwnd_sample_t *new_sample = (cwnd_sample_t*)calloc(1, sizeof(cwnd_sample_t));
    if (new_sample) {
        new_sample->timestamp = pkt_ts;
        new_sample->bytes_in_flight = bytes_flight;
        new_sample->next = conn_data_path->cwnd_evolution_samples; 
        conn_data_path->cwnd_evolution_samples = new_sample;
    }
}


void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
    (void)(param); 

    g_packets_processed++; 
    if (g_packets_processed % 100000 == 0) {
        printf("Pacotes processados: %llu.\n", (unsigned long long)g_packets_processed);
    }

    if (header->caplen < ETHERNET_HEADER_SIZE) return;

    const ip_header_t *ip = (ip_header_t *)(pkt_data + ETHERNET_HEADER_SIZE);

    unsigned int ip_header_len = ip->ihl * 4;
    if (ip_header_len < 20 || header->caplen < ETHERNET_HEADER_SIZE + ip_header_len) return;

    const tcp_header_t *tcp = (tcp_header_t *)((u_char *)ip + ip_header_len);
    unsigned int tcp_header_len = tcp->doff * 4;
    if (tcp_header_len < 20 || header->caplen < ETHERNET_HEADER_SIZE + ip_header_len + tcp_header_len) return;

    tcp_connection_key_t current_pkt_flow_key;
    current_pkt_flow_key.ip_src = ip->saddr;
    current_pkt_flow_key.ip_dst = ip->daddr;
    current_pkt_flow_key.port_src = tcp->source;
    current_pkt_flow_key.port_dst = tcp->dest;

    tcp_connection_key_t reverse_pkt_flow_key;
    reverse_pkt_flow_key.ip_src = ip->daddr;
    reverse_pkt_flow_key.ip_dst = ip->saddr;
    reverse_pkt_flow_key.port_src = tcp->dest;
    reverse_pkt_flow_key.port_dst = tcp->source;
    
    int payload_len = ntohs(ip->tot_len) - ip_header_len - tcp_header_len;
    if (payload_len < 0) payload_len = 0;

    connection_data_t *conn_forward = find_or_create_connection(&current_pkt_flow_key, header->ts, payload_len);
    connection_data_t *conn_reverse = find_connection(&reverse_pkt_flow_key); 

    const u_char *tcp_options_ptr = (const u_char *)tcp + 20;
    int tcp_options_len = tcp_header_len - 20;

    if (tcp->flags & TH_SYN) {
        connection_data_t* syn_sender_conn = NULL;
        connection_data_t* synack_sender_conn = NULL;

        if (!(tcp->flags & TH_ACK)) { 
            syn_sender_conn = conn_forward;
            synack_sender_conn = conn_reverse; 
        } else { 
            synack_sender_conn = conn_forward;
            syn_sender_conn = conn_reverse; 
        }
        update_handshake_info(syn_sender_conn, synack_sender_conn, tcp, tcp_options_ptr, tcp_options_len, header->ts, &current_pkt_flow_key);
    }

    if (payload_len > 0 || (tcp->flags & (TH_SYN | TH_FIN))) {
        add_segment_size(conn_forward, tcp_header_len + payload_len);
    }

    add_port_count(ntohs(tcp->source));
    add_port_count(ntohs(tcp->dest));

    int is_retransmission_event = 0;
    if (payload_len > 0) {
        is_retransmission_event = check_and_log_retransmission(conn_forward, ntohl(tcp->seq), payload_len, header->ts);
    }
    
    if (payload_len > 0) {
        process_rtt_sample_collection(conn_forward, ntohl(tcp->seq), payload_len, header->ts, is_retransmission_event);
    }

    if ((tcp->flags & TH_ACK) && conn_reverse) {
        process_ack_for_segments(conn_reverse, ntohl(tcp->ack_seq), header->ts);
    }

    update_cwnd_evolution(conn_forward, tcp, header->ts, payload_len, 0, (payload_len > 0 || (tcp->flags & (TH_SYN | TH_FIN))));

    if (conn_reverse && (tcp->flags & TH_ACK)) {
        update_cwnd_evolution(conn_reverse, tcp, header->ts, 0, 1, 0);
    }
}


void print_connections() {
    printf("\n--- Resumos de Conexão ---\n");
    int count = 0;
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        connection_data_t *curr = connections[i];
        while (curr) {
            count++;
            printf("Fluxo: %s:%u -> %s:%u\n", curr->src_ip_str, ntohs(curr->key.port_src), curr->dst_ip_str, ntohs(curr->key.port_dst));

            struct timeval duration;
            timeval_diff(&curr->start_time, &curr->end_time, &duration);
            printf("   Duração: %ld.%06lds, Pacotes: %d, Bytes: %llu, Retransmissões: %d\n",
                           duration.tv_sec, duration.tv_usec, curr->packet_count, (unsigned long long)curr->total_bytes, curr->retransmissions); 

            if (curr->handshake.syn_seen && curr->handshake.synack_seen) {
                struct timeval handshake_time;
                timeval_diff(&curr->handshake.ts_syn, &curr->handshake.ts_synack, &handshake_time);
                printf("   Tempo de Handshake (SYN para SYN/ACK): %ld.%06lds, MSS: %d\n",
                               handshake_time.tv_sec, handshake_time.tv_usec, curr->handshake.mss);
            } else if (curr->handshake.syn_seen) {
                printf("   Handshake: SYN visto, MSS: %d (SYN/ACK não visto ou não para o registro desta direção de fluxo)\n", curr->handshake.mss);
            }

            int rtt_count = 0; double avg_rtt = 0.0, sum_rtt = 0.0;
            rtt_sample_data_t *rtt_s = curr->rtt_measurements;
            while(rtt_s) { rtt_count++; sum_rtt += rtt_s->rtt_milliseconds; rtt_s = rtt_s->next; }
            if (rtt_count > 0) avg_rtt = sum_rtt / rtt_count;
            printf("   Amostras de RTT: %d, RTT Médio: %.3f ms\n", rtt_count, avg_rtt);
            
            printf("\n");
            curr = curr->next;
        }
    }
    printf("Total de fluxos únicos processados: %d\n", count);
}

void print_top_ports() {
    int total_port_mentions = 0;
    for (int i = 0; i < 65536; i++) {
        total_port_mentions += port_counts_array[i];
    }
    if (total_port_mentions == 0) total_port_mentions = 1; 

    printf("\n--- Top 10 Portas (por aparição como src/dst) ---\n");
    
    typedef struct {
        uint16_t port;
        int count;
    } PortStat;

    PortStat *all_ports_stats = (PortStat *)malloc(65536 * sizeof(PortStat));
    if (!all_ports_stats) {
        perror("Falha na alocação de malloc para all_ports_stats");
        return;
    }

    int num_unique_ports = 0;
    for (int i = 0; i < 65536; i++) {
        if (port_counts_array[i] > 0) {
            all_ports_stats[num_unique_ports].port = i;
            all_ports_stats[num_unique_ports].count = port_counts_array[i];
            num_unique_ports++;
        }
    }

    for (int i = 0; i < num_unique_ports - 1; i++) {
        for (int j = 0; j < num_unique_ports - i - 1; j++) {
            if (all_ports_stats[j].count < all_ports_stats[j+1].count) {
                PortStat temp = all_ports_stats[j];
                all_ports_stats[j] = all_ports_stats[j+1];
                all_ports_stats[j+1] = temp;
            }
        }
    }

    for (int i = 0; i < 10 && i < num_unique_ports; i++) {
        double perc = (double)all_ports_stats[i].count * 100.0 / total_port_mentions;
        printf("Porta %u: %d menções (%.2f%%)\n", all_ports_stats[i].port, all_ports_stats[i].count, perc);
    }
    
    free(all_ports_stats);
}

void save_all_data_to_csv() { 
    FILE *f_summary = fopen("connection_summary.csv", "w");
    FILE *f_rtt = fopen("rtt_samples.csv", "w");
    FILE *f_cwnd = fopen("cwnd_evolution.csv", "w");
    FILE *f_segments = fopen("segment_sizes.csv", "w");

    if (!f_summary || !f_rtt || !f_cwnd || !f_segments) {
        perror("Erro ao abrir um ou mais arquivos CSV para escrita");
        if(f_summary) fclose(f_summary);
        if(f_rtt) fclose(f_rtt);
        if(f_cwnd) fclose(f_cwnd);
        if(f_segments) fclose(f_segments);
        return;
    }

    fprintf(f_summary, "SrcIP,SrcPort,DstIP,DstPort,StartTime_s,EndTime_s,Duration_s,TotalBytes,TotalPackets,Retransmissions,HandshakeTime_ms,MSS,IsElephant,AvgThroughput_bps,AvgRTT_ms,RTT_SamplesCount\n");
    fprintf(f_rtt, "SrcIP,SrcPort,DstIP,DstPort,RTT_ms\n");
    fprintf(f_cwnd, "SrcIP,SrcPort,DstIP,DstPort,Timestamp_s,BytesInFlight\n");
    fprintf(f_segments, "SrcIP,SrcPort,DstIP,DstPort,SegmentSize,Count\n");

    const uint64_t ELEPHANT_THRESHOLD_BYTES = 1 * 1024 * 1024; // 1MB

    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        connection_data_t *curr = connections[i];
        while (curr) {
            double start_s = curr->start_time.tv_sec + curr->start_time.tv_usec / 1000000.0;
            double end_s = curr->end_time.tv_sec + curr->end_time.tv_usec / 1000000.0;
            double duration_s = end_s - start_s;
            if (duration_s < 0.000001) duration_s = 0.000001; 

            double avg_throughput_bps = (curr->total_bytes * 8.0) / duration_s;

            double handshake_time_ms = -1.0;
            if (curr->handshake.syn_seen && curr->handshake.synack_seen) {
                struct timeval handshake_tv;
                timeval_diff(&curr->handshake.ts_syn, &curr->handshake.ts_synack, &handshake_tv);
                handshake_time_ms = handshake_tv.tv_sec * 1000.0 + handshake_tv.tv_usec / 1000.0;
            }
            
            curr->is_elephant_flow = (curr->total_bytes > ELEPHANT_THRESHOLD_BYTES) ? 1 : 0;

            int rtt_count = 0; double avg_rtt = 0.0, sum_rtt = 0.0;
            rtt_sample_data_t *rtt_s = curr->rtt_measurements;
            while(rtt_s) { rtt_count++; sum_rtt += rtt_s->rtt_milliseconds; rtt_s = rtt_s->next; }
            if (rtt_count > 0) avg_rtt = sum_rtt / rtt_count;

            fprintf(f_summary, "%s,%u,%s,%u,%.6f,%.6f,%.6f,%llu,%d,%d,%.3f,%d,%d,%.2f,%.3f,%d\n",
                            curr->src_ip_str, ntohs(curr->key.port_src),
                            curr->dst_ip_str, ntohs(curr->key.port_dst),
                            start_s, end_s, duration_s,
                            (unsigned long long)curr->total_bytes, curr->packet_count, curr->retransmissions,
                            handshake_time_ms, curr->handshake.mss, curr->is_elephant_flow, avg_throughput_bps,
                            avg_rtt, rtt_count);

            rtt_s = curr->rtt_measurements;
            while(rtt_s) {
                fprintf(f_rtt, "%s,%u,%s,%u,%.3f\n",
                                curr->src_ip_str, ntohs(curr->key.port_src),
                                curr->dst_ip_str, ntohs(curr->key.port_dst),
                                rtt_s->rtt_milliseconds);
                rtt_s = rtt_s->next;
            }

            cwnd_sample_t *cwnd_s = curr->cwnd_evolution_samples;
            while(cwnd_s) {
                double ts_s = cwnd_s->timestamp.tv_sec + cwnd_s->timestamp.tv_usec / 1000000.0;
                fprintf(f_cwnd, "%s,%u,%s,%u,%.6f,%u\n",
                                curr->src_ip_str, ntohs(curr->key.port_src),
                                curr->dst_ip_str, ntohs(curr->key.port_dst),
                                ts_s, cwnd_s->bytes_in_flight);
                cwnd_s = cwnd_s->next;
            }

            segment_size_node_t *seg_s = curr->segment_sizes;
            while(seg_s) {
                fprintf(f_segments, "%s,%u,%s,%u,%d,%d\n",
                                curr->src_ip_str, ntohs(curr->key.port_src),
                                curr->dst_ip_str, ntohs(curr->key.port_dst),
                                seg_s->size, seg_s->count);
                seg_s = seg_s->next;
            }
            curr = curr->next;
        }
    }

    fclose(f_summary);
    fclose(f_rtt);
    fclose(f_cwnd);
    fclose(f_segments);
}

void cleanup_rtt_pending_segments(rtt_pending_segment_t *head) {
    rtt_pending_segment_t *curr = head;
    while (curr) {
        rtt_pending_segment_t *temp = curr;
        curr = curr->next;
        free(temp);
    }
}

void cleanup_rtt_measurements(rtt_sample_data_t *head) {
    rtt_sample_data_t *curr = head;
    while (curr) {
        rtt_sample_data_t *temp = curr;
        curr = curr->next;
        free(temp);
    }
}

void cleanup_sent_seq_list(seq_entry_t *head) {
    seq_entry_t *curr = head;
    while (curr) {
        seq_entry_t *temp = curr;
        curr = curr->next;
        free(temp);
    }
}

void cleanup_cwnd_evolution_samples(cwnd_sample_t *head) {
    cwnd_sample_t *curr = head;
    while (curr) {
        cwnd_sample_t *temp = curr;
        curr = curr->next;
        free(temp);
    }
}

void cleanup_segment_sizes(segment_size_node_t *head) {
    segment_size_node_t *curr = head;
    while (curr) {
        segment_size_node_t *temp = curr;
        curr = curr->next;
        free(temp);
    }
}

void cleanup_connections_and_ports() {
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        connection_data_t *curr_conn = connections[i];
        while (curr_conn) {
            cleanup_rtt_pending_segments(curr_conn->rtt_pending_segments);
            cleanup_rtt_measurements(curr_conn->rtt_measurements);
            cleanup_sent_seq_list(curr_conn->sent_seq_list);
            cleanup_cwnd_evolution_samples(curr_conn->cwnd_evolution_samples);
            cleanup_segment_sizes(curr_conn->segment_sizes);

            connection_data_t *temp_conn = curr_conn;
            curr_conn = curr_conn->next;
            free(temp_conn);
        }
        connections[i] = NULL; 
    }
}


int main(int argc, char **argv) {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    const char *pcap_file;
    struct bpf_program fp;      
    int limite_pacotes = 300000; // -1 é rodar tudo do pacote se quise bota um valor aleatorio aqui pra diminui tempo kkkkkkkkkkk
    bpf_u_int32 net;            

    if (argc != 2) {
        fprintf(stderr, "Uso: %s <arquivo_pcap>\n", argv[0]);
        return 1;
    }
    pcap_file = argv[1];

    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        connections[i] = NULL;
    }
    memset(port_counts_array, 0, sizeof(port_counts_array));

    handle = pcap_open_offline(pcap_file, errbuf);
    if (!handle) {
        fprintf(stderr, "Erro ao abrir o arquivo pcap %s: %s\n", pcap_file, errbuf);
        return 1;
    }

    if (pcap_compile(handle, &fp, "tcp", 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Não foi possível analisar o filtro 'tcp': %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Não foi possível instalar o filtro 'tcp': %s\n", pcap_geterr(handle));
        pcap_freecode(&fp);
        pcap_close(handle);
        return 1;
    }

    pcap_loop(handle, limite_pacotes, packet_handler, NULL);

    printf("\nProcessamento de pacotes finalizado.\n");

    print_connections();
    print_top_ports();
    save_all_data_to_csv();

    cleanup_connections_and_ports();
    pcap_freecode(&fp);
    pcap_close(handle);

    return 0;
}
