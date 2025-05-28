#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>     // Para uint32_t, uint64_t, etc.
#include <sys/time.h>   // Para struct timeval e timeval_diff (pode já ser incluído por pcap.h)
#include <netinet/in.h> // Para IPPROTO_TCP e ntohs/ntohl (pode já ser incluído por pcap.h)
// #include <arpa/inet.h> // Se fosse usar inet_ntoa ou inet_ntop


#define ETHERNET_HEADER_SIZE 14

#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20

// Estruturas de Cabeçalho IP e TCP (como no original)
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
    unsigned char  reserved : 4; // Corrigido: reserved e doff ordem
    unsigned char  doff : 4;
    unsigned char  flags;
    unsigned short window;
    unsigned short check;
    unsigned short urg_ptr;
} tcp_header_t;

// Chave para identificar uma conexão TCP (unidirecional)
typedef struct {
    uint32_t ip_src;
    uint32_t ip_dst;
    uint16_t port_src;
    uint16_t port_dst;
} tcp_connection_key_t;

// Dados do Handshake (como no original)
typedef struct handshake_data {
    int syn_seen;       // SYN from key.ip_src
    int synack_seen;    // SYN/ACK from key.ip_dst
    struct timeval ts_syn;
    struct timeval ts_synack;
    int mss;            // MSS from SYN or SYN/ACK options
} handshake_data_t;

// Para RTT: Segmentos enviados aguardando ACK
typedef struct rtt_pending_segment {
    uint32_t seq;       // Absolute sequence number of the data segment sent by this flow's source
    uint32_t len;       // Payload length of the data segment
    struct timeval send_ts;
    int is_retransmission_sample; // Was this segment considered a retransmission when sent?
    struct rtt_pending_segment *next;
} rtt_pending_segment_t;

// Para RTT: Amostras de RTT calculadas
typedef struct rtt_sample_data {
    double rtt_milliseconds;
    struct rtt_sample_data *next;
} rtt_sample_data_t;

// Para CWND: Amostras de bytes em trânsito
typedef struct cwnd_sample {
    struct timeval timestamp;
    uint32_t bytes_in_flight;
    struct cwnd_sample *next;
} cwnd_sample_t;

// Para Retransmissão: Rastreamento de segmentos enviados
typedef struct seq_entry {
    uint32_t seq;       // Absolute sequence number
    uint32_t len;       // Payload length
    struct timeval ts;  // Timestamp of first transmission of this seq+len
    int acked;          // Has this segment been acked? (for more advanced retransmission)
    struct seq_entry *next;
} seq_entry_t;

// Para Distribuição de Tamanhos de Segmento (como no original)
typedef struct segment_size_node {
    int size;   // TCP Header + Payload
    int count;
    struct segment_size_node *next;
} segment_size_node_t;

// Estrutura principal de dados da conexão
typedef struct connection_data {
    tcp_connection_key_t key;

    struct timeval start_time;
    struct timeval end_time;

    uint64_t total_bytes;   // Bytes for key.ip_src -> key.ip_dst
    int packet_count;       // Packets for key.ip_src -> key.ip_dst

    handshake_data_t handshake;

    // RTT Estimation: for data sent by key.ip_src and ACKed by key.ip_dst
    rtt_pending_segment_t *rtt_pending_segments;
    rtt_sample_data_t *rtt_measurements;

    // Retransmissions: for data sent by key.ip_src
    seq_entry_t *sent_seq_list; // Lista de segmentos únicos de dados enviados por key.ip_src
    int retransmissions;

    // CWND Evolution: for data sent by key.ip_src
    uint32_t isn_key_src;
    int isn_key_src_set;
    uint32_t rel_highest_seq_sent;   // Relative to isn_key_src
    uint32_t rel_highest_ack_received; // Relative to isn_key_src (ack for this flow's data)
    cwnd_sample_t *cwnd_evolution_samples;

    // Segment Sizes: for segments sent by key.ip_src
    segment_size_node_t *segment_sizes;

    int is_elephant_flow; // Flag set during post-processing

    struct connection_data *next;
} connection_data_t;

connection_data_t *connections = NULL;

// Para Top 10 Portas (como no original)
typedef struct port_count {
    uint16_t port;
    int count;
    struct port_count *next;
} port_count_t;
port_count_t *port_counts = NULL;


// --- Protótipos de Funções Auxiliares ---
int connection_key_equal(const tcp_connection_key_t *a, const tcp_connection_key_t *b);
void timeval_diff(const struct timeval *start, const struct timeval *end, struct timeval *result);
int parse_mss_option(const u_char *tcp_options, int options_len);
connection_data_t *find_connection(const tcp_connection_key_t *key);
connection_data_t *find_or_create_connection(const tcp_connection_key_t *key, struct timeval ts, uint32_t payload_len_this_pkt);
void add_segment_size(connection_data_t *conn, int size);
void add_port_count(uint16_t port);
void update_handshake_info(connection_data_t *conn_syn_sender, connection_data_t *conn_synack_sender, const tcp_header_t *tcp, const u_char* tcp_options_ptr, int tcp_options_len, struct timeval ts, const tcp_connection_key_t* flow_key_of_packet);
void process_rtt_and_retransmission(connection_data_t *conn_data_sender, const tcp_header_t *tcp_ack_packet, struct timeval ack_ts, uint32_t payload_len_of_data_pkt);
void update_cwnd_evolution(connection_data_t *conn_data_path, const tcp_header_t* tcp_packet, struct timeval pkt_ts, int payload_len, int is_ack_for_this_path_data, int is_data_from_this_path);
void save_all_data_to_csv(connection_data_t *conns);
void cleanup_connections(connection_data_t *conns);
int check_and_log_retransmission(connection_data_t *conn, uint32_t seq, uint32_t len, struct timeval ts);


// --- Implementações ---

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
        if (kind == 0) break; // End of options list
        if (kind == 1) { offset++; continue; } // NOP

        if (offset + 1 >= options_len) break; // Malformed
        uint8_t length = tcp_options[offset + 1];
        if (length < 2 || offset + length > options_len) break; // Malformed

        if (kind == 2 && length == 4) { // MSS
            uint16_t mss = (tcp_options[offset + 2] << 8) | tcp_options[offset + 3];
            return mss;
        }
        offset += length;
    }
    return -1; // MSS option not found or malformed
}


connection_data_t *find_connection(const tcp_connection_key_t *key) {
    connection_data_t *curr = connections;
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
        // start_time is set at creation
        conn->total_bytes += payload_len_this_pkt; // Only payload for this specific packet/direction
        conn->packet_count++;
        return conn;
    }

    conn = (connection_data_t *)malloc(sizeof(connection_data_t));
    if (!conn) {
        perror("Failed to allocate memory for connection_data_t");
        exit(EXIT_FAILURE); // Critical error
    }
    memset(conn, 0, sizeof(connection_data_t)); // Initialize all fields to 0/NULL

    conn->key = *key;
    conn->start_time = ts;
    conn->end_time = ts;
    conn->total_bytes = payload_len_this_pkt;
    conn->packet_count = 1;
    conn->handshake.mss = -1; // Default MSS

    // Initialize all pointers to NULL (already done by memset)
    // conn->rtt_pending_segments = NULL;
    // conn->rtt_measurements = NULL;
    // conn->sent_seq_list = NULL;
    // conn->cwnd_evolution_samples = NULL;
    // conn->segment_sizes = NULL;

    conn->next = connections;
    connections = conn;
    return conn;
}

// Improved retransmission check and logging
// Returns 1 if it's a retransmission, 0 otherwise. Increments conn->retransmissions.
int check_and_log_retransmission(connection_data_t *conn, uint32_t seq, uint32_t len, struct timeval ts) {
    if (len == 0) return 0; // Typically don't track retransmissions of non-data segments like pure ACKs

    seq_entry_t *curr = conn->sent_seq_list;
    int found_earlier_transmission = 0;
    while (curr) {
        if (curr->seq == seq && curr->len == len) {
            // Found a previous transmission of the same segment (seq+len).
            // If current timestamp is later, it's a retransmission.
            if (timercmp(&ts, &curr->ts, >)) {
                // To avoid double counting for same retransmission event if packets are very close,
                // one might add a small delta time check, but this is simpler.
                // This simple check doesn't consider if it was acked in between.
                conn->retransmissions++;
                return 1; // It's a retransmission
            }
            found_earlier_transmission = 1; // It was sent before, but current one is not later (e.g. out-of-order capture)
            break; 
        }
        curr = curr->next;
    }

    // If not found_earlier_transmission, it's a new segment, log it.
    if (!found_earlier_transmission) {
        seq_entry_t *new_entry = (seq_entry_t *)malloc(sizeof(seq_entry_t));
        if (!new_entry) { perror("malloc failed for seq_entry"); return 0; }
        new_entry->seq = seq;
        new_entry->len = len;
        new_entry->ts = ts;
        new_entry->acked = 0;
        new_entry->next = conn->sent_seq_list;
        conn->sent_seq_list = new_entry;
    }
    return 0; // Not a retransmission based on this logic, or it's the first time we log it
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
    segment_size_node_t *new_node = (segment_size_node_t *)malloc(sizeof(segment_size_node_t));
    if (!new_node) { perror("malloc failed for segment_size_node"); return; }
    new_node->size = size;
    new_node->count = 1;
    new_node->next = conn->segment_sizes;
    conn->segment_sizes = new_node;
}

void add_port_count(uint16_t port) {
    port_count_t *curr = port_counts;
    while (curr) {
        if (curr->port == port) {
            curr->count++;
            return;
        }
        curr = curr->next;
    }
    port_count_t *new_node = (port_count_t *)malloc(sizeof(port_count_t));
    if (!new_node) { perror("malloc failed for port_count"); return; }
    new_node->port = port;
    new_node->count = 1;
    new_node->next = port_counts;
    port_counts = new_node;
}

void update_handshake_info(connection_data_t *conn_syn_sender, // The connection from the SYN sender's perspective
                           connection_data_t *conn_synack_sender, // The connection from the SYN-ACK sender's perspective
                           const tcp_header_t *tcp, 
                           const u_char* tcp_options_ptr, int tcp_options_len, 
                           struct timeval ts, 
                           const tcp_connection_key_t* flow_key_of_packet // Key of the current packet
                           ) {
    int is_syn = (tcp->flags & TH_SYN) != 0;
    int is_ack = (tcp->flags & TH_ACK) != 0;

    // Packet is from SYN sender (e.g. client to server)
    if (conn_syn_sender && connection_key_equal(&conn_syn_sender->key, flow_key_of_packet)) {
        if (is_syn && !is_ack && !conn_syn_sender->handshake.syn_seen) {
            conn_syn_sender->handshake.syn_seen = 1;
            conn_syn_sender->handshake.ts_syn = ts;
            if (conn_syn_sender->handshake.mss == -1) { // Get MSS from SYN if available
                 int mss_val = parse_mss_option(tcp_options_ptr, tcp_options_len);
                 if (mss_val > 0) conn_syn_sender->handshake.mss = mss_val;
            }
             // If conn_synack_sender also exists, its handshake.mss might also be set from this packet
            if (conn_synack_sender && conn_synack_sender->handshake.mss == -1) {
                int mss_val = parse_mss_option(tcp_options_ptr, tcp_options_len);
                if (mss_val > 0) conn_synack_sender->handshake.mss = mss_val;
            }
        }
    }
    // Packet is from SYN-ACK sender (e.g. server to client)
    else if (conn_synack_sender && connection_key_equal(&conn_synack_sender->key, flow_key_of_packet)) {
         if (is_syn && is_ack && conn_syn_sender && conn_syn_sender->handshake.syn_seen && !conn_syn_sender->handshake.synack_seen) {
            conn_syn_sender->handshake.synack_seen = 1; // Mark on the SYN sender's record
            conn_syn_sender->handshake.ts_synack = ts;  // Time SYN-ACK was received by SYN sender (captured)
             if (conn_syn_sender->handshake.mss == -1) { // Get MSS from SYN-ACK if not in SYN
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


void process_rtt_sample_collection(connection_data_t *conn_data_path, // Flow that sent the data
                                   uint32_t data_seq, uint32_t data_len, struct timeval data_ts, int is_retrans_sample) {
    if (data_len == 0) return; // Only for data packets

    rtt_pending_segment_t *new_pending = (rtt_pending_segment_t *)malloc(sizeof(rtt_pending_segment_t));
    if (!new_pending) { perror("malloc for rtt_pending_segment failed"); return; }
    new_pending->seq = data_seq;
    new_pending->len = data_len;
    new_pending->send_ts = data_ts;
    new_pending->is_retransmission_sample = is_retrans_sample;
    new_pending->next = conn_data_path->rtt_pending_segments;
    conn_data_path->rtt_pending_segments = new_pending;
}

void match_ack_for_rtt(connection_data_t *conn_data_sender, // Flow that originally sent the data
                       uint32_t ack_seq_val, struct timeval ack_ts) {
    rtt_pending_segment_t *p = conn_data_sender->rtt_pending_segments;
    rtt_pending_segment_t *prev_p = NULL;

    while (p) {
        // If the ACK acknowledges this segment (or beyond)
        // and this segment wasn't a retransmission (Karn's algorithm part 1)
        if (ack_seq_val >= (p->seq + p->len)) { 
            if (!p->is_retransmission_sample) { // Only sample RTT for non-retransmitted segments
                struct timeval rtt_diff;
                timeval_diff(&p->send_ts, &ack_ts, &rtt_diff);
                double rtt_ms = rtt_diff.tv_sec * 1000.0 + rtt_diff.tv_usec / 1000.0;
                if (rtt_ms >= 0) { // Basic sanity check
                    rtt_sample_data_t *new_rtt = (rtt_sample_data_t *)malloc(sizeof(rtt_sample_data_t));
                    if (new_rtt) {
                        new_rtt->rtt_milliseconds = rtt_ms;
                        new_rtt->next = conn_data_sender->rtt_measurements;
                        conn_data_sender->rtt_measurements = new_rtt;
                    }
                }
            }
            // Remove the acked segment from pending list
            if (prev_p) prev_p->next = p->next;
            else conn_data_sender->rtt_pending_segments = p->next;
            
            rtt_pending_segment_t *to_free = p;
            p = p->next;
            free(to_free);
            // An ACK can acknowledge multiple segments. For RTT, we typically match one outstanding segment.
            // This simple logic takes the first match. More complex logic could try to match more precisely.
            // continue; // Let's remove only one matching segment per ACK for simplicity
            return; // Process one match and return
        }
        prev_p = p;
        p = p->next;
    }
}


void update_cwnd_evolution(connection_data_t *conn_data_path, // The flow whose CWND (bytes in flight) we are tracking
                           const tcp_header_t* tcp_packet, // The current packet being processed
                           struct timeval pkt_ts, 
                           int payload_len, // Payload of current packet
                           int is_ack_for_this_path_data, // Boolean: is this packet an ACK for conn_data_path's data?
                           int is_data_from_this_path) {  // Boolean: is this packet data from conn_data_path?

    if (!conn_data_path->isn_key_src_set && is_data_from_this_path && (tcp_packet->flags & TH_SYN)) {
        conn_data_path->isn_key_src = ntohl(tcp_packet->seq);
        conn_data_path->isn_key_src_set = 1;
        // SYN consumes 1 seq number. If there's payload (unlikely with SYN), it's added below.
        conn_data_path->rel_highest_seq_sent = (tcp_packet->flags & TH_FIN || tcp_packet->flags & TH_SYN) ? 1 : 0; 
        conn_data_path->rel_highest_ack_received = 0;
    }

    if (!conn_data_path->isn_key_src_set) return; // Cannot proceed without ISN

    if (is_data_from_this_path) {
        uint32_t current_abs_seq_end = ntohl(tcp_packet->seq) + payload_len;
        if (tcp_packet->flags & TH_FIN || tcp_packet->flags & TH_SYN) current_abs_seq_end++; // FIN/SYN consume a sequence number

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

    // Record bytes in flight if a change occurred or periodically
    // Ensure seq_sent is ahead of ack_received before calculating diff.
    if (conn_data_path->rel_highest_seq_sent > conn_data_path->rel_highest_ack_received) {
        uint32_t bytes_flight = conn_data_path->rel_highest_seq_sent - conn_data_path->rel_highest_ack_received;
        
        cwnd_sample_t *new_sample = (cwnd_sample_t*)malloc(sizeof(cwnd_sample_t));
        if (new_sample) {
            new_sample->timestamp = pkt_ts;
            new_sample->bytes_in_flight = bytes_flight;
            new_sample->next = conn_data_path->cwnd_evolution_samples;
            conn_data_path->cwnd_evolution_samples = new_sample;
        }
    } else if (conn_data_path->rel_highest_seq_sent <= conn_data_path->rel_highest_ack_received) {
        // All sent data acked, or initial state, 0 bytes in flight for this sample
        cwnd_sample_t *new_sample = (cwnd_sample_t*)malloc(sizeof(cwnd_sample_t));
        if (new_sample) {
            new_sample->timestamp = pkt_ts;
            new_sample->bytes_in_flight = 0;
            new_sample->next = conn_data_path->cwnd_evolution_samples;
            conn_data_path->cwnd_evolution_samples = new_sample;
        }
    }
}


void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
    (void)(param); // Unused parameter

    if (header->caplen < ETHERNET_HEADER_SIZE) return; // Packet too short

    const ip_header_t *ip = (ip_header_t *)(pkt_data + ETHERNET_HEADER_SIZE);
    if (ip->version != 4) return; // Only IPv4
    if (ip->protocol != IPPROTO_TCP) return; // Only TCP

    unsigned int ip_header_len = ip->ihl * 4;
    if (ip_header_len < 20 || header->caplen < ETHERNET_HEADER_SIZE + ip_header_len) return; // IP header too short or packet too short

    const tcp_header_t *tcp = (tcp_header_t *)((u_char *)ip + ip_header_len);
    unsigned int tcp_header_len = tcp->doff * 4;
    if (tcp_header_len < 20 || header->caplen < ETHERNET_HEADER_SIZE + ip_header_len + tcp_header_len) return; // TCP header too short or packet too short

    // --- Define keys for forward and reverse flow relative to the current packet ---
    tcp_connection_key_t current_pkt_flow_key; // Packet's actual src->dst
    current_pkt_flow_key.ip_src = ip->saddr;
    current_pkt_flow_key.ip_dst = ip->daddr;
    current_pkt_flow_key.port_src = tcp->source;
    current_pkt_flow_key.port_dst = tcp->dest;

    tcp_connection_key_t reverse_pkt_flow_key; // Reverse of packet's actual src->dst
    reverse_pkt_flow_key.ip_src = ip->daddr;
    reverse_pkt_flow_key.ip_dst = ip->saddr;
    reverse_pkt_flow_key.port_src = tcp->dest;
    reverse_pkt_flow_key.port_dst = tcp->source;
    
    int payload_len = ntohs(ip->tot_len) - ip_header_len - tcp_header_len;
    if (payload_len < 0) payload_len = 0; // Should not happen with valid packets

    // --- Find or Create Connection Entries ---
    // conn_forward represents the flow in the same direction as the current packet
    connection_data_t *conn_forward = find_or_create_connection(&current_pkt_flow_key, header->ts, payload_len);
    // conn_reverse represents the flow in the opposite direction of the current packet
    // We find it here; it might not exist yet if this is the first packet in that reverse direction.
    connection_data_t *conn_reverse = find_connection(&reverse_pkt_flow_key);


    // --- Update Handshake Info ---
    // Handshake data (SYN time, SYN-ACK time, MSS) is typically stored on the connection record of the SYN sender.
    // If current packet is from SYN sender: conn_forward is SYN sender's record.
    // If current packet is from SYN-ACK sender: conn_reverse is SYN sender's record.
    const u_char *tcp_options_ptr = (const u_char *)tcp + 20;
    int tcp_options_len = tcp_header_len - 20;

    if (tcp->flags & TH_SYN) { // Only call update_handshake_info for SYN or SYN/ACK packets
        connection_data_t* syn_sender_conn = NULL;
        connection_data_t* synack_sender_conn = NULL;

        if (!(tcp->flags & TH_ACK)) { // Pure SYN from current_pkt_flow_key.ip_src
            syn_sender_conn = conn_forward;
            synack_sender_conn = conn_reverse; // Might be NULL if not created yet
        } else { // SYN/ACK from current_pkt_flow_key.ip_src
            synack_sender_conn = conn_forward;
            syn_sender_conn = conn_reverse; // Should exist if SYN was processed
        }
        update_handshake_info(syn_sender_conn, synack_sender_conn, tcp, tcp_options_ptr, tcp_options_len, header->ts, &current_pkt_flow_key);
    }


    // --- Segment Size Distribution (for segments sent by current_pkt_flow_key.ip_src) ---
    if (payload_len > 0 || (tcp->flags & (TH_SYN | TH_FIN))) { // Consider data packets and SYN/FIN for segment size
        add_segment_size(conn_forward, tcp_header_len + payload_len);
    }

    // --- Port Usage Count ---
    add_port_count(ntohs(tcp->source)); // Count both source and dest ports as "used"
    add_port_count(ntohs(tcp->dest));   // (ntohs for printing/comparing later)

    // --- Retransmission Check (for data sent by current_pkt_flow_key.ip_src) ---
    int is_retransmission_event = 0;
    if (payload_len > 0) { // Only check data-carrying segments for retransmissions this way
        is_retransmission_event = check_and_log_retransmission(conn_forward, ntohl(tcp->seq), payload_len, header->ts);
    }
    
    // --- RTT Logic ---
    // If current packet is DATA from current_pkt_flow_key.ip_src: log it for RTT pending.
    if (payload_len > 0) {
        process_rtt_sample_collection(conn_forward, ntohl(tcp->seq), payload_len, header->ts, is_retransmission_event);
    }
    // If current packet is an ACK from current_pkt_flow_key.ip_src:
    // This ACK is for data sent by reverse flow (conn_reverse).
    if ((tcp->flags & TH_ACK) && conn_reverse) {
        match_ack_for_rtt(conn_reverse, ntohl(tcp->ack_seq), header->ts);
    }

    // --- CWND Evolution Logic ---
    // Update CWND for the forward path (conn_forward) if this packet is data from it
    update_cwnd_evolution(conn_forward, tcp, header->ts, payload_len, 0, (payload_len > 0 || (tcp->flags & (TH_SYN | TH_FIN))));
    // Update CWND for the reverse path (conn_reverse) if this packet is an ACK for its data
    if (conn_reverse && (tcp->flags & TH_ACK)) {
        update_cwnd_evolution(conn_reverse, tcp, header->ts, 0, 1, 0);
    }
}


void print_connections() { // Basic console printing, CSVs are more important
    connection_data_t *curr = connections;
    printf("\n--- Connection Summaries ---\n");
    int count = 0;
    while (curr) {
        count++;
        char src_ip_str[16], dst_ip_str[16];
        sprintf(src_ip_str, "%u.%u.%u.%u", (curr->key.ip_src >> 24) & 0xFF, (curr->key.ip_src >> 16) & 0xFF, (curr->key.ip_src >> 8) & 0xFF, curr->key.ip_src & 0xFF);
        sprintf(dst_ip_str, "%u.%u.%u.%u", (curr->key.ip_dst >> 24) & 0xFF, (curr->key.ip_dst >> 16) & 0xFF, (curr->key.ip_dst >> 8) & 0xFF, curr->key.ip_dst & 0xFF);

        printf("Flow: %s:%u -> %s:%u\n", src_ip_str, ntohs(curr->key.port_src), dst_ip_str, ntohs(curr->key.port_dst));

        struct timeval duration;
        timeval_diff(&curr->start_time, &curr->end_time, &duration);
        printf("  Duration: %ld.%06lds, Packets: %d, Bytes: %lu, Retransmissions: %d\n",
               duration.tv_sec, duration.tv_usec, curr->packet_count, curr->total_bytes, curr->retransmissions);

        if (curr->handshake.syn_seen && curr->handshake.synack_seen) {
            struct timeval handshake_time;
            timeval_diff(&curr->handshake.ts_syn, &curr->handshake.ts_synack, &handshake_time);
            printf("  Handshake Time (SYN to SYN/ACK): %ld.%06lds, MSS: %d\n",
                   handshake_time.tv_sec, handshake_time.tv_usec, curr->handshake.mss);
        } else if (curr->handshake.syn_seen) {
            printf("  Handshake: SYN seen, MSS: %d (SYN/ACK not seen or not for this flow direction's record)\n", curr->handshake.mss);
        }


        // Count RTT samples
        int rtt_count = 0; double avg_rtt = 0.0, sum_rtt = 0.0;
        rtt_sample_data_t *rtt_s = curr->rtt_measurements;
        while(rtt_s) { rtt_count++; sum_rtt += rtt_s->rtt_milliseconds; rtt_s = rtt_s->next; }
        if (rtt_count > 0) avg_rtt = sum_rtt / rtt_count;
        printf("  RTT Samples: %d, Avg RTT: %.3f ms\n", rtt_count, avg_rtt);
        
        printf("\n");
        curr = curr->next;
    }
     printf("Total unique flows processed: %d\n", count);
}

void print_top_ports() { // (como no original, mas adaptado para ntohs na impressão)
    int total_port_mentions = 0; // Each time a port appears as src or dst
    port_count_t *temp_pc = port_counts;
    while (temp_pc) {
        total_port_mentions += temp_pc->count;
        temp_pc = temp_pc->next;
    }
    if (total_port_mentions == 0) total_port_mentions = 1; // Avoid division by zero

    printf("\n--- Top 10 Ports (by appearance as src/dst) ---\n");
    // Create a temporary list for sorting or finding top N without modifying original
    port_count_t *sorted_ports = NULL;
    port_count_t *curr_orig = port_counts;
     while(curr_orig){ // Simple copy
        port_count_t *new_node = (port_count_t*)malloc(sizeof(port_count_t));
        memcpy(new_node, curr_orig, sizeof(port_count_t));
        new_node->next = sorted_ports;
        sorted_ports = new_node;
        curr_orig = curr_orig->next;
    }

    for (int i = 0; i < 10; i++) {
        port_count_t *max_node = NULL;
        port_count_t *prev_max_node_parent = NULL;
        port_count_t *curr = sorted_ports;
        port_count_t *parent = NULL;

        while (curr) {
            if (max_node == NULL || curr->count > max_node->count) {
                max_node = curr;
                prev_max_node_parent = parent;
            }
            parent = curr;
            curr = curr->next;
        }

        if (max_node == NULL || max_node->count == 0) break; // No more ports or count is 0

        double perc = (double)max_node->count * 100.0 / total_port_mentions;
        printf("Port %u: %d mentions (%.2f%%)\n", ntohs(max_node->port), max_node->count, perc);

        // Remove max_node from sorted_ports list to find next max
        if (prev_max_node_parent == NULL) sorted_ports = max_node->next; // Max was head
        else prev_max_node_parent->next = max_node->next;
        free(max_node); // Free the copy
    }
    // Free any remaining nodes in sorted_ports if not all were printed
    while(sorted_ports){
        port_count_t* temp = sorted_ports;
        sorted_ports = sorted_ports->next;
        free(temp);
    }
}

void save_all_data_to_csv(connection_data_t *conns) {
    FILE *f_summary = fopen("connection_summary.csv", "w");
    FILE *f_rtt = fopen("rtt_samples.csv", "w");
    FILE *f_cwnd = fopen("cwnd_evolution.csv", "w");
    FILE *f_segments = fopen("segment_sizes.csv", "w");
    // FILE *f_elephant = fopen("elephant_flows.csv", "w"); // Or include in summary

    if (!f_summary || !f_rtt || !f_cwnd || !f_segments) {
        perror("Error opening one or more CSV files for writing");
        if(f_summary) fclose(f_summary);
        if(f_rtt) fclose(f_rtt);
        if(f_cwnd) fclose(f_cwnd);
        if(f_segments) fclose(f_segments);
        return;
    }

    fprintf(f_summary, "SrcIP,SrcPort,DstIP,DstPort,StartTime_s,EndTime_s,Duration_s,TotalBytes,TotalPackets,Retransmissions,HandshakeTime_ms,MSS,IsElephant,AvgThroughput_bps\n");
    fprintf(f_rtt, "SrcIP,SrcPort,DstIP,DstPort,RTT_ms\n");
    fprintf(f_cwnd, "SrcIP,SrcPort,DstIP,DstPort,Timestamp_s,BytesInFlight\n");
    fprintf(f_segments, "SrcIP,SrcPort,DstIP,DstPort,SegmentSize,Count\n");

    const uint64_t ELEPHANT_THRESHOLD_BYTES = 1 * 1024 * 1024; // 1MB, adjust as needed

    connection_data_t *curr = conns;
    while (curr) {
        char src_ip_str[16], dst_ip_str[16];
        sprintf(src_ip_str, "%u.%u.%u.%u", (curr->key.ip_src >> 24) & 0xFF, (curr->key.ip_src >> 16) & 0xFF, (curr->key.ip_src >> 8) & 0xFF, curr->key.ip_src & 0xFF);
        sprintf(dst_ip_str, "%u.%u.%u.%u", (curr->key.ip_dst >> 24) & 0xFF, (curr->key.ip_dst >> 16) & 0xFF, (curr->key.ip_dst >> 8) & 0xFF, curr->key.ip_dst & 0xFF);

        struct timeval duration_tv;
        timeval_diff(&curr->start_time, &curr->end_time, &duration_tv);
        double duration_s = duration_tv.tv_sec + duration_tv.tv_usec / 1000000.0;
        if (duration_s < 0.000001) duration_s = 0.000001; // Avoid division by zero for throughput

        double avg_throughput_bps = (curr->total_bytes * 8) / duration_s;

        double handshake_time_ms = -1.0;
        if (curr->handshake.syn_seen && curr->handshake.synack_seen) {
            struct timeval handshake_tv;
            timeval_diff(&curr->handshake.ts_syn, &curr->handshake.ts_synack, &handshake_tv);
            handshake_time_ms = handshake_tv.tv_sec * 1000.0 + handshake_tv.tv_usec / 1000.0;
        }
        
        curr->is_elephant_flow = (curr->total_bytes > ELEPHANT_THRESHOLD_BYTES) ? 1 : 0;

        fprintf(f_summary, "%s,%u,%s,%u,%.6f,%.6f,%.6f,%lu,%d,%d,%.3f,%d,%d,%.2f\n",
                src_ip_str, ntohs(curr->key.port_src), dst_ip_str, ntohs(curr->key.port_dst),
                curr->start_time.tv_sec + curr->start_time.tv_usec / 1000000.0,
                curr->end_time.tv_sec + curr->end_time.tv_usec / 1000000.0,
                duration_s, curr->total_bytes, curr->packet_count, curr->retransmissions,
                handshake_time_ms, curr->handshake.mss, curr->is_elephant_flow, avg_throughput_bps);

        rtt_sample_data_t *rtt_s = curr->rtt_measurements;
        while (rtt_s) {
            fprintf(f_rtt, "%s,%u,%s,%u,%.3f\n", src_ip_str, ntohs(curr->key.port_src), dst_ip_str, ntohs(curr->key.port_dst), rtt_s->rtt_milliseconds);
            rtt_s = rtt_s->next;
        }

        cwnd_sample_t *cwnd_s = curr->cwnd_evolution_samples;
        while (cwnd_s) {
            double cwnd_ts_s = cwnd_s->timestamp.tv_sec + cwnd_s->timestamp.tv_usec / 1000000.0;
            fprintf(f_cwnd, "%s,%u,%s,%u,%.6f,%u\n", src_ip_str, ntohs(curr->key.port_src), dst_ip_str, ntohs(curr->key.port_dst), cwnd_ts_s, cwnd_s->bytes_in_flight);
            cwnd_s = cwnd_s->next;
        }
        
        segment_size_node_t *ssn = curr->segment_sizes;
        while(ssn){
            fprintf(f_segments, "%s,%u,%s,%u,%d,%d\n", src_ip_str, ntohs(curr->key.port_src), dst_ip_str, ntohs(curr->key.port_dst), ssn->size, ssn->count);
            ssn = ssn->next;
        }

        curr = curr->next;
    }

    fclose(f_summary);
    fclose(f_rtt);
    fclose(f_cwnd);
    fclose(f_segments);
    printf("Data saved to CSV files.\n");
}


void cleanup_connections(connection_data_t *conns) {
    connection_data_t *curr = conns;
    while (curr != NULL) {
        connection_data_t *next_conn = curr->next;

        // Free RTT pending segments
        rtt_pending_segment_t *rtt_p = curr->rtt_pending_segments;
        while (rtt_p != NULL) {
            rtt_pending_segment_t *next_rtt_p = rtt_p->next;
            free(rtt_p);
            rtt_p = next_rtt_p;
        }
        // Free RTT measurements
        rtt_sample_data_t *rtt_m = curr->rtt_measurements;
        while (rtt_m != NULL) {
            rtt_sample_data_t *next_rtt_m = rtt_m->next;
            free(rtt_m);
            rtt_m = next_rtt_m;
        }
        // Free sent sequence list (for retransmissions)
        seq_entry_t *seq_e = curr->sent_seq_list;
        while (seq_e != NULL) {
            seq_entry_t *next_seq_e = seq_e->next;
            free(seq_e);
            seq_e = next_seq_e;
        }
        // Free CWND samples
        cwnd_sample_t *cwnd_s = curr->cwnd_evolution_samples;
        while (cwnd_s != NULL) {
            cwnd_sample_t *next_cwnd_s = cwnd_s->next;
            free(cwnd_s);
            cwnd_s = next_cwnd_s;
        }
        // Free segment sizes
        segment_size_node_t *ssn = curr->segment_sizes;
        while (ssn != NULL) {
            segment_size_node_t *next_ssn = ssn->next;
            free(ssn);
            ssn = next_ssn;
        }
        free(curr);
        curr = next_conn;
    }
    connections = NULL; // Reset global pointer

    // Cleanup port counts
    port_count_t *pc = port_counts;
    while(pc != NULL){
        port_count_t *next_pc = pc->next;
        free(pc);
        pc = next_pc;
    }
    port_counts = NULL;
}


int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Uso: %s <arquivo.pcap>\n", argv[0]);
        return 1;
    }

    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_offline(argv[1], errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Erro ao abrir arquivo pcap: %s\n", errbuf);
        return 2;
    }

    if (pcap_datalink(handle) != DLT_EN10MB) { // Common for Ethernet
        fprintf(stderr, "Tipo de link de dados %d nao suportado (esperado DLT_EN10MB para Ethernet).\nVerifique o tipo com pcap_datalink_val_to_name().\n", pcap_datalink(handle));
        // You might want to support DLT_LINUX_SLL as well for "Linux cooked" captures
        // or others, but for now, sticking to Ethernet.
        pcap_close(handle);
        return 3;
    }

    printf("Analisando pacotes de %s...\n", argv[1]);
    pcap_loop(handle, 0, packet_handler, NULL); // 0 means process all packets
    printf("Analise concluida.\n");

    pcap_close(handle);

    print_connections(); // Optional: Print basic summaries to console
    print_top_ports();   // Optional: Print top ports to console

    save_all_data_to_csv(connections); // Save detailed metrics to CSVs

    cleanup_connections(connections); // Free allocated memory

    return 0;
}
