#include <pcap.h>
#include <stdio.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <string.h>

// FAZER
// RTT estimado	
// Throughput médio por conexão	
// Evolução da janela congestion.	
// Fluxos elefantes e microbursts	

#pragma comment(lib, "ws2_32.lib")

#define ETHERNET_HEADER_SIZE 14

#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20

typedef struct ip_header {
    unsigned char  ihl:4;       
    unsigned char  version:4;   
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
    unsigned char  reserved:4;
    unsigned char  doff:4;     
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

typedef struct seq_entry {
    uint32_t seq;
    struct timeval ts;
    struct seq_entry *next;
} seq_entry_t;

typedef struct segment_size_node {
    int size;
    int count;
    struct segment_size_node *next;
} segment_size_node_t;

typedef struct port_count {
    uint16_t port;
    int count;
    struct port_count *next;
} port_count_t;

typedef struct connection_data {
    tcp_connection_key_t key;

    struct timeval start_time;
    struct timeval end_time;

    uint64_t total_bytes;
    int packet_count;

    handshake_data_t handshake;

    seq_entry_t *seq_list;
    int retransmissions;

    segment_size_node_t *segment_sizes;

    struct connection_data *next;
} connection_data_t;

connection_data_t *connections = NULL;
port_count_t *port_counts = NULL;

int connection_key_equal(tcp_connection_key_t *a, tcp_connection_key_t *b) {
    return (a->ip_src == b->ip_src && a->ip_dst == b->ip_dst &&
            a->port_src == b->port_src && a->port_dst == b->port_dst);
}

void timeval_diff(struct timeval *start, struct timeval *end, struct timeval *result) {
    result->tv_sec = end->tv_sec - start->tv_sec;
    result->tv_usec = end->tv_usec - start->tv_usec;
    if (result->tv_usec < 0) {
        result->tv_sec--;
        result->tv_usec += 1000000;
    }
}

int parse_mss_option(const u_char *tcp_header, int tcp_header_len) {
    int offset = 20; 
    while (offset < tcp_header_len) {
        uint8_t kind = tcp_header[offset];
        if (kind == 0) break; // fim das opções
        if (kind == 1) { offset++; continue; } // NOP
        if (offset + 1 >= tcp_header_len) break;

        uint8_t length = tcp_header[offset + 1];
        if (length < 2 || offset + length > tcp_header_len) break;

        if (kind == 2 && length == 4) { // MSS
            uint16_t mss = (tcp_header[offset + 2] << 8) | tcp_header[offset + 3];
            return mss;
        }
        offset += length;
    }
    return -1;
}

connection_data_t *find_connection(tcp_connection_key_t *key) {
    connection_data_t *curr = connections;
    while (curr) {
        if (connection_key_equal(&curr->key, key)) return curr;
        curr = curr->next;
    }
    return NULL;
}

connection_data_t *find_or_create_connection(tcp_connection_key_t *key, struct timeval ts, uint32_t payload_len) {
    connection_data_t *conn = find_connection(key);
    if (conn) {
        if (timercmp(&ts, &conn->end_time, >)) conn->end_time = ts;
        if (timercmp(&ts, &conn->start_time, <)) conn->start_time = ts;
        conn->total_bytes += payload_len;
        conn->packet_count++;
        return conn;
    }

    conn = malloc(sizeof(connection_data_t));
    conn->key = *key;
    conn->start_time = ts;
    conn->end_time = ts;
    conn->total_bytes = payload_len;
    conn->packet_count = 1;
    conn->handshake.syn_seen = 0;
    conn->handshake.synack_seen = 0;
    conn->handshake.mss = -1;
    conn->seq_list = NULL;
    conn->retransmissions = 0;
    conn->segment_sizes = NULL;
    conn->next = connections;
    connections = conn;
    return conn;
}

int is_retransmission(connection_data_t *conn, uint32_t seq, struct timeval ts) {
    seq_entry_t *curr = conn->seq_list;
    while (curr) {
        if (curr->seq == seq) return 1;
        curr = curr->next;
    }
    seq_entry_t *new_entry = malloc(sizeof(seq_entry_t));
    new_entry->seq = seq;
    new_entry->ts = ts;
    new_entry->next = conn->seq_list;
    conn->seq_list = new_entry;
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
    segment_size_node_t *new_node = malloc(sizeof(segment_size_node_t));
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
    port_count_t *new_node = malloc(sizeof(port_count_t));
    new_node->port = port;
    new_node->count = 1;
    new_node->next = port_counts;
    port_counts = new_node;
}

void update_handshake(connection_data_t *conn, const tcp_header_t *tcp, struct timeval ts) {
    int syn = (tcp->flags & TH_SYN) != 0;
    int ack = (tcp->flags & TH_ACK) != 0;

    if (syn && !ack && !conn->handshake.syn_seen) {
        conn->handshake.syn_seen = 1;
        conn->handshake.ts_syn = ts;

        int tcp_header_len = tcp->doff * 4;
        const u_char *tcp_ptr = (const u_char *)tcp;
        int mss = parse_mss_option(tcp_ptr, tcp_header_len);
        if (mss > 0) conn->handshake.mss = mss;

    } else if (syn && ack && conn->handshake.syn_seen && !conn->handshake.synack_seen) {
        conn->handshake.synack_seen = 1;
        conn->handshake.ts_synack = ts;
    }
}

void print_connections() {
    connection_data_t *curr = connections;
    while (curr) {
        printf("Conexão: %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u\n",
            (curr->key.ip_src >> 24) & 0xFF, (curr->key.ip_src >> 16) & 0xFF,
            (curr->key.ip_src >> 8) & 0xFF, curr->key.ip_src & 0xFF,
            ntohs(curr->key.port_src),
            (curr->key.ip_dst >> 24) & 0xFF, (curr->key.ip_dst >> 16) & 0xFF,
            (curr->key.ip_dst >> 8) & 0xFF, curr->key.ip_dst & 0xFF,
            ntohs(curr->key.port_dst));

        struct timeval duration;
        timeval_diff(&curr->start_time, &curr->end_time, &duration);
        printf("Duração: %ld.%06lds\n", duration.tv_sec, duration.tv_usec);
        printf("Pacotes: %d, Bytes: %llu\n", curr->packet_count, curr->total_bytes);

        if (curr->handshake.syn_seen && curr->handshake.synack_seen) {
            struct timeval handshake_time;
            timeval_diff(&curr->handshake.ts_syn, &curr->handshake.ts_synack, &handshake_time);
            printf("Handshake SYN->SYN/ACK: %ld.%06lds\n", handshake_time.tv_sec, handshake_time.tv_usec);
            if (curr->handshake.mss > 0)
                printf("MSS: %d\n", curr->handshake.mss);
        }

        printf("Retransmissões: %d\n", curr->retransmissions);

        printf("Tamanhos dos segmentos:\n");
        segment_size_node_t *ssn = curr->segment_sizes;
        while (ssn) {
            printf("  %d bytes: %d vezes\n", ssn->size, ssn->count);
            ssn = ssn->next;
        }

        printf("\n");
        curr = curr->next;
    }
}

void print_top_ports() {
    int total_connections = 0;
    port_count_t *curr = port_counts;
    while (curr) {
        total_connections += curr->count;
        curr = curr->next;
    }

    printf("Top 10 portas TCP mais usadas:\n");

    for (int i = 0; i < 10; i++) {
        port_count_t *max_node = NULL;
        curr = port_counts;
        while (curr) {
            if (max_node == NULL || curr->count > max_node->count) max_node = curr;
            curr = curr->next;
        }
        if (max_node == NULL) break;

        double perc = (double)max_node->count * 100.0 / total_connections;
        printf("Porta %u: %d conexões (%.2f%%)\n", ntohs(max_node->port), max_node->count, perc);

        max_node->count = 0;
    }
}

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
    (void)(param);

    if (header->caplen < ETHERNET_HEADER_SIZE + sizeof(ip_header_t)) return;

    const u_char *ip_packet = pkt_data + ETHERNET_HEADER_SIZE;
    ip_header_t *ip = (ip_header_t *)ip_packet;

    if (ip->protocol != IPPROTO_TCP) return;

    int ip_header_len = ip->ihl * 4;
    if (header->caplen < ETHERNET_HEADER_SIZE + ip_header_len + sizeof(tcp_header_t)) return;

    tcp_header_t *tcp = (tcp_header_t *)(ip_packet + ip_header_len);

    uint16_t src_port = tcp->source;
    uint16_t dst_port = tcp->dest;

    tcp_connection_key_t key;
    key.ip_src = ip->saddr;
    key.ip_dst = ip->daddr;
    key.port_src = src_port;
    key.port_dst = dst_port;

    int tcp_header_len = tcp->doff * 4;
    int ip_total_len = ntohs(ip->tot_len);
    int payload_len = ip_total_len - ip_header_len - tcp_header_len;

    connection_data_t *conn = find_or_create_connection(&key, header->ts, payload_len);

    update_handshake(conn, tcp, header->ts);

    if (is_retransmission(conn, ntohl(tcp->seq), header->ts)) {
        conn->retransmissions++;
    }

    int segment_size = payload_len + tcp_header_len;
    add_segment_size(conn, segment_size);

    add_port_count(src_port);
    add_port_count(dst_port);
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

    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Tipo de link não suportado, esperado Ethernet.\n");
        pcap_close(handle);
        return 3;
    }

    pcap_loop(handle, 0, packet_handler, NULL);

    pcap_close(handle);

    print_connections();
    print_top_ports();

    return 0;
}
