#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

#define MAX_PACKETS 5000

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Uso: %s arquivo_entrada.pcap arquivo_saida.pcap\n", argv[0]);
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t *handle = pcap_open_offline(argv[1], errbuf);
    if (!handle) {
        fprintf(stderr, "Erro ao abrir arquivo de entrada: %s\n", errbuf);
        return 2;
    }

    pcap_dumper_t *dumper = NULL;
    dumper = pcap_dump_open(handle, argv[2]);
    if (!dumper) {
        fprintf(stderr, "Erro ao criar arquivo de saída: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return 3;
    }

    struct pcap_pkthdr *header;
    const u_char *packet;
    int res;
    int count = 0;

    while ((res = pcap_next_ex(handle, &header, &packet)) >= 0) {
        pcap_dump((u_char*)dumper, header, packet);
        count++;
        if (count >= MAX_PACKETS) break;
    }

    printf("Arquivo %s criado com %d pacotes.\n", argv[2], count);

    pcap_dump_close(dumper);
    pcap_close(handle);

    return 0;
}
