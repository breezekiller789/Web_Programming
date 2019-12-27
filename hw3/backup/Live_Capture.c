#include <stdio.h>
#include <time.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header);

int main(int argc, char *argv[]) {
    char *device;
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    pcap_t *fp;
    const u_char *packet;
    struct pcap_pkthdr packet_header;
    struct pcap_addr packet_addr;
    int packet_count_limit = 1;
    int timeout_limit = 10000; /* In milliseconds */

    fp = pcap_open_offline("icmp fragmented.cap", error_buffer);
    /* packet = pcap_next(fp, &packet_header); */
    packet = pcap_next(fp, &packet_addr);
    if (packet == NULL) {
        printf("No packet found.\n");
        return 2;
    }

    print_packet_info(packet, packet_header);

    return 0;
}

/* void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header) { */
void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header) {
    printf("Time Stamp = %d\n", packet_header.ts.tv_usec);
    printf("Packet capture length: %d\n", packet_header.caplen);
    printf("Packet total length %d\n", packet_header.len);
}
