#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <time.h>
#include <string.h>
#define IP_HL(ip)   (((ip)->ver_ihl) & 0x0f)
#define YES 1
#define NO -1
#define ETHER_ADDR_LEN 6
#define MAC_ADDRSTRLEN 2*6+5+1

static int address_record[1000][9]={0};
static int row=0;

typedef struct __attribute__((__packed__)) EtherHeader {
    const struct ether_addr destAddr[6];
    const struct ether_addr sourceAddr[6];
    uint8_t protocol;
}EtherHeader;

/* UDP header */
struct sniff_udp
{
  uint16_t sport;		/* source port */
  uint16_t dport;		/* destination port */
  uint16_t udp_length;
  uint16_t udp_sum;		/* checksum */
};
 
/* TCP header */
typedef u_int tcp_seq;
struct sniff_tcp
{
  u_short th_sport;		/* source port */
  u_short th_dport;		/* destination port */
  tcp_seq th_seq;		/* sequence number */
  tcp_seq th_ack;		/* acknowledgement number */
  u_char th_offx2;		/* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
  u_char th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
  u_short th_win;		/* window */
  u_short th_sum;		/* checksum */
  u_short th_urp;		/* urgent pointer */
};
 
int cnt=0;
typedef struct ip_address
{
 u_char byte1;
 u_char byte2;
 u_char byte3;
 u_char byte4;
}ip_address;

typedef struct ip_header
{
 u_char ver_ihl;  /* Version (4 bits) + Internet header length (4 bits)*/
 u_char tos;      /* Type of service */
 u_short tlen;    /* Total length */
 u_short identification; /* Identification */
 u_short flags_fo;       /* Flags (3 bits) + Fragment offset (13 bits)*/
 u_char ttl;      /* Time to live */
 u_char proto;    /* Protocol */
 u_short crc;     /* Header checksum */
 ip_address saddr;/* Source address */
 ip_address daddr;/* Destination address */
 u_int op_pad;    /* Option + Padding */
}ip_header;

int Check_If_Exists(struct ip_header *ih){
    for(int i=0; i<row; i++){
        if(ih->saddr.byte1==address_record[i][0] && ih->saddr.byte2==address_record[i][1]
                && ih->saddr.byte3==address_record[i][2] && ih->saddr.byte4==address_record[i][3]
                && ih->daddr.byte1==address_record[i][4] && ih->daddr.byte2==address_record[i][5]
                && ih->daddr.byte3==address_record[i][6] && ih->daddr.byte4==address_record[i][7]){
            address_record[i][8]++;
            return YES;
        }
    }
    address_record[row][0] = ih->saddr.byte1;
    address_record[row][1] = ih->saddr.byte2;
    address_record[row][2] = ih->saddr.byte3;
    address_record[row][3] = ih->saddr.byte4;
    address_record[row][4] = ih->daddr.byte1;
    address_record[row][5] = ih->daddr.byte2;
    address_record[row][6] = ih->daddr.byte3;
    address_record[row][7] = ih->daddr.byte4;
    address_record[row][8] = 1;
    return NO;
}

/* Finds the payload of a TCP/IP packet */
void my_packet_handler(
    u_char *args,
    const struct pcap_pkthdr *header,
    const u_char *packet
)
{
    int col=0;
    //  time stamp
    printf("Time = %s",ctime((const time_t*)&header->ts.tv_sec));

    //  Mac
    const struct EtherHeader *eth;
    eth = (EtherHeader *)packet;
    printf("Src MAC: %s\n", ether_ntoa(eth->sourceAddr));
    printf("Dst MAC: %s\n", ether_ntoa(eth->destAddr));


    //  檢查是否ip封包。
    struct ip_header *ih;
    struct ether_header *eth_header;
    int ethernet_header_length = 14; /* Doesn't change */
    ih = packet + ethernet_header_length;
    eth_header = (struct ether_header *) packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        printf("Not an IP packet...\n");
        cnt--;
        /* return; */
    }
    else{

        if(Check_If_Exists(ih) == NO){
            //  代表剛剛insert了一組，要把row++
            row++;
        }
        /* print ip addresse*/
        printf("Ip Address %d.%d.%d.%d -> %d.%d.%d.%d\n",
        //  Destination address
        ih->saddr.byte1,
        ih->saddr.byte2,
        ih->saddr.byte3,
        ih->saddr.byte4,
        //  Source address
        ih->daddr.byte1,
        ih->daddr.byte2,
        ih->daddr.byte3,
        ih->daddr.byte4
        );
    }

    /* The total packet length, including all headers
       and the data payload is stored in
       header->len and header->caplen. Caplen is
       the amount actually available, and len is the
       total packet length even if it is larger
       than what we currently have captured. If the snapshot
       length set with pcap_open_live() is too small, you may
       not have the whole packet. */

    /* printf("Total packet available: %d bytes\n", header->caplen); */
    /* printf("Expected packet size: %d bytes\n", header->len); */

    /* Pointers to start point of various headers */
    const u_char *ip_hdr;
    const u_char *tcp_header;
    const u_char *payload;

    /* Header lengths in bytes */
    int ip_header_length;
    int tcp_header_length;
    int payload_length;

    /* Find start of IP header */
    ip_hdr = packet + ethernet_header_length;
    //  Ip header的長度。
    ip_header_length = ((*ip_hdr) & 0x0F);
    ip_header_length = ip_header_length * 4;

    /* The second-half of the first byte in ip_header
       contains the IP header length (IHL). */
    /* The IHL is number of 32-bit segments. Multiply
       by four to get a byte count for pointer arithmetic */
    /* printf("IP header length (IHL) in bytes: %d\n", ip_header_length); */

    /* Now that we know where the IP header is, we can 
       inspect the IP header for a protocol number to 
       make sure it is TCP before going any further. 
       Protocol is always the 10th byte of the IP header */
    u_char protocol = *(ip_hdr + 9);
    if (protocol == IPPROTO_UDP) {
        const struct sniff_udp *udp;
        udp = (struct sniff_udp *)(packet+ethernet_header_length+ip_header_length);
        printf("This is an UDP packet\n");
        printf("Src Port = %d\n", ntohs(udp->sport));
        printf("Dst Port = %d\n", ntohs(udp->dport));
        /* return; */
    }
    else if(protocol == IPPROTO_TCP){
        const struct sniff_tcp *tcp;
        tcp = (struct sniff_tcp *)(packet+ethernet_header_length+ip_header_length);
        printf("This is an TCP packet\n");
        printf("Src Port = %d\n", ntohs(tcp->th_sport));
        printf("Dst Port = %d\n", ntohs(tcp->th_dport));
    }
    else{
        printf("Not TCP or UDP Protocol\n");
    }

    /* Add the ethernet and ip header length to the start of the packet
       to find the beginning of the TCP header */
    tcp_header = packet + ethernet_header_length + ip_header_length;
    /* TCP header length is stored in the first half 
       of the 12th byte in the TCP header. Because we only want
       the value of the top half of the byte, we have to shift it
       down to the bottom half otherwise it is using the most 
       significant bits instead of the least significant bits */
    tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;
    /* The TCP header length stored in those 4 bits represents
       how many 32-bit words there are in the header, just like
       the IP header length. We multiply by four again to get a
       byte count. */

    /* tcp_header_length = tcp_header_length * 4; */
    /* printf("TCP header length in bytes: %d\n", tcp_header_length); */

    /* Add up all the header sizes to find the payload offset */

    /* int total_headers_size = ethernet_header_length+ip_header_length+tcp_header_length; */
    /* printf("Size of all headers combined: %d bytes\n", total_headers_size); */
    /* payload_length = header->caplen - */
    /*     (ethernet_header_length + ip_header_length + tcp_header_length); */
    /* printf("Payload size: %d bytes\n", payload_length); */
    /* payload = packet + total_headers_size; */
    /* printf("Memory address where payload begins: %p\n\n", payload); */

    /* Print payload in ASCII */

    /*  
    if (payload_length > 0) {
        const u_char *temp_pointer = payload;
        int byte_count = 0;
        while (byte_count++ < payload_length) {
            printf("%c", *temp_pointer);
            temp_pointer++;
        }
        printf("\n");
    }
    */

    /* printf("row = %d\n", row); */
    printf("\n");
    cnt++;
    return;
}

int main(int argc, char **argv) {    
    char *device;
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle, *fp;
    /* Snapshot length is how many bytes to capture from each packet. This includes*/
    int snapshot_length = 1024;
    /* End the loop after this many packets are captured */
    int total_packet_count = 500;
    u_char *my_arguments = NULL;
    struct bpf_program filter;
    char filter_exp[] = "port 80";
    bpf_u_int32 subnet_mask, ip;
    if(argc != 3){
        printf("Please add path to pcap file\n");
        return 0;
    }
    printf("%s\n", argv[2]);


    /* handle = pcap_open_live(device, snapshot_length, 0, 10000, error_buffer); */
    fp = pcap_open_offline(argv[2], error_buffer);
    /* fp = pcap_open_offline("pcap_file/ipv6_tcp_ip_cap", error_buffer); */

    pcap_loop(fp, total_packet_count, my_packet_handler, my_arguments);
    /* pcap_loop(handle, 100, my_packet_handler, my_arguments); */

    printf("Total packets = %d\n", cnt);
    for(int i=0; i<row; i++){
        printf("%d %d %d %d -> %d %d %d %d\tCount = %d\n", address_record[i][0]
                , address_record[i][1], address_record[i][2], address_record[i][3]
                , address_record[i][4], address_record[i][5], address_record[i][6]
                , address_record[i][7], address_record[i][8]);
    }
    return 0;

}
