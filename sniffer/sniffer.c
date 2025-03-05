#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <inttypes.h>

#define TCP 6
#define UDP 17
#define LOG_FILE_PATH "log.txt"

FILE* log_file;
unsigned int total, tcp, udp, other;
unsigned short iphdrlen;
uint8_t l4proto;

void payload(unsigned char* buffer, size_t buflen) {
    size_t summary_headers_length = iphdrlen + sizeof(struct ethhdr);

    switch (l4proto) {
        case TCP:
            summary_headers_length += sizeof(struct tcphdr);
            break;
        case UDP:
            summary_headers_length += sizeof(struct udphdr);
            break;
    }

    unsigned char* data = (buffer + summary_headers_length);
    size_t remaining_data = buflen - summary_headers_length;

    fprintf(log_file, "\nData:\n");
    for (size_t i = 0; i < remaining_data; i++) {
        if (i % 16 == 0) fprintf(log_file, "\n");
        fprintf(log_file, "%.2X ", data[i]);
    }
    fprintf(log_file, "\n\nPAYLOAD SIZE: %zu\n", remaining_data);
}

void ip_header(unsigned char* buffer, size_t buflen) {
    struct sockaddr_in source;
    struct sockaddr_in dest;

    struct iphdr* ip = (struct iphdr*)(buffer + sizeof(struct ethhdr));

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = ip->saddr;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = ip->daddr;

    fprintf(log_file, "\nIP Header\n");
    fprintf(log_file, "\t|-Version\t\t\t\t: %d\n", (unsigned int)ip->version);
    fprintf(log_file, "\t|-Internet Header Length: %d DWORDS or %d Bytes\n", (unsigned int)ip->ihl, ((unsigned int)(ip->ihl)) * 4);
    fprintf(log_file, "\t|-Type Of Service\t\t: %" PRIu8 "\n", ntohs(ip->tos));
    fprintf(log_file, "\t|-Total Length\t\t\t: %" PRIu16 "\n", ntohs(ip->tot_len));
    fprintf(log_file, "\t|-Identification\t\t: %" PRIu16 " Bytes\n", ntohs(ip->id));

    fprintf(log_file, "\t|----------Flags----------\n");
    fprintf(log_file, "\t\t|-(DF) Don't Fragment\t: %" PRIu16 "\n", htons(ip->frag_off) >> 14);
    fprintf(log_file, "\t\t|-(MF) More Fragments\t: %" PRIu16 "\n", htons(ip->frag_off) >> 13 & 0x01);

    fprintf(log_file, "\t|-Time To Live\t\t\t: %" PRIu8 "\n", ip->ttl);
    fprintf(log_file, "\t|-Protocol\t\t\t\t: %" PRIu8 "\n", ip->protocol);
    fprintf(log_file, "\t|-Header Checksum\t\t: %" PRIu8 " (0x%" PRIx8 ")\n", ntohs(ip->check), ntohs(ip->check));
    fprintf(log_file, "\t|-Source IP\t\t\t\t: %s\n", inet_ntoa(source.sin_addr));
    fprintf(log_file, "\t|-Destination IP\t\t: %s\n", inet_ntoa(dest.sin_addr));

    fprintf(log_file, "\nIP HEADER SIZE: %zu\nIP STRUCT SIZE: %zu\n", sizeof(*ip), sizeof(struct iphdr));

    iphdrlen = ip->ihl * 4;
    l4proto = ip->protocol;
}

void ethernet_header(unsigned char* buffer, size_t buflen) {
    struct ethhdr* eth = (struct ethhdr*)(buffer);
    fprintf(log_file, "\nEthernet Header\n");
    fprintf(log_file, "\t|-Source Address\t\t: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",
           eth->h_source[0],
           eth->h_source[1],
           eth->h_source[2],
           eth->h_source[3],
           eth->h_source[4],
           eth->h_source[5]
    );
    fprintf(log_file, "\t|-Destination Address\t: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",
           eth->h_dest[0],
           eth->h_dest[1],
           eth->h_dest[2],
           eth->h_dest[3],
           eth->h_dest[4],
           eth->h_dest[5]
    );
    fprintf(log_file, "\t|-Protocol\t\t\t\t: %d\n", eth->h_proto);
    
    fprintf(log_file, "\nETH HEADER SIZE: %zu\nETH STRUCT SIZE: %zu\n", sizeof(*eth), sizeof(struct ethhdr));
}

void tcp_header(unsigned char* buffer, size_t buflen) {
    fprintf(log_file, "\n*************************TCP Packet******************************");

    ethernet_header(buffer, buflen);
    ip_header(buffer, buflen);

    struct tcphdr* tcp = (struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));

    fprintf(log_file, "\nTCP Header\n");
    fprintf(log_file, "\t|-Source Port\t\t\t: %" PRIu16 "\n", ntohs(tcp->source));
    fprintf(log_file, "\t|-Destination Port\t\t: %" PRIu16 "\n", ntohs(tcp->dest));
    fprintf(log_file, "\t|-Sequence number\t\t: %" PRIu32 "\n", ntohl(tcp->seq));
    fprintf(log_file, "\t|-Acknowledgment Number\t: %" PRIu32 "\n", ntohl(tcp->ack_seq));
    fprintf(log_file, "\t|-Header Length\t\t\t: %" PRIu16 " DWORDS or %" PRIu16 " bytes\n", tcp->doff, tcp->doff * 4);

    fprintf(log_file, "\t|----------Flags----------\n");
    fprintf(log_file, "\t\t|-Urgent Flag\t\t\t: %" PRIu16 "\n", tcp->urg);
    fprintf(log_file, "\t\t|-Acknowledgement Flag\t: %" PRIu16 "\n", tcp->ack);
    fprintf(log_file, "\t\t|-Push Flag\t\t\t\t: %" PRIu16 "\n", tcp->psh);
    fprintf(log_file, "\t\t|-Reset Flag\t\t\t: %" PRIu16 "\n", tcp->rst);
    fprintf(log_file, "\t\t|-Synchronise Flag\t\t: %" PRIu16 "\n", tcp->syn);
    fprintf(log_file, "\t\t|-Finish Flag\t\t\t: %" PRIu16 "\n", tcp->fin);

    fprintf(log_file, "\t|-Window size\t\t\t: %" PRIu16 "\n", ntohs(tcp->window));
    fprintf(log_file, "\t|-Checksum\t\t\t\t: %" PRIu16 " (0x%" PRIx16 ")\n", ntohs(tcp->check), ntohs(tcp->check));
    fprintf(log_file, "\t|-Urgent Pointer\t\t: %" PRIu16 "\n", tcp->urg_ptr);

    payload(buffer, buflen);
    fprintf(log_file, "\nTCP HEADER SIZE: %zu\nTCP STRUCT SIZE: %zu\n", sizeof(*tcp), sizeof(struct tcphdr));
    fprintf(log_file, "*****************************************************************\n");
    fprintf(log_file, "\nBUFLEN: %zu\n", buflen);
}

void udp_header(unsigned char* buffer, size_t buflen) {
    fprintf(log_file, "\n*************************UDP Packet******************************");

    ethernet_header(buffer, buflen);
    ip_header(buffer, buflen);

    struct udphdr* udp = (struct udphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));

    fprintf(log_file, "\nUDP Header\n");
    fprintf(log_file, "\t|-Source Port\t\t\t: %" PRIu8 "\n", ntohs(udp->source));
    fprintf(log_file, "\t|-Destination Port\t\t: %" PRIu8 "\n", ntohs(udp->dest));
    fprintf(log_file, "\t|-UDP Length\t\t\t: %" PRIu8 "\n", ntohs(udp->len));
    fprintf(log_file, "\t|-UDP Checksum\t\t\t: %" PRIu8 "\n", ntohs(udp->check));

    payload(buffer, buflen);
    fprintf(log_file, "\nUDP HEADER SIZE: %zu\nUDP STRUCT SIZE: %zu\n", sizeof(*udp), sizeof(struct udphdr));
	fprintf(log_file, "*****************************************************************\n");
    fprintf(log_file, "\nBUFLEN: %zu\n", buflen);
}

void process_data(unsigned char* buffer, size_t buflen) {
    struct iphdr* ip = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    ++total;
    switch (ip->protocol) {
        case TCP:
            ++tcp;
            tcp_header(buffer, buflen);
            break;
            
        case UDP:
            ++udp;
            udp_header(buffer, buflen);
            break;

        default:
            ++other;
    }
    printf("TCP: %d  UDP: %d  Other: %d  Total: %d\r", tcp, udp, other, total);
}

/* 
 * This program must be run from root, as it requires a raw socket
*/
int main() {
    int sock_raw;
    sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    /* 
     * AF_PACKET socket allows user-space application to capture raw packets 
     * at link layer (OSI L2) so that it can see the whole packet data starting
     * from link layer headers and bottom up to transport layer and application payload
     * Orig: https://csulrong.github.io/blogs/2022/03/10/linux-afpacket/ 
    */
    
    if (sock_raw < 0) {
        printf("error in socket\n");
        return -1;
    }
    printf("socket was opened successfully\n");

    unsigned char* buffer = (unsigned char*) malloc(65536);
    memset(buffer, 0, 65536);

    log_file = fopen(LOG_FILE_PATH, "w");
    if (!log_file) {
        printf("unable to open %s\n", LOG_FILE_PATH);
        return -1;
    }
    printf("file %s was opened successfully\n", LOG_FILE_PATH);

    struct sockaddr saddr;
    socklen_t saddr_len = sizeof(saddr);

    printf("starting sniffing...\n");

    while (1) {
        /* receive a network packet and copy it into buffer */
        size_t buflen = recvfrom(sock_raw, buffer, 65536, 0, &saddr, &saddr_len);
        
        fflush(log_file);
        process_data(buffer, buflen);
    }

    close(sock_raw);
    printf("finished sniffing\n");
}
