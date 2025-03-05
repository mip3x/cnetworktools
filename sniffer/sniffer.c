#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <stdio.h>

#define TCP 6
#define UDP 17

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
    struct sockaddr saddr;
    socklen_t saddr_len = sizeof(saddr);

    /* receive a network packet and copy it into buffer */
    size_t buflen = recvfrom(sock_raw, buffer, 65536, 0, &saddr, &saddr_len);
    printf("\nBUFLEN: %zu\n", buflen);

    struct ethhdr* eth = (struct ethhdr*)(buffer);
    printf("\nEthernet Header\n");
    printf("\t|-Source Address\t: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",
           eth->h_source[0],
           eth->h_source[1],
           eth->h_source[2],
           eth->h_source[3],
           eth->h_source[4],
           eth->h_source[5]
    );
    printf("\t|-Destination Address\t: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",
           eth->h_dest[0],
           eth->h_dest[1],
           eth->h_dest[2],
           eth->h_dest[3],
           eth->h_dest[4],
           eth->h_dest[5]
    );
    printf("\t|-Protocol\t\t: %04X \n", (__be16)eth->h_proto);
    
    printf("\nETH PACKET SIZE: %zu\nETH STRUCT SIZE: %zu\n", sizeof(*eth), sizeof(struct ethhdr));

    struct sockaddr_in source;
    struct sockaddr_in dest;

    unsigned short iphdrlen;
    struct iphdr* ip = (struct iphdr*)(buffer + sizeof(struct ethhdr));

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = ip->saddr;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = ip->daddr;

    printf("\nIP Header\n");
    printf("\t|-Version\t\t: %d\n", (unsigned int)ip->version);
    printf("\t|-Internet Header Length: %d DWORDS or %d Bytes\n", (unsigned int)ip->ihl, ((unsigned int)(ip->ihl)) * 4);
    printf("\t|-Type Of Service\t: %d\n", (unsigned int)ip->tos);
    printf("\t|-Total Length\t\t: %d\n", (unsigned int)ip->tot_len);
    printf("\t|-Identification\t: %d Bytes\n", ntohs(ip->id));
    printf("\t|-Time To Live\t\t: %d\n", (unsigned int)ip->ttl);
    printf("\t|-Protocol\t\t: %d\n", (unsigned int)ip->protocol);
    printf("\t|-Header Checksum\t: %d\n", ntohs(ip->check));
    printf("\t|-Source IP\t\t: %s\n", inet_ntoa(source.sin_addr));
    printf("\t|-Destination IP\t: %s\n", inet_ntoa(dest.sin_addr));

    printf("\nIP PACKET SIZE: %zu\nIP STRUCT SIZE: %zu\n", sizeof(*ip), sizeof(struct iphdr));

    iphdrlen = ip->ihl * 4;
    unsigned int l4proto = (unsigned int)ip->protocol;

    if (l4proto == UDP) {
        struct udphdr* udp = (struct udphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));

        printf("\nUDP Header\n");
        printf("\t|-Source Port\t\t: %d\n", ntohs(udp->source));
        printf("\t|-Destination Port\t: %d\n", ntohs(udp->dest));
        printf("\t|-UDP Length\t\t: %d\n", ntohs(udp->len));
        printf("\t|-UDP Checksum\t\t: %d\n", ntohs(udp->check));

        printf("\nUDP PACKET SIZE: %zu\nUDP STRUCT SIZE: %zu\n", sizeof(*udp), sizeof(struct udphdr));
    }
    else if (l4proto == TCP) {
        struct tcphdr* tcp = (struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));

        printf("\nTCP Header\n");
        printf("\t|-Source Port\t\t: %d\n", ntohs(tcp->source));
        printf("\t|-Destination Port\t: %d \n", ntohs(tcp->dest));
        printf("\t|-Sequence number\t: %d\n", ntohl(tcp->seq));
        printf("\t|-Acknowledgment Number\t: %d\n", ntohl(tcp->ack_seq));
        printf("\t|-Header Length\t\t: %d DWORDS or %d bytes\n", (unsigned int)tcp->doff, (unsigned int)tcp->doff * 4);
        printf("\t|----------Flags----------\n");
        printf("\t\t|-Urgent Flag\t\t: %d\n", (unsigned int)tcp->urg);
        printf("\t\t|-Acknowledgement Flag\t: %d\n", (unsigned int)tcp->ack);
        printf("\t\t|-Push Flag\t\t: %d\n", (unsigned int)tcp->psh);
        printf("\t\t|-Reset Flag\t\t: %d\n", (unsigned int)tcp->rst);
        printf("\t\t|-Synchronise Flag\t: %d\n", (unsigned int)tcp->syn);
        printf("\t\t|-Finish Flag\t\t: %d\n", (unsigned int)tcp->fin);
        printf("\t|-Window size\t\t: %d\n", ntohs(tcp->window));
        printf("\t|-Checksum\t\t: %d\n", ntohs(tcp->check));
        printf("\t|-Urgent Pointer\t: %d\n", tcp->urg_ptr);

        printf("\nTCP PACKET SIZE: %zu\nTCP STRUCT SIZE: %zu\n", sizeof(*tcp), sizeof(struct tcphdr));
    }

    size_t summary_headers_length = iphdrlen + sizeof(struct ethhdr) + sizeof(struct udphdr);
    unsigned char* data = (buffer + summary_headers_length);
    int remaining_data = buflen - summary_headers_length;

    for (int i = 0; i < remaining_data; i++) {
        if (i % 16 == 0) printf("\n");
        printf("%.2X ", data[i]);
    }
    printf("\n");

    printf("\nREMAIN DATA SIZE: %d\n", remaining_data);
}
