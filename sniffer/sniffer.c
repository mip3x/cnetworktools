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
    printf("\t|-Source Address: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",
           eth->h_source[0],
           eth->h_source[1],
           eth->h_source[2],
           eth->h_source[3],
           eth->h_source[4],
           eth->h_source[5]
    );
    printf("\t|-Destination Address: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",
           eth->h_dest[0],
           eth->h_dest[1],
           eth->h_dest[2],
           eth->h_dest[3],
           eth->h_dest[4],
           eth->h_dest[5]
    );
    printf("\t|-Protocol: %04X \n", (__be16)eth->h_proto);
    
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
    printf("\t|-Version: %d\n", (unsigned int)ip->version);
    printf("\t|-Internet Header Length: %d DWORDS or %d Bytes\n", (unsigned int)ip->ihl, ((unsigned int)(ip->ihl)) * 4);
    printf("\t|-Type Of Service: %d\n", (unsigned int)ip->tos);
    printf("\t|-Total Length: %d\n", (unsigned int)ip->tot_len);
    printf("\t|-Identification: %d Bytes\n", ntohs(ip->id));
    printf("\t|-Time To Live: %d\n", (unsigned int)ip->ttl);
    printf("\t|-Protocol: %d\n", (unsigned int)ip->protocol);
    printf("\t|-Header Checksum: %d\n", ntohs(ip->check));
    printf("\t|-Source IP: %s\n", inet_ntoa(source.sin_addr));
    printf("\t|-Destination IP: %s\n", inet_ntoa(dest.sin_addr));

    printf("\nIP PACKET SIZE: %zu\nIP STRUCT SIZE: %zu\n", sizeof(*ip), sizeof(struct iphdr));

    iphdrlen = ip->ihl * 4;
    struct udphdr* udp = (struct udphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));

    printf("\nUDP Header\n");
    printf("\t|-Source Port: %d\n", ntohs(udp->source));
    printf("\t|-Destination Port: %d\n", ntohs(udp->dest));
    printf("\t|-UDP Length: %d\n", ntohs(udp->len));
    printf("\t|-UDP Checksum: %d\n", ntohs(udp->check));

    printf("\nUDP PACKET SIZE: %zu\nUDP STRUCT SIZE: %zu\n", sizeof(*udp), sizeof(struct udphdr));
}
