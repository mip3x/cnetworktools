#include <string.h>

#include "protocols.h"

#define IP_FRAGMENT_OFFSET_MASK 0x1fff
#define IP_MF_MASK 0x01

void process_ip_header(struct state state) {
    struct sockaddr_in source;
    struct sockaddr_in dest;

    struct iphdr* ip = (struct iphdr*)(state.buffer + sizeof(struct ethhdr));

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = ip->saddr;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = ip->daddr;

    fprintf(state.log_file, "\nIP Header\n");
    fprintf(state.log_file, "\t|-Version\t\t\t\t: %d\n", (unsigned int)ip->version);
    fprintf(state.log_file, "\t|-Internet Header Length: %d DWORDS or %d Bytes\n", (unsigned int)ip->ihl, ((unsigned int)(ip->ihl)) * 4);
    fprintf(state.log_file, "\t|-Type Of Service\t\t: %" PRIu8 "\n", ip->tos);
    fprintf(state.log_file, "\t|-Total Length\t\t\t: %" PRIu16 "\n", ntohs(ip->tot_len));
    fprintf(state.log_file, "\t|-Identification\t\t: %" PRIu16 " Bytes (0x%" PRIx16 ")\n", ntohs(ip->id), ntohs(ip->id));

    fprintf(state.log_file, "\t|----------Flags----------\n");
    fprintf(state.log_file, "\t\t|-(DF) Don't Fragment\t: %" PRIu16 "\n", ntohs(ip->frag_off) >> 14);
    fprintf(state.log_file, "\t\t|-(MF) More Fragments\t: %" PRIu16 "\n", ntohs(ip->frag_off) >> 13 & IP_MF_MASK);

    fprintf(state.log_file, "\t|-Fragment Offset\t\t: %" PRIu16 "\n", ntohs(ip->frag_off) & IP_FRAGMENT_OFFSET_MASK);
    fprintf(state.log_file, "\t|-Time To Live\t\t\t: %" PRIu8 "\n", ip->ttl);
    fprintf(state.log_file, "\t|-Protocol\t\t\t\t: %" PRIu8 "\n", ip->protocol);
    fprintf(state.log_file, "\t|-Header Checksum\t\t: %" PRIu8 " (0x%" PRIx8 ")\n", ntohs(ip->check), ntohs(ip->check));
    fprintf(state.log_file, "\t|-Source IP\t\t\t\t: %s\n", inet_ntoa(source.sin_addr));
    fprintf(state.log_file, "\t|-Destination IP\t\t: %s\n", inet_ntoa(dest.sin_addr));

    fprintf(state.log_file, "\nIP HEADER SIZE: %zu\nIP STRUCT SIZE: %zu\n", sizeof(*ip), sizeof(struct iphdr));

    state.iphdrlen = ip->ihl * 4;
    state.l4proto = ip->protocol;
}
