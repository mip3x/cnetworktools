#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <sys/ioctl.h>
#include <string.h>
#include <stdio.h>

#include "ip.h"

enum status get_ip_addr(struct state* state) {
    memset(&(state->ifreq_ip), 0, sizeof(state->ifreq_ip));
    strncpy(state->ifreq_ip.ifr_name, state->interface_name, IFNAMSIZ - 1);

    if ((ioctl(state->sock_raw, SIOCGIFADDR, &(state->ifreq_ip))) == -1) {
        puts("error in SIOCGIFADDR"); 
        return ERROR;
    }

    return OK;
}

enum status construct_ip_header(struct state* state) {
    struct iphdr* iph = (struct iphdr*)(state->sendbuff + sizeof(struct ethhdr));
    iph->version = 4;
    iph->ihl = 5;
    iph->tos = 16;
    iph->id = htons(ID_VALUE);
    iph->ttl = 64;
    iph->protocol = 17;
    iph->saddr = inet_addr(inet_ntoa( ((struct sockaddr_in*) &state->ifreq_ip.ifr_addr)->sin_addr));
    iph->daddr = inet_addr(inet_ntoa( ((struct sockaddr_in*) &state->ifreq_ip.ifr_addr)->sin_addr));

    state->packet_length += sizeof(struct iphdr);

    return OK;
}
