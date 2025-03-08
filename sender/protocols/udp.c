#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include "udp.h"

static void get_data(struct state* state) {
    state->sendbuff[state->packet_length++] = 0xAA;
    state->sendbuff[state->packet_length++] = 0xBB;
    state->sendbuff[state->packet_length++] = 0xCC;
    state->sendbuff[state->packet_length++] = 0xDD;
}

enum status construct_udp_header(struct state* state) {
    struct udphdr* udph = (struct udphdr*)(state->sendbuff + sizeof(struct ethhdr) + sizeof(struct iphdr));

    udph->source = htons(DEFAULT_PORT);
    udph->dest = htons(DEFAULT_PORT + 1);
    udph->check = 0;

    state->packet_length += sizeof(struct udphdr);
    get_data(state);
    udph->len = htons(state->packet_length - sizeof(struct ethhdr) - sizeof(struct iphdr));

    return OK;
}
