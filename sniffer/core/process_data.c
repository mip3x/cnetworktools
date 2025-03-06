#include "../protocols/protocols.h"

unsigned int total, icmp, tcp, udp, other;

void process_data(struct state state) {
    struct iphdr* ip = (struct iphdr*)(state.buffer + sizeof(struct ethhdr));
    ++total;
    switch (ip->protocol) {
        case TCP:
            ++tcp;
            process_tcp_header(state);
            break;

        case UDP:
            ++udp;
            process_udp_header(state);
            break;

        case ICMP:
            ++icmp;
            process_icmp_header(state);
            break;

        default:
            ++other;
    }
    printf("ICMP: %d TCP: %d  UDP: %d  Other: %d  Total: %d\r", icmp, tcp, udp, other, total);
}
