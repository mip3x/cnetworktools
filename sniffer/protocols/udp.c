#include "protocols.h"

void process_udp_header(struct state state) {
    fprintf(state.log_file, "\n*************************UDP Packet******************************");

    process_ethernet_header(state);
    process_ip_header(state);

    struct udphdr* udp = (struct udphdr*)(state.buffer + state.iphdrlen + sizeof(struct ethhdr));

    fprintf(state.log_file, "\nUDP Header\n");
    fprintf(state.log_file, "\t|-Source Port\t\t\t: %" PRIu16 "\n", ntohs(udp->source));
    fprintf(state.log_file, "\t|-Destination Port\t\t: %" PRIu16 "\n", ntohs(udp->dest));
    fprintf(state.log_file, "\t|-UDP Length\t\t\t: %" PRIu16 "\n", ntohs(udp->len));
    fprintf(state.log_file, "\t|-UDP Checksum\t\t\t: %" PRIu16 " (0x%" PRIx16 ")\n", ntohs(udp->check), ntohs(udp->check));

    process_payload(state);
    fprintf(state.log_file, "\nUDP HEADER SIZE: %zu\nUDP STRUCT SIZE: %zu\n", sizeof(*udp), sizeof(struct udphdr));
	fprintf(state.log_file, "*****************************************************************\n");
    fprintf(state.log_file, "\nBUFLEN: %zu\n", state.buflen);
}
