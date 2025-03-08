#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>

#include "protocols.h"

void process_tcp_header(struct state state) {
    fprintf(state.log_file, "\n*************************TCP Packet******************************");

    process_ethernet_header(state);
    process_ip_header(state);

    struct tcphdr* tcp = (struct tcphdr*)(state.buffer + state.iphdrlen + sizeof(struct ethhdr));

    fprintf(state.log_file, "\nTCP Header\n");
    fprintf(state.log_file, "\t|-Source Port\t\t\t: %" PRIu16 "\n", ntohs(tcp->source));
    fprintf(state.log_file, "\t|-Destination Port\t\t: %" PRIu16 "\n", ntohs(tcp->dest));
    fprintf(state.log_file, "\t|-Sequence number\t\t: %" PRIu32 "\n", ntohl(tcp->seq));
    fprintf(state.log_file, "\t|-Acknowledgment Number\t: %" PRIu32 "\n", ntohl(tcp->ack_seq));
    fprintf(state.log_file, "\t|-Header Length\t\t\t: %" PRIu16 " DWORDS or %" PRIu16 " bytes\n", tcp->doff, tcp->doff * 4);

    fprintf(state.log_file, "\t|----------Flags----------\n");
    fprintf(state.log_file, "\t\t|-Urgent Flag\t\t\t: %" PRIu16 "\n", tcp->urg);
    fprintf(state.log_file, "\t\t|-Acknowledgement Flag\t: %" PRIu16 "\n", tcp->ack);
    fprintf(state.log_file, "\t\t|-Push Flag\t\t\t\t: %" PRIu16 "\n", tcp->psh);
    fprintf(state.log_file, "\t\t|-Reset Flag\t\t\t: %" PRIu16 "\n", tcp->rst);
    fprintf(state.log_file, "\t\t|-Synchronise Flag\t\t: %" PRIu16 "\n", tcp->syn);
    fprintf(state.log_file, "\t\t|-Finish Flag\t\t\t: %" PRIu16 "\n", tcp->fin);

    fprintf(state.log_file, "\t|-Window size\t\t\t: %" PRIu16 "\n", ntohs(tcp->window));
    fprintf(state.log_file, "\t|-Checksum\t\t\t\t: %" PRIu16 " (0x%" PRIx16 ")\n", ntohs(tcp->check), ntohs(tcp->check));
    fprintf(state.log_file, "\t|-Urgent Pointer\t\t: %" PRIu16 "\n", ntohs(tcp->urg_ptr));

    process_payload(state);
    fprintf(state.log_file, "\nTCP HEADER SIZE: %zu\nTCP STRUCT SIZE: %zu\n", sizeof(*tcp), sizeof(struct tcphdr));
    fprintf(state.log_file, "*****************************************************************\n");
    fprintf(state.log_file, "\nBUFLEN: %zu\n", state.buflen);
}
