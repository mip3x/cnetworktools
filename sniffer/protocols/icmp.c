#include "protocols.h"

void process_icmp_header(struct state state) {
    fprintf(state.log_file, "\n************************ICMP Packet******************************");

    process_ethernet_header(state);
    process_ip_header(state);

    struct icmphdr* icmp = (struct icmphdr*)(state.buffer + sizeof(struct ethhdr) + state.iphdrlen);
    fprintf(state.log_file, "\nICMP Header\n");

    uint8_t type = icmp->type;
    uint8_t code = icmp->code;
    fprintf(state.log_file, "\t|-Type\t\t\t\t\t: %" PRIu8 " ", type);

    char* code_description = NULL;
    switch (type) {
        case ICMP_ECHOREPLY:
            fprintf(state.log_file, "(Echo reply)");
            break;

        case ICMP_ECHO:
            fprintf(state.log_file, "(Echo request)");
            break;
    }
    fprintf(state.log_file, "\n");

    fprintf(state.log_file, "\t|-Code\t\t\t\t\t: %" PRIu8 "", code);
    if (code_description != NULL)
        fprintf(state.log_file, " (%s)", code_description);
    fprintf(state.log_file, "\n");

    switch (code) {
    }

    fprintf(state.log_file, "\t|-Checksum\t\t\t\t: %" PRIu16 " (0x%" PRIx16 ")\n", ntohs(icmp->checksum), ntohs(icmp->checksum));
    fprintf(state.log_file, "\t|-Identifier\t\t\t: %" PRIu16 " (0x%" PRIx16 ")\n", ntohs(icmp->un.echo.id), ntohs(icmp->un.echo.id));
    fprintf(state.log_file, "\t|-Sequence\t\t\t\t: %" PRIu16 " (0x%" PRIx16 ")\n", ntohs(icmp->un.echo.sequence), ntohs(icmp->un.echo.sequence));

	fprintf(state.log_file, "*****************************************************************\n");
    fprintf(state.log_file, "\nBUFLEN: %zu\n", state.buflen);
}
