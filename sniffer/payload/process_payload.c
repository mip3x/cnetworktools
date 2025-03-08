#include <netinet/ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "../protocols/protocols.h"
#include "../core/state.h"

void process_payload(struct state* state) {
    size_t summary_headers_length = state->iphdrlen + sizeof(struct ethhdr);

    switch (state->l4proto) {
        case TCP:
            summary_headers_length += sizeof(struct tcphdr);
            break;

        case UDP:
            summary_headers_length += sizeof(struct udphdr);
            break;
    }

    unsigned char* data = (state->buffer + summary_headers_length);
    size_t remaining_data = state->buflen - summary_headers_length;

    fprintf(state->log_file, "\nData:\n");
    for (size_t i = 0; i < remaining_data; i++) {
        if (i % 16 == 0) fprintf(state->log_file, "\n");
        fprintf(state->log_file, "%.2X ", data[i]);
    }
    fprintf(state->log_file, "\n\nPAYLOAD SIZE: %zu\n", remaining_data);
}
