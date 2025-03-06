#include "protocols.h"

void process_ethernet_header(struct state state) {
    struct ethhdr* eth = (struct ethhdr*)(state.buffer);
    fprintf(state.log_file, "\nEthernet Header\n");
    fprintf(state.log_file, "\t|-Source Address\t\t: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",
           eth->h_source[0],
           eth->h_source[1],
           eth->h_source[2],
           eth->h_source[3],
           eth->h_source[4],
           eth->h_source[5]
    );
    fprintf(state.log_file, "\t|-Destination Address\t: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",
           eth->h_dest[0],
           eth->h_dest[1],
           eth->h_dest[2],
           eth->h_dest[3],
           eth->h_dest[4],
           eth->h_dest[5]
    );
    fprintf(state.log_file, "\t|-Protocol\t\t\t\t: %d\n", eth->h_proto);
    
    fprintf(state.log_file, "\nETH HEADER SIZE: %zu\nETH STRUCT SIZE: %zu\n", sizeof(*eth), sizeof(struct ethhdr));
}
