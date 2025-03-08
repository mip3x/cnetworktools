#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_packet.h>
#include <netinet/ether.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

#include "parser.h"
#include "../protocols/protocols.h"
#include "state.h"
#include "status.h"

int main(int argc, char* argv[]) {
    struct state state = {0};
    if (parse_config(CONFIG_FILE_NAME, &state) == ERROR) return -1;

    if (state.interface_name == NULL) {
        puts("\ntaking default interface_name...\n");
        state.interface_name = DEFAULT_DEVICE_NAME;
    }

    state.sock_raw = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
    if (state.sock_raw == -1) {
        puts("error in socket");
        return -1;
    }
    puts("socket was opened successfully");

    if (get_eth_index(&state) == ERROR) return -1;
    if (get_src_mac_addr(&state) == ERROR) return -1;
    if (get_ip_addr(&state) == ERROR) return -1;

    state.sendbuff = (uint8_t*)malloc(SENDBUF_SIZE);
    memset(state.sendbuff, 0, SENDBUF_SIZE);

    puts("");

    if (construct_eth_header(&state) == ERROR) return -1;
    if (construct_ip_header(&state) == ERROR) return -1;

    struct sockaddr_ll sadr_ll;
	sadr_ll.sll_ifindex = state.ifreq_i.ifr_ifindex;
	sadr_ll.sll_halen = ETH_ALEN;

    for (size_t i = 0; i < MAC_ADDR_LEN; i++)
        sadr_ll.sll_addr[i] = (unsigned char)state.dest_mac_addr.addr[i];

    size_t sent_len = 0;
    size_t packets_count = 0;
    puts("sending...");

    while (true) {
        sent_len = sendto(state.sock_raw,
                          state.sendbuff,
                          state.packet_length,
                          0,
                          (const struct sockaddr*)&sadr_ll,
                          sizeof(struct sockaddr_ll)
        );

		if (sent_len == -1) {
			printf("error in sending:\n\nsendlen = %zu\nerrno = %d\n", sent_len, errno);
			return -1;
		}
        printf("sent packet #%zu length of %zu bytes\n", ++packets_count, sent_len);
        
        usleep(LATENCY_MICROSEC);
    }

    close(state.sock_raw);
}
