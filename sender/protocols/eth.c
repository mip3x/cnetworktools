#include <arpa/inet.h>
#include <netinet/ether.h>
#include <sys/ioctl.h>
#include <string.h>
#include <stdio.h>

#include <inttypes.h>

#include "eth.h"
#include "mac_utils.h"

enum status get_eth_index(struct state* state) {
    memset(&(state->ifreq_i), 0, sizeof(state->ifreq_i));
    strncpy(state->ifreq_i.ifr_name, state->interface_name, IFNAMSIZ - 1);

    /* 
        * from <net/if.h>:
        *   # define ifr_ifindex	ifr_ifru.ifru_ivalue    // interface index     		
    */

    if ((ioctl(state->sock_raw, SIOCGIFINDEX, &(state->ifreq_i))) == -1) {
        puts("error in index ioctl reading");
        return ERROR;
    }

    return OK;
}

enum status construct_eth_header(struct state state) {
    struct ethhdr* eth = (struct ethhdr*)state.sendbuff;

    for (size_t i = 0; i < MAC_ADDR_LEN; i++) {
        eth->h_source[i] = (unsigned char)state.ifreq_c.ifr_hwaddr.sa_data[i];
        eth->h_dest[i] = state.dest_mac_addr.addr[i];
    }

    puts("CONSTRUCT ETH:");

    printf("\t|-Interface index: %d\n", state.ifreq_i.ifr_ifindex);
	printf("\t|-Source IP addr: %s\n", inet_ntoa( ((struct sockaddr_in*) &state.ifreq_ip.ifr_addr)->sin_addr ));
    printf("\t|-Source MAC addr: ");
    print_mac_addr(state.dest_mac_addr);

    printf("\t|-Destination MAC addr: ");
    print_mac_addr(state.dest_mac_addr);

    return OK;
}
