#include <netinet/ether.h>
#include <sys/ioctl.h>
#include <string.h>
#include <stdio.h>

#include "eth.h"

enum status get_eth_index(struct state state) {
    memset(&state.ifreq_i, 0, sizeof(state.ifreq_i));
    strncpy(state.ifreq_i.ifr_name, state.interface_name, IFNAMSIZ - 1);

    /* 
        * from <net/if.h>:
        *   # define ifr_ifindex	ifr_ifru.ifru_ivalue    // interface index     		
    */

    if ((ioctl(state.sock_raw, SIOCGIFINDEX, &state.ifreq_i)) == -1) {
        printf("error in index ioctl reading\n");
        return ERROR;
    }

    printf("Interface index: %d\n", state.ifreq_i.ifr_ifindex);

    return OK;
}

enum status construct_eth_header(struct state state) {
    struct ethhdr* eth = (struct ethhdr*)state.sendbuff;

    return OK;
}
