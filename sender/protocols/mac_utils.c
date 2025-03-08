#include <sys/ioctl.h>
#include <string.h>
#include <stdio.h>

#include "../core/mac.h"
#include "mac_utils.h"

void print_mac_addr(mac addr) {
    printf("%.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n", 
           addr.addr[0],
           addr.addr[1],
           addr.addr[2],
           addr.addr[3],
           addr.addr[4],
           addr.addr[5]
    );
}

enum status get_src_mac_addr(struct state* state) {
    memset(&(state->ifreq_c), 0, sizeof(state->ifreq_c));
    strncpy(state->ifreq_c.ifr_name, state->interface_name, IFNAMSIZ - 1);
 
    if ((ioctl(state->sock_raw, SIOCGIFHWADDR, &(state->ifreq_c))) == -1) {
        puts("error in SIOCGIFHWADDR ioctl reading");
        return ERROR;
    }

    /* 
        * from <net/if.h>:
        *   # define ifr_hwaddr	ifr_ifru.ifru_hwaddr   // MAC address 		
    */

    mac mac = {0};
    for (size_t i = 0; i < MAC_ADDR_LEN; i++)
        mac.addr[i] = (uint8_t)(state->ifreq_c.ifr_hwaddr.sa_data[i]);
    state->dest_mac_addr = mac;

    return OK;
}

enum status parse_mac_addr(struct state* state, const char* const string_to_parse) {
    if (sscanf(string_to_parse, "%hhx-%hhx-%hhx-%hhx-%hhx-%hhx",
               &state->dest_mac_addr.addr[0],
               &state->dest_mac_addr.addr[1],
               &state->dest_mac_addr.addr[2],
               &state->dest_mac_addr.addr[3],
               &state->dest_mac_addr.addr[4],
               &state->dest_mac_addr.addr[5]) != 6)
        return ERROR;

    return OK;
}
