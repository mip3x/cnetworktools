#include <sys/ioctl.h>
#include <string.h>
#include <stdio.h>

#include "../core/mac.h"
#include "mac_utils.h"

void print_mac_addr(mac addr) {
    printf("MAC addr: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n", 
           addr.as_uint8[0],
           addr.as_uint8[1],
           addr.as_uint8[2],
           addr.as_uint8[3],
           addr.as_uint8[4],
           addr.as_uint8[5]
    );
}

enum status get_src_mac_addr(struct state state) {
    memset(&state.ifreq_c, 0, sizeof(state.ifreq_c));
    strncpy(state.ifreq_c.ifr_name, state.interface_name, IFNAMSIZ - 1);
 
    if ((ioctl(state.sock_raw, SIOCGIFHWADDR, &state.ifreq_c)) == -1) {
        printf("error in SIOCGIFHWADDR ioctl reading\n");
        return ERROR;
    }

    /* 
        * from <net/if.h>:
        *   # define ifr_hwaddr	ifr_ifru.ifru_hwaddr   // MAC address 		
    */

    mac addr = {0};
    strncpy(addr.as_char, state.ifreq_c.ifr_hwaddr.sa_data, 6);
    printf("Source ");
    print_mac_addr(addr);

    return OK;
}

enum status parse_mac_addr(struct state* state, const char* const string_to_parse) {
    if (sscanf(string_to_parse, "%hhx-%hhx-%hhx-%hhx-%hhx-%hhx",
               &state->dest_mac_addr.as_uint8[0],
               &state->dest_mac_addr.as_uint8[1],
               &state->dest_mac_addr.as_uint8[2],
               &state->dest_mac_addr.as_uint8[3],
               &state->dest_mac_addr.as_uint8[4],
               &state->dest_mac_addr.as_uint8[5]) != 6)
        return ERROR;

    return OK;
}
