#include <sys/ioctl.h>
#include <string.h>
#include <stdio.h>

#include "protocols.h"

enum status get_mac_addr(struct state state) {
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

    printf("MAC addr: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n", 
           (unsigned char)(state.ifreq_c.ifr_hwaddr.sa_data[0]),
           (unsigned char)(state.ifreq_c.ifr_hwaddr.sa_data[1]),
           (unsigned char)(state.ifreq_c.ifr_hwaddr.sa_data[2]),
           (unsigned char)(state.ifreq_c.ifr_hwaddr.sa_data[3]),
           (unsigned char)(state.ifreq_c.ifr_hwaddr.sa_data[4]),
           (unsigned char)(state.ifreq_c.ifr_hwaddr.sa_data[5]))
    ;

    return OK;
}
