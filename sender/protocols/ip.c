#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <string.h>
#include <stdio.h>

#include "ip.h"

enum status get_ip_addr(struct state* state) {
    memset(&(state->ifreq_ip), 0, sizeof(state->ifreq_ip));
    strncpy(state->ifreq_ip.ifr_name, state->interface_name, IFNAMSIZ - 1);

    if ((ioctl(state->sock_raw, SIOCGIFADDR, &(state->ifreq_ip))) == -1) {
        puts("error in SIOCGIFADDR"); 
        return ERROR;
    }

    return OK;
}
