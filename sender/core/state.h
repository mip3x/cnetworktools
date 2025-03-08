#ifndef SENDER_STATE_H
#define SENDER_STATE_H

#include <net/if.h>

#define DEFAULT_DEVICE_NAME "lo"

struct state {
    char* interface_name;
    int sock_raw;
    struct ifreq ifreq_i;
    struct ifreq ifreq_c;
    struct ifreq ifreq_ip;
};

#endif
