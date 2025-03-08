#ifndef SENDER_STATE_H
#define SENDER_STATE_H

#include <net/if.h>

struct state {
    char* device_name;
    int sock_raw;
    struct ifreq ifreq_i;
    struct ifreq ifreq_c;
    struct ifreq ifreq_ip;
};

#endif
