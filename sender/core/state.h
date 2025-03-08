#ifndef SENDER_STATE_H
#define SENDER_STATE_H

#include <net/if.h>
#include <stdint.h>

#include "mac.h"

#define CONFIG_FILE_NAME "sender.conf"
#define DEFAULT_DEVICE_NAME "lo"
#define SENDBUF_SIZE 64

struct state {
    char* interface_name;
    int sock_raw;
    uint8_t* sendbuff;
    struct ifreq ifreq_i;
    struct ifreq ifreq_c;
    struct ifreq ifreq_ip;
    mac dest_mac_addr;
};

#endif
