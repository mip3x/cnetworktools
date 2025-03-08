#ifndef MAC_H
#define MAC_H

#include <stdint.h>

#define MAC_ADDR_LEN 6

typedef struct {
    uint8_t addr[MAC_ADDR_LEN];
} mac;

#endif
