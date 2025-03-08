#ifndef MAC_H
#define MAC_H

#include <stdint.h>

#define MAC_ADDR_LEN 6

typedef struct {
    union {
        char as_char[MAC_ADDR_LEN];
        uint8_t as_uint8[MAC_ADDR_LEN];
    };
} mac;

#endif
