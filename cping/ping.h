#ifndef PING_H
#define PING_H

#include <stdint.h>

#define ECHO_TYPE 8
#define ECHO_REPLY_TYPE 0
#define CODE 0
#define MAGIC_PAYLOAD "CPING"

struct __attribute__((packed)) icmp_raw_header {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint8_t data[];
};

enum icmp_header_type {
    unassigned,
    echo,
    echoreply
};

struct icmp_header {
    enum icmp_header_type kind;
    uint16_t payload_size;
    uint8_t* payload_data;
};

void printhex(uint8_t* str, uint16_t size, uint8_t delim);
void memory_copy(uint8_t* dst, uint8_t* src, uint16_t size);
uint16_t checksum(uint8_t* pkt, uint16_t size);

struct icmp_header* make_icmp(enum icmp_header_type kind, const uint8_t* payload_data, uint16_t payload_size);
uint8_t* eval_icmp(struct icmp_header* pkt);
void show_icmp(struct icmp_header* pkt);

#endif
