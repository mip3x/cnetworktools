#ifndef PING_H
#define PING_H

#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>

#define ECHO_TYPE 8
#define ECHO_REPLY_TYPE 0
#define CODE 0
#define MAGIC_PAYLOAD "CPING"
#define ICMP_PROTO_ID 1
#define IP_DEFAULT_TTL 250
#define IP_DEFAULT_VERSION 4

#define show(x) _Generic((x),                                   \
    struct ip*:    show_ip((uint8_t*)# x, ((struct ip*)x)),     \
    struct icmp*:  show_icmp((uint8_t*)# x, ((struct icmp*)x))  \
)

enum icmp_hdr_type {
    unassigned,
    echo,
    echoreply
} __attribute__((packed));

enum ip_overlying_proto_type {
    icmp_proto,
    tcp_proto,
    udp_proto
} __attribute__((packed));

struct icmp_raw_hdr {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint8_t data[];
} __attribute__((packed));

struct icmp {
    enum icmp_hdr_type kind:3;
    uint16_t payload_size;
    uint8_t* payload_data;
} __attribute__((packed));

struct ip_raw_hdr {
    uint8_t version:4;
    uint8_t ihl:4;
    uint8_t dscp:6;
    uint8_t ecn:2;
    uint16_t length;
    uint16_t id;
    uint8_t flags:3;
    uint16_t offset:13;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src;
    uint32_t dst;
    uint8_t options[];
} __attribute__((packed));

struct ip {
    enum ip_overlying_proto_type kind:3;
    uint32_t src;
    uint32_t dst;
    uint16_t id;
    struct icmp* payload;
} __attribute__((packed));

// common
void printhex(uint8_t* str, uint16_t size, uint8_t delim);
void memory_copy(uint8_t* dst, uint8_t* src, uint16_t size);
uint16_t checksum(uint8_t* pkt, uint16_t size);
uint16_t endian16(uint16_t x);
uint8_t* todotted(in_addr_t ip);

// icmp
struct icmp* make_icmp(enum icmp_hdr_type kind, const uint8_t* payload_data, uint16_t payload_size);
uint8_t* eval_icmp(struct icmp* pkt);
void show_icmp(uint8_t* ident, struct icmp* pkt);

// ip
struct ip* make_ip(enum ip_overlying_proto_type kind, const uint8_t* src, const uint8_t* dst, uint16_t id, uint16_t* cntptr);
uint8_t* eval_ip(struct ip* pkt);
void show_ip(uint8_t* ident, struct ip* pkt);

#endif
