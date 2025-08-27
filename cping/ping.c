#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "ping.h"

#define IP_ADDR_MAX_LEN 16

uint32_t setup() {
    uint32_t s, one;
    signed int tmp;

    one = (uint32_t)1;
    tmp = socket(AF_INET, SOCK_RAW, 1);
    if (tmp > 2)
        s = (uint32_t)tmp;
    else
        s = (uint32_t)0;

    tmp = setsockopt(s, SOL_IP, IP_HDRINCL, (int*)&one, sizeof(uint32_t));

    if (tmp)
        return (uint32_t)0;

    return s;
}

bool sendip(uint32_t s, struct ip* pkt) {
    uint8_t *raw;
    uint16_t n;
    signed int ret;
    struct sockaddr_in sock;

    if (!pkt)
        return false;

    memset((uint8_t*)&sock, 0, sizeof(sock));

    raw = eval(pkt);
    n =
    (
        sizeof(struct ip_raw_hdr)
        + sizeof(struct icmp_raw_hdr)
        + pkt->payload->payload_size
    );

    sock.sin_addr.s_addr = (in_addr_t)pkt->dst;
    ret = sendto(s, raw, (uint8_t)n, 0, 
                 (const struct sockaddr*)&sock, sizeof(sock));

    if (ret < 0) 
        return false;
    else
        return true;
}

uint8_t* eval_ip(struct ip* pkt) {
    struct ip_raw_hdr rawpkt;
    struct ip_raw_hdr *rawptr;
    uint16_t check;
    uint16_t size;
    uint8_t *ptr, *ret;
    uint8_t protocol;
    uint16_t lengthle;
    uint16_t lengthbe;
    uint8_t *icmpptr;

    if (!pkt)
        return NULL;

    protocol = 0;
    switch (pkt->kind) {
        case icmp_proto:
            protocol = ICMP_PROTO_ID;
            break;

        default:
            return NULL;
            break;
    }

    rawpkt.checksum = 0;
    rawpkt.dscp = 0;
    rawpkt.dst = pkt->dst;
    rawpkt.ecn = 0;
    rawpkt.flags = 0;
    rawpkt.id = endian16(pkt->id);
    rawpkt.ihl = sizeof(struct ip_raw_hdr) / 4;

    lengthle = 0;
    if (pkt->payload) {
        lengthle = (rawpkt.ihl * 4) + pkt->payload->payload_size +
            sizeof(struct icmp_raw_hdr);
        lengthbe = endian16(lengthle);
        rawpkt.length = lengthbe;
    }
    else
        lengthle = rawpkt.length = (rawpkt.ihl * 4);

    rawpkt.offset = 0;
    rawpkt.protocol = protocol;
    rawpkt.src = pkt->src;
    rawpkt.ttl = IP_DEFAULT_TTL;
    rawpkt.version = IP_DEFAULT_VERSION;

    if (lengthle % 2)
        lengthle++;

    size = sizeof(struct ip_raw_hdr);
    ptr = (uint8_t*)malloc(lengthle);
    ret = ptr;

    if (ptr == NULL) {
        fprintf(stderr, "Problem allocating\n");
        return NULL;
    }
    memset(ptr, 0, lengthle);

    memory_copy(ptr, (uint8_t*)&rawpkt, size);
    ptr += size;

    if (pkt->payload) {
        size = (sizeof(struct icmp_raw_hdr) +
            pkt->payload->payload_size);
        icmpptr = eval_icmp(pkt->payload);
        if (icmpptr) {
            memory_copy(ptr, icmpptr, size);
            free(icmpptr);
        }
    }

    check = checksum(ret, lengthle);
    rawptr = (struct ip_raw_hdr*)ret;
    rawptr->checksum = check;

    return ret;
}

struct ip* make_ip(enum ip_overlying_proto_type kind, const uint8_t* src, const uint8_t* dst, uint16_t id_, uint16_t* cntptr) {
    uint16_t id;
    uint16_t size;
    struct ip* pkt;

    if (!src || !dst) {
        fprintf(stderr, "Problem with ");
        if (!src) fprintf(stderr, "src\n");
        if (!dst) fprintf(stderr, "dst\n");
        return NULL;
    }

    if (id_)
        id = id_;
    else
        id = *cntptr++;

    size = sizeof(struct ip);
    pkt = malloc(size);
    if (pkt == NULL) {
        fprintf(stderr, "Problem allocating ip struct\n");
        return NULL;
    }
    memset(pkt, 0, size);

    pkt->kind = kind;
    pkt->id = id;
    pkt->src = inet_addr((char*)src);
    pkt->dst = inet_addr((char*)dst);
    pkt->payload = NULL;

    if (!pkt->dst) {
        free(pkt);
        fprintf(stderr, "Destination IP is NULL\n");
        return NULL;
    }

    return pkt;
}

void show_ip(uint8_t* ident, struct ip* pkt) {
    if (!pkt) {
        fprintf(stderr, "Invalid IP packet!\n");
        return;
    }

    uint16_t pkt_size = (sizeof(struct ip_raw_hdr)
        + sizeof(struct icmp_raw_hdr)
        + pkt->payload->payload_size);

    printf("(ip *)%s = {\n", (char*)ident);
    printf("  size:\t %d bytes total\n", pkt_size);
    printf("  kind:\t 0x%.02hhx\n", (char)pkt->kind);
    printf("  id:\t 0x%.02hhx\n", (uint8_t)pkt->id);
    printf("  src:\t %s\n", (char*)todotted(pkt->src));
    printf("  dst:\t %s\n", (char*)todotted(pkt->dst));
    printf("}\n");

    if (pkt->payload)
        show(pkt->payload);

    return;
}

uint16_t endian16(uint16_t x) {
    uint8_t a, b;
    uint16_t y;

    b = (x & 0x00ff);
    a = ((x & 0xff00) >> 8);
    y = (b << 8) | a;

    return y;
}

uint8_t* todotted(in_addr_t ip) {
    uint8_t a, b, c, d;
    static uint8_t buf[16];

    d = ((ip & 0xff000000) >> 24);
    c = ((ip & 0xff0000) >> 16);
    b = ((ip & 0xff00) >> 8);
    a = ((ip & 0xff));

    memset(buf, 0, sizeof(buf));
    snprintf((char *)buf, 16, "%d.%d.%d.%d", a, b, c, d);

    return buf;
}

/*
 * https://repo.doctorbirch.com/birchutils/v1.3/files/birchutils.c
 */
void printhex(uint8_t* str, uint16_t size, uint8_t delim) {
    uint8_t *ptr;
    uint16_t n;

    for (ptr = str, n = size; n; n--, ptr++) {
        printf("%.02x", *ptr);
        if (delim)
            printf("%c", delim);
        fflush(stdout);
    }
    printf("\n");

    return;
}

/* 
 * http://www.faqs.org/rfcs/rfc1071.html
 */
uint16_t checksum(uint8_t *pkt, uint16_t size) {
    uint16_t* ptr;
    uint32_t acc, b;
    uint16_t carry;
    uint16_t n;
    uint16_t sum;
    uint16_t ret;

    acc = 0;
    for (n = size, ptr = (uint16_t*)pkt; n; n -= 2, ptr++) {
        b = *ptr;
        acc += b;
    }
    carry = ((acc & 0xffff0000) >> 16);
    sum = (acc & 0x0000ffff);
    ret = ~(sum + carry);

    return endian16(ret);
}

void memory_copy(uint8_t *dst, uint8_t *src, uint16_t size) {
    uint8_t *dptr, *sptr;

    for (dptr = dst, sptr = src; size; size--)
        *dptr++ = *sptr++;

    return;
}

uint8_t* eval_icmp(struct icmp* pkt) {
    uint8_t *ptr, *ret;
    uint16_t full_icmp_pkt_size;
    struct icmp_raw_hdr rawpkt;
    struct icmp_raw_hdr *rawptr;
    uint16_t check;

    if (!pkt || !pkt->payload_data) {
        fprintf(stderr, "Invalid ICMP packet!\n");
        return NULL;
    }

    switch (pkt->kind) {
        case echo:
            rawpkt.type = ECHO_TYPE;
            rawpkt.code = CODE;

            break;

        case echoreply:
            rawpkt.type = ECHO_REPLY_TYPE;
            rawpkt.code = CODE;

            break;

        default:
            fprintf(stderr, "Invalid ICMP packet!\n");
            return NULL;
            break;
    }

    rawpkt.checksum = 0;
    full_icmp_pkt_size = sizeof(struct icmp_raw_hdr) + pkt->payload_size;
    if (full_icmp_pkt_size % 2)
        full_icmp_pkt_size++;

    ptr = malloc(full_icmp_pkt_size);
    ret = ptr;

    if (ptr == NULL) {
        fprintf(stderr, "Problem allocating\n");
        return NULL;
    }
    memset(ptr, 0, full_icmp_pkt_size);

    memory_copy(ptr, (uint8_t*)&rawpkt, sizeof(struct icmp_raw_hdr));
    ptr += sizeof(struct icmp_raw_hdr);
    memory_copy(ptr, pkt->payload_data, pkt->payload_size);

    check = checksum(ret, full_icmp_pkt_size);
    rawptr = (struct icmp_raw_hdr*)ret;
    rawptr->checksum = check;

    return ret;
}

void show_icmp(uint8_t* ident, struct icmp* pkt) {
    if (!pkt) {
        fprintf(stderr, "Invalid ICMP packet!\n");
        return;
    }

    printf("(icmp *)%s = {\n", (char*)ident);
    printf("  kind:\t %s\n", (pkt->kind == echo) ? "Echo" : "Echo Reply");
    printf("  size:\t %d bytes of payload\n", (uint16_t)pkt->payload_size);
    printf("}\n");
    printf("payload:\n");

    if (pkt->payload_data) {
        printhex(pkt->payload_data, pkt->payload_size, 0);
        printf("\n");
    }

    return;
}

struct icmp* make_icmp(enum icmp_hdr_type kind, const uint8_t* payload_data, uint16_t payload_size) {
    struct icmp *icmp_hdr_ptr;
    uint16_t full_icmp_pkt_size;

    if (!payload_data || !payload_size)
        return NULL;

    full_icmp_pkt_size = sizeof(struct icmp) + payload_size;
    icmp_hdr_ptr = (struct icmp*)malloc(full_icmp_pkt_size);

    if (icmp_hdr_ptr == NULL) {
        fprintf(stderr, "Problem allocating icmp struct\n");
        return NULL;
    }
    memset(icmp_hdr_ptr, 0, full_icmp_pkt_size);

    icmp_hdr_ptr->kind = kind;
    icmp_hdr_ptr->payload_size = payload_size;
    icmp_hdr_ptr->payload_data = (uint8_t*)payload_data;

    return icmp_hdr_ptr;
}

char* get_ip_from_input(char* input, struct sockaddr_in* addr) {
    struct hostent* he;
    struct in_addr** addr_list;
    char* ip = malloc(sizeof(char) * IP_ADDR_MAX_LEN);

    if (ip == NULL) {
        fprintf(stderr, "Problem allocating ip\n");
        return NULL;
    }

    if ((he = gethostbyname(input)) == NULL) {
        fprintf(stderr, "Incorrect ip\n");
        return NULL;
    }

    addr_list = (struct in_addr**)he->h_addr_list;
    for (size_t i = 0; addr_list[i] != NULL; i++) {
        addr->sin_addr = *addr_list[i];
        strcpy(ip, inet_ntoa(addr->sin_addr));
        break;
    }

    return ip;
}

int main1(int argc, char** argv) {
    struct sockaddr_in src = { .sin_family = AF_INET };
    struct sockaddr_in dst;
    memset((char *)&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;

    if (argc < 2) {
        fprintf(stderr, "Provide ip addr or hostname\n");
        return 1;
    }

    char* ip;
    if ((ip = get_ip_from_input(argv[1], &dst)) != NULL)
        printf("Resolved ip: %s\n", ip);
    else {
        free(ip);
        return 1;
    }

    struct ping* str;
    uint8_t* raw;
    uint16_t rnd;
    uint16_t size;
    struct icmp* icmppkt;
    struct ip* ippkt;
    uint32_t s;
    bool ret;

    (void)rnd;
    srand(getpid());
    rnd = rand() % 50000;

    size = (sizeof(struct ping)
        + 4);
    str = (struct ping*)malloc(size);
    if (str == NULL) {
        fprintf(stderr, "Problem allocating str\n");
        free(ip);
        return 1;
    }
    memset(str, 0, size);
    
    str->id = endian16(5000);
    str->seq = endian16(1);
    strncpy((char*)str->data, MAGIC_PAYLOAD, strlen((char*)str));

    icmppkt = make_icmp(echo, (uint8_t*)str, size);
    if (icmppkt == NULL) {
        free(ip);
        return 1;
    }

    ippkt = make_ip(icmp_proto, (uint8_t*)"192.168.1.198", (uint8_t*)ip, 0, &rnd);
    if (ippkt == NULL) {
        free(icmppkt->payload_data);
        free(icmppkt);
        return 1;
    }
    ippkt->payload = icmppkt;

    raw = eval_ip(ippkt);
    size = sizeof(struct ip_raw_hdr) +
        sizeof(struct icmp_raw_hdr) +
        ippkt->payload->payload_size;
    show(ippkt);
    printhex(raw, size, ' ');

    s = setup();
    if (!s) {
        printf("error\n");
        return 1;
    }

    ret = sendip(s, ippkt);
    printf("ret=%s\n", (ret) ? "true" : "false");

    free(icmppkt->payload_data);
    free(icmppkt);
    free(ippkt);
    free(ip);

    return 0;
}

int main(int argc, char** argv) {
    return main1(argc, argv);
}

