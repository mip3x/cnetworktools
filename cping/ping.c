#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "ping.h"

#define IP_ADDR_MAX_LEN 16

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

    acc = 0;
    for (n = size, ptr = (uint16_t*)pkt; n; n -= 2, ptr++) {
        b = *ptr;
        acc += b;
    }
    carry = ((acc & 0xffff0000) >> 16);
    sum = (acc & 0x0000ffff);

    return ~(sum + carry);
}

void memory_copy(uint8_t *dst, uint8_t *src, uint16_t size) {
    uint8_t *dptr, *sptr;

    for (dptr = dst, sptr = src; size; size--)
        *dptr++ = *sptr++;

    return;
}

uint8_t* eval_icmp(struct icmp_header* pkt) {
    uint8_t *ptr, *ret;
    uint16_t full_icmp_pkt_size;
    struct icmp_raw_header rawpkt;
    struct icmp_raw_header *rawptr;
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
    full_icmp_pkt_size = sizeof(struct icmp_raw_header) + pkt->payload_size;
    if (full_icmp_pkt_size % 2)
        full_icmp_pkt_size++;

    ptr = malloc(full_icmp_pkt_size);
    ret = ptr;

    if (ptr == NULL) {
        fprintf(stderr, "Problem allocating\n");
        return NULL;
    }
    memset(ptr, 0, full_icmp_pkt_size);

    memory_copy(ptr, (uint8_t*)&rawpkt, sizeof(struct icmp_raw_header));
    ptr += sizeof(struct icmp_raw_header);
    memory_copy(ptr, pkt->payload_data, pkt->payload_size);

    check = checksum(ret, full_icmp_pkt_size);
    rawptr = (struct icmp_raw_header*)ret;
    rawptr->checksum = check;

    return ret;
}

void show_icmp(struct icmp_header* pkt) {
    if (!pkt) {
        fprintf(stderr, "Invalid ICMP packet!\n");
        return;
    }

    printf("kind:\t %s\nsize:\t %d\npayload:\n", 
           (pkt->kind == echo) ? "Echo" : "Echo Reply",
           (uint16_t)pkt->payload_size);

    if (pkt->payload_data) {
        printhex(pkt->payload_data, pkt->payload_size, 0);
        printf("\n");
    }

    return;
}

struct icmp_header* make_icmp(enum icmp_header_type kind, const uint8_t* payload_data, uint16_t payload_size) {
    struct icmp_header *icmp_header_ptr;
    uint16_t full_icmp_pkt_size;

    if (!payload_data || !payload_size)
        return NULL;

    full_icmp_pkt_size = sizeof(struct icmp_header) + payload_size;
    icmp_header_ptr = (struct icmp_header*)malloc(full_icmp_pkt_size);

    if (icmp_header_ptr == NULL) {
        fprintf(stderr, "Problem allocating icmp_header struct\n");
        return NULL;
    }
    memset(icmp_header_ptr, 0, full_icmp_pkt_size);

    icmp_header_ptr->kind = kind;
    icmp_header_ptr->payload_size = payload_size;
    icmp_header_ptr->payload_data = (uint8_t*)payload_data;

    return icmp_header_ptr;
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

int main(int argc, char** argv) {
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

    uint8_t* str;
    uint8_t* raw;
    uint16_t size;
    struct icmp_header* pkt;

    str = malloc(strlen(MAGIC_PAYLOAD));
    if (str == NULL) {
        fprintf(stderr, "Problem allocating str\n");
        free(ip);
        return 1;
    }
    strncpy((char*)str, MAGIC_PAYLOAD, strlen((char*)str));

    pkt = make_icmp(echo, str, strlen((char*)str));
    if (pkt == NULL) {
        free(ip);
        return 1;
    }
    show_icmp(pkt);

    raw = eval_icmp(pkt);
    if (raw == NULL) {
        free(pkt->payload_data);
        free(pkt);
        free(ip);
        return 1;
    }
    size = sizeof(struct icmp_raw_header) + pkt->payload_size;

    printhex(raw, size, 0);

    free(pkt->payload_data);
    free(pkt);
    free(ip);

    return 0;
}
