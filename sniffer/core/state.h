#ifndef SNIFFER_STATE_H
#define SNIFFER_STATE_H

#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>

#define BUFFER_SIZE 65536

struct state {
    unsigned char* buffer;
    size_t buflen;
#define DEFAULT_LOG_FILE_PATH "log.txt"
    FILE* log_file;
    unsigned short iphdrlen;
    uint8_t l4proto;
};

#endif
