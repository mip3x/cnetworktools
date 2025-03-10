#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#define IP_ADDR_MAX_LEN 16

char* get_ip_from_input(char* input, struct sockaddr_in* addr) {
    struct hostent* he;
    struct in_addr** addr_list;
    char* ip = malloc(sizeof(char) * IP_ADDR_MAX_LEN);

    if (ip == NULL) {
        puts("problem allocating ip");
        return NULL;
    }

    if ((he = gethostbyname(input)) == NULL)
        return NULL;

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
        puts("Provide ip addr or hostname");
        return 1;
    }

    char* ip;
    if ((ip = get_ip_from_input(argv[1], &dst)) != NULL)
        printf("resolved ip: %s\n", ip);

    free(ip);
}
