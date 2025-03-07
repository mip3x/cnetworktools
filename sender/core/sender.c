#include <arpa/inet.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/if_ether.h>
#include <stdio.h>
#include <net/if.h>
#include <sys/ioctl.h>

#define DEFAULT_DEVICE_NAME "lo"

int main(int argc, char* argv[]) {
    char* device_name = DEFAULT_DEVICE_NAME;

    if (argc == 2) device_name = argv[1];

    int sock_raw;
    sock_raw = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);

    if (sock_raw == -1) {
        printf("error in socket\n");
        return -1;
    }

    struct ifreq ifreq_i;
    memset(&ifreq_i, 0, sizeof(ifreq_i));
    strncpy(ifreq_i.ifr_name, device_name, IFNAMSIZ - 1);

    if ((ioctl(sock_raw, SIOCGIFINDEX, &ifreq_i)) != 0)
        printf("error in index ioctl reading\n");

    printf("index = %d\n", ifreq_i.ifr_ifru.ifru_ivalue);
}
