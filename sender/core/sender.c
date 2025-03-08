#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>

#include "state.h"
#include "../protocols/protocols.h"
#include "status.h"

int main(int argc, char* argv[]) {
    struct state state = {0};

    state.interface_name = (argc == 2) ? argv[1] : DEFAULT_DEVICE_NAME;

    state.sock_raw = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
    if (state.sock_raw == -1) {
        printf("error in socket\n");
        return -1;
    }
    printf("socket was opened successfully\n");

    if (get_eth_index(state) == ERROR) return -1;
    if (get_mac_addr(state) == ERROR) return -1;
    if (get_ip_addr(state) == ERROR) return -1;

    close(state.sock_raw);
}
