#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>

#include "state.h"
#include "../protocols/protocols.h"

#define DEFAULT_DEVICE_NAME "lo"

int main(int argc, char* argv[]) {
    struct state state = {0};

    state.interface_name = (argc == 2) ? argv[1] : DEFAULT_DEVICE_NAME;

    state.sock_raw = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
    if (state.sock_raw == -1) {
        printf("error in socket\n");
        return -1;
    }
    printf("socket was opened successfully\n");

    get_eth_index(state);
    get_mac_address(state);

    close(state.sock_raw);
}
