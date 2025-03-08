#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

#include "parser.h"
#include "../protocols/protocols.h"
#include "state.h"
#include "status.h"

int main(int argc, char* argv[]) {
    struct state state = {0};
    if (parse_config(CONFIG_FILE_NAME, &state) == ERROR) return -1;

    if (state.interface_name == NULL) {
        printf("\ntaking default interface_name...\n\n");
        state.interface_name = DEFAULT_DEVICE_NAME;
    }

    state.sock_raw = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
    if (state.sock_raw == -1) {
        printf("error in socket\n");
        return -1;
    }
    printf("socket was opened successfully\n");

    if (get_eth_index(state) == ERROR) return -1;
    if (get_src_mac_addr(state) == ERROR) return -1;
    if (get_ip_addr(state) == ERROR) return -1;

    /*state.sendbuff = (uint8_t*)malloc(SENDBUF_SIZE);*/
    /*memset(&state.sendbuff, 0, SENDBUF_SIZE);*/

    close(state.sock_raw);
}
