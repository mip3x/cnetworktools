#include <arpa/inet.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <netinet/ether.h>

#include "state.h"
#include "process_data.h"

/* 
 * This program must be run from root, as it requires a raw socket
*/
int main(int argc, char* argv[]) {
    char* log_file_path = DEFAULT_LOG_FILE_PATH;

    if (argc == 2) log_file_path = argv[1];
    struct state state = {0};

    int sock_raw;
    sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    /* 
     * AF_PACKET socket allows user-space application to capture raw packets 
     * at link layer (OSI L2) so that it can see the whole packet data starting
     * from link layer headers and bottom up to transport layer and application payload
     * Orig: https://csulrong.github.io/blogs/2022/03/10/linux-afpacket/ 
    */
    
    if (sock_raw == -1) {
        printf("error in socket\n");
        return -1;
    }
    printf("socket was opened successfully\n");

    unsigned char* buffer = (unsigned char*) malloc(BUFFER_SIZE);
    memset(buffer, 0, BUFFER_SIZE);
    state.buffer = buffer;

    state.log_file = fopen(log_file_path, "w");
    if (!state.log_file) {
        printf("unable to open %s\n", log_file_path);
        return -1;
    }
    printf("file %s was opened successfully\n", log_file_path);

    struct sockaddr saddr;
    socklen_t saddr_len = sizeof(saddr);

    printf("starting sniffing...\n");

    while (true) {
        /* receive a network packet and copy it into buffer */
        state.buflen = recvfrom(sock_raw, buffer, BUFFER_SIZE, 0, &saddr, &saddr_len);
        
        fflush(state.log_file);
        process_data(&state);
    }

    close(sock_raw);
    printf("finished sniffing\n");
}
