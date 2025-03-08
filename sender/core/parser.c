#include <stdio.h>
#include <string.h>

#include "parser.h"
#include "../protocols/mac_utils.h"

enum status parse_config(const char* const file_name, struct state* state) {
    FILE* file = fopen(file_name, "r");
    if (!file) return ERROR;

    char line[MAX_LINE_LENGTH];
    while (fgets(line, sizeof(line), file) != NULL) {
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == NEW_LINE_SYMBOL) line[len - 1] = EOF_SYMBOL;

        char* delimiter = strchr(line, DELIMITER_SYMBOL);
        if (!delimiter) continue;

        *delimiter = EOF_SYMBOL;
        char* key = line;
        char* value = delimiter + 1;

        while (*value == SPACE_SYMBOL || *value == TAB_SYMBOL) value++;

        if (strcmp(key, INTERFACE_NAME_KEY) == 0)
            state->interface_name = strdup(value);
        else if (strcmp(key, DEST_MAC_ADDR_KEY) == 0) {
            if (parse_mac_addr(state, value) == ERROR) {
                printf("error in parsing mac address\n");
                return ERROR;
            }
            printf("Destination ");
            print_mac_addr(state->dest_mac_addr);
        }
    }

    fclose(file);
    return OK;
}
