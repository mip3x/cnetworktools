#ifndef PARSER_H
#define PARSER_H

#include "state.h"
#include "status.h"

#define MAX_LINE_LENGTH 256
#define SPACE_SYMBOL ' '
#define TAB_SYMBOL '\t'
#define EOF_SYMBOL '\0'
#define NEW_LINE_SYMBOL '\n'
#define DELIMITER_SYMBOL ':'

#define INTERFACE_NAME_KEY "interface_name"
#define DEST_MAC_ADDR_KEY "dest_mac_addr"

enum status parse_config(const char* const file_name, struct state* state);

#endif
