#ifndef MAC_UTILS_H
#define MAC_UTILS_H

#include "../core/mac.h"
#include "../core/state.h"
#include "../core/status.h"

void print_mac_addr(mac addr);
enum status get_src_mac_addr(struct state* state);
enum status parse_mac_addr(struct state* state, const char* const string_to_parse);

#endif
