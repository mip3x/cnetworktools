#ifndef PROTOCOLS_H
#define PROTOCOLS_H

#include "../core/state.h"
#include "../core/status.h"

// L2
enum status get_eth_index(struct state);
enum status get_mac_addr(struct state);

// L3
enum status get_ip_addr(struct state);

#endif
