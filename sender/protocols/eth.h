#ifndef ETH_H
#define ETH_H

#include "../core/status.h"
#include "../core/state.h"

enum status get_eth_index(struct state state);
enum status construct_eth_header(struct state state);

#endif
