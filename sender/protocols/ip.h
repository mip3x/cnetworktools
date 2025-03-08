#ifndef IP_H
#define IP_H

#include "../core/status.h"
#include "../core/state.h"

#define ID_VALUE 10201

enum status get_ip_addr(struct state* state);
enum status construct_ip_header(struct state* state);

#endif
