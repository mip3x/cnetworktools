#ifndef PROTO_H
#define PROTO_H

#include "../core/state.h"
#include "../payload/payload.h"

#define IP_FRAGMENT_OFFSET_MASK 0x1fff
#define IP_MF_MASK 0x01

#define ICMP 1

#define TCP 6
#define UDP 17

/* L2 */
void process_ethernet_header(struct state state);

/* L3 */
void process_ip_header(struct state state);
void process_icmp_header(struct state state);

/* L4 */
void process_tcp_header(struct state state);
void process_udp_header(struct state state);

#endif
