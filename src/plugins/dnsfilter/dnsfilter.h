/* SPDX-License-Identifier: Apache-2.0 */

/*
 * dnsfilter.h — mighty_lb DNS Sinkhole, VPP mode datapath (network mode
 * l2). The VPP counterpart of xdp_bridge's dnsf_lan_stage /
 * xdp_dnsf_return (ebpf/xdp_bridge/kern/xdp_bridge.c): LAN -> WAN DNS
 * queries are taken out of the bridge and handed to the box's DNS engine
 * (pihole-FTL) through a tap, and its answers are put back on the LAN
 * port the query came from, MACs restored, so the client sees its own
 * resolver answer. See node.c for the packet path and virtserver/dnsf for
 * the control side (the tap's Linux end, nft, policy routing, the engine).
 */

#ifndef __included_dnsfilter_h__
#define __included_dnsfilter_h__

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ethernet/mac_address.h>
#include <vppinfra/bihash_8_8.h>
#include <vppinfra/bihash_8_16.h>

/* Return table: one entry per outstanding query (client ip, port, proto).
 * A UDP entry is removed when its answer goes back; what is left (TCP,
 * unanswered queries) is swept after DNSFILTER_RET_TTL_SEC without a query
 * packet. At DNSFILTER_RET_MAX entries new queries bypass (forwarded
 * unfiltered) instead of evicting. 262,144 covers ~25,000 qps with answers
 * taking up to 10 s — same size as xdp_bridge's dnsf_ret_map. */
#define DNSFILTER_RET_MAX	  262144
#define DNSFILTER_RET_BUCKETS	  (DNSFILTER_RET_MAX / 4)
#define DNSFILTER_RET_MEMORY	  (128 << 20)
#define DNSFILTER_RET_TTL_SEC	  10
/* Per-client rate windows (1 second), swept like the return table. */
#define DNSFILTER_CLIENT_MAX	  65536
#define DNSFILTER_CLIENT_BUCKETS  (DNSFILTER_CLIENT_MAX / 4)
#define DNSFILTER_CLIENT_MEMORY	  (16 << 20)
#define DNSFILTER_CLIENT_TTL_SEC  10
/* DoH server addresses ("dnsfilter doh-ip load <file>"). */
#define DNSFILTER_DOH_MAX	  16384
#define DNSFILTER_DOH_BUCKETS	  4096
#define DNSFILTER_DOH_MEMORY	  (4 << 20)
/* Clients without the per-client limit ("dnsfilter exempt set"): in-house
 * resolvers and NAT devices that speak for many hosts. */
#define DNSFILTER_EXEMPT_MAX	  64
#define DNSFILTER_EXEMPT_BUCKETS  64
#define DNSFILTER_EXEMPT_MEMORY	  (1 << 20)

#define DNSFILTER_SWEEP_INTERVAL 2.0 /* seconds */

/* Counters — the same names and meaning as xdp_bridge's dnsf-status. */
#define foreach_dnsfilter_counter                                             \
  _ (REDIRECTED, "redirected", "query taken to the DNS engine")             \
  _ (RETURNED, "returned", "answer put back on the LAN port")               \
  _ (BYPASS_DAEMON_DOWN, "bypass_daemon_down",                              \
     "query bridged unfiltered: DNS engine not answering")                  \
  _ (BYPASS_GLOBAL_LIMIT, "bypass_global_limit",                            \
     "query bridged unfiltered: over the global limit or table full")       \
  _ (CLIENT_LIMIT_DROPPED, "client_limit_dropped",                          \
     "query dropped: over the per-client limit")                            \
  _ (DOT_DROPPED, "dot_dropped", "DNS over TLS (853) dropped")              \
  _ (DOH_DROPPED, "doh_dropped", "new connection to a DoH server dropped")  \
  _ (RETURN_DROPPED, "return_dropped",                                      \
     "frame from the DNS engine with no client to return to")

typedef enum
{
#define _(sym, name, desc) DNSFILTER_CNT_##sym,
  foreach_dnsfilter_counter
#undef _
    DNSFILTER_N_COUNTER,
} dnsfilter_counter_t;

/* Interface role (dnsfilter_main_t.roles, by sw_if_index). LAN ports run
 * the interception node; the WAN role only tells the node that a
 * destination MAC learned there is "toward the Internet". */
typedef enum
{
  DNSFILTER_ROLE_NONE = 0,
  DNSFILTER_ROLE_LAN,
  DNSFILTER_ROLE_WAN,
} dnsfilter_role_t;

/* Return table value (bihash_8_16): the client's MAC, the MAC it sent the
 * query to (its gateway, the answer's source MAC), the LAN port and the
 * last time a query packet refreshed it (seconds, u16 wraps). */
typedef union
{
  struct
  {
    u8 client_mac[6];
    u8 gw_mac[6];
    u16 sw_if_index; /* LAN port (main interfaces only, < 65536) */
    u16 seen;
  };
  u64 as_u64[2];
} dnsfilter_ret_t;

typedef struct
{
  /* Configuration, written by the CLI (barrier) and read by the workers. */
  u8 intercept;	 /* 53 interception on */
  u8 daemon_ok;	 /* the engine answers (virtserver health check) */
  u8 block_dot;	 /* drop 853 */
  u8 block_doh_ip; /* drop new connections to doh_ips */
  u32 client_qps;	 /* 0 = no limit */
  u32 global_qps;	 /* 0 = no limit */

  u8 *roles; /* dnsfilter_role_t by sw_if_index */
  u32 n_lan; /* interfaces with the interception node */

  /* The tap toward the engine ("dnsfilter tap"): its sw_if_index and the
   * Linux end's MAC (the intercepted frame's new destination). */
  u32 tap_sw_if_index;
  mac_address_t host_mac;

  clib_bihash_8_16_t ret;	/* (client ip, port, proto) -> dnsfilter_ret_t */
  volatile u32 n_ret;
  clib_bihash_8_8_t clients; /* client ip -> (window second << 32) | count */
  volatile u32 n_clients;
  clib_bihash_8_8_t doh_ips; /* IPv4 (network order) -> 1 */
  u32 n_doh_ips;
  clib_bihash_8_8_t exempt; /* client IPv4 (network order) -> 1 */
  u32 n_exempt;

  /* Global rate window (all workers). */
  volatile u32 global_sec;
  volatile u32 global_count;

  vlib_simple_counter_main_t counters[DNSFILTER_N_COUNTER];

  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} dnsfilter_main_t;

extern dnsfilter_main_t dnsfilter_main;
extern vlib_node_registration_t dnsfilter_lan_node;
extern vlib_node_registration_t dnsfilter_return_node;

/* Seconds the datapath counts in (vlib time, truncated). */
always_inline u32
dnsfilter_now_sec (vlib_main_t *vm)
{
  return (u32) vlib_time_now (vm);
}

#endif /* __included_dnsfilter_h__ */
