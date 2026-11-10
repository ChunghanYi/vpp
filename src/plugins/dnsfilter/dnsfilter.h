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
 *
 * Fast path (docs/dns_filter_l2_bridge_review.md section 11, same as
 * xdp_bridge's dnsf_judge / dnsf_block_reply): with fastpath on, every
 * LAN -> WAN UDP query is first looked up in the block table on the
 * receiving worker and a blocked name is answered right there; only the
 * allowed queries go on — to the engine (intercept on: "Inspect") or
 * unchanged to the client's own resolver. Blocked queries are reported to
 * etad over the memif ETA also uses ("DNF1" frames), and every UDP query
 * is counted per client (Busiest Clients / Active Clients).
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

/* ── Fast path: block table, judgement and answer ──
 * Same hash and bits as virtserver/dnsf/hashlist.go and xdp_bridge
 * (DNSF_CAT_*): FNV-1a 64 over the lowercase name from its last byte to
 * its first; value bits 0-7 the name and its subdomains (bit 6 Deny, bit 7
 * answered NXDOMAIN), bits 8-15 this exact name only, bit 31 Allow. */
#define DNSFILTER_CAT_BITS	0xffU
#define DNSFILTER_CAT_NXDOMAIN	(1U << 7)
#define DNSFILTER_EXACT_SHIFT	8
#define DNSFILTER_CAT_ALLOW	(1U << 31)
#define DNSFILTER_QNAME_MAX	255 /* wire name without the root 0 */
#define DNSFILTER_LOOKUPS_MAX	16  /* suffixes looked up, rightmost first */
#define DNSFILTER_FNV_OFFSET	0xcbf29ce484222325ULL
#define DNSFILTER_FNV_PRIME	0x100000001b3ULL
#define DNSFILTER_EDNS_UDP	1232 /* our OPT's UDP payload size */
/* The block table file (hashlist.go): magic, u32 count, u32 0, then count
 * x {u64 hash, u32 bits, u32 0}, little endian. */
#define DNSFILTER_HASH_MAGIC	"DNSFHL01"
#define DNSFILTER_HASH_HDR	16
#define DNSFILTER_HASH_REC	16

/* Blocked query events: "DNF1" frames on the events interface (the memif
 * shared with ETA, read by etad's memif_source). Same header as eta.h's
 * eta_frame_hdr_t, then a dnsfilter_event_t — the layout of xdp_bridge's
 * struct dnsf_event, but ts_ns is real time (unix ns). At most
 * DNSFILTER_EVENTS_PER_SEC per worker and second (fp_event_lost). */
#define DNSFILTER_FRAME_MAGIC	   0x31464e44 /* "DNF1" */
#define DNSFILTER_EVENT_NAME_MAX   128
#define DNSFILTER_EVENTS_PER_SEC   2000
typedef struct
{
  u32 magic;
  u32 sw_if_index; /* LAN port the query came in on */
  u32 flags;
  u32 reserved;
} dnsfilter_frame_hdr_t;
typedef struct
{
  u64 ts_ns;
  u32 client_ip; /* network order */
  u32 cats;
  u16 qtype;
  u16 name_len;
  u8 name[DNSFILTER_EVENT_NAME_MAX]; /* ".www.example.com" (may be cut) */
} dnsfilter_event_t;

/* Per-client query counts (Busiest Clients / Active Clients): one table
 * per worker, written only by it (no contention); the main thread sums
 * them up ("show dnsfilter clients") and sweeps clients idle for
 * DNSFILTER_ACTIVE_SEC. value[0] total queries, value[1] last second. */
#define DNSFILTER_STATS_BUCKETS	  (DNSFILTER_CLIENT_MAX / 4)
#define DNSFILTER_STATS_MEMORY	  (8 << 20)
#define DNSFILTER_ACTIVE_SEC	  3600
#define DNSFILTER_STATS_SWEEP_SEC 60.0
#define DNSFILTER_TOP_MAX	  64

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
     "frame from the DNS engine with no client to return to")               \
  _ (FP_JUDGED, "fp_judged", "fast path: query looked up")                  \
  _ (FP_BLOCKED, "fp_blocked", "fast path: blocked, answered in place")     \
  _ (FP_NXDOMAIN, "fp_nxdomain",                                            \
     "fast path: blocked, answered NXDOMAIN (no room for the record)")      \
  _ (FP_SKIPPED, "fp_skipped", "fast path: query not judged (format)")      \
  _ (FP_PASSED, "fp_passed",                                                \
     "fast path: allowed, to the client's own resolver (Fast mode)")        \
  _ (FP_EVENT_LOST, "fp_event_lost",                                        \
     "fast path: blocked query not logged (limit, no buffer, no output)")   \
  _ (FP_REPLY_FAILED, "fp_reply_failed",                                    \
     "fast path: blocked query dropped (the answer could not be built)")

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

/* Per-worker state of the fast path. */
typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u32 event_sec;   /* events rate window */
  u32 event_count;
  clib_bihash_8_16_t stats; /* client ip -> {total, last second} */
  volatile u32 n_stats;
} dnsfilter_per_thread_t;

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

  /* Fast path (see the doc comment at the top). block points at the
   * current table (0: none loaded — nothing is judged); a new one is built
   * beside it and swapped in under the worker barrier. */
  u8 fastpath;
  u32 cat_mask;
  u32 block_ttl;
  clib_bihash_8_8_t *volatile block;
  u32 block_entries;
  f64 block_loaded_at; /* unix time */
  u32 events_sw_if_index; /* "DNF1" frames go out here; ~0 = none */
  dnsfilter_per_thread_t *per_thread;
  /* "show dnsfilter clients": totals at the previous (non-peek) reading */
  uword *clients_prev; /* client ip -> total */
  u8 clients_prev_valid;
  f64 stats_swept;

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
