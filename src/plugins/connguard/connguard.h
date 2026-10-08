/* SPDX-License-Identifier: Apache-2.0 */

/*
 * connguard.h — mighty_xddos Application Filter (VPP mode): shared state
 * and control-plane API. See node.c's package doc comment for the packet
 * path and connguard.c's for the once-a-second scan; the Kernel/XDP mode
 * counterpart is ebpf/xdp_bridge (kern/xdp_bridge.c's
 * app_filter_config_map + xdp_bridge_daemon.c's app_filter_thread) and
 * both must behave the same.
 */

#ifndef __included_connguard_h__
#define __included_connguard_h__

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vppinfra/bihash_8_8.h>

/* Sizes — must match ebpf/xdp_bridge (APP_FILTER_*). */
#define CONNGUARD_MAX_SERVERS 64
#define CONNGUARD_MAX_PORTS   16   /* per server */
/* conns[]/halfopen[] slot counts: defaults, and the range
 * `connguard config conn-slots|halfopen-slots` accepts (virtserver sizes
 * them from the link speed or the admin's value, like Kernel mode's
 * tables — see virtserver/cmd/xdp_table_sizes.go). */
#define CONNGUARD_CONN_SLOTS_DEFAULT     262144
#define CONNGUARD_HALFOPEN_SLOTS_DEFAULT 131072
#define CONNGUARD_SLOTS_MIN 1024
#define CONNGUARD_SLOTS_MAX (16 * 1024 * 1024)
/* The scan's aggregation table: a power of 2 of at least this many slots
 * per conns[] slot. */
#define CONNGUARD_AGG_PER_CONN 4
/* Aggregation entries one connection can create: (source, service) and
 * (source, server). */
#define CONNGUARD_AGG_USED_PER_CONN 2
#define CONNGUARD_DEDUP_SLOTS 8192
#define CONNGUARD_DEDUP_NS      (10ULL * 1000000000ULL) /* per-source limit report hold */
#define CONNGUARD_SYN_STALE_NS  (10ULL * 1000000000ULL) /* unanswered SYN stops counting */
#define CONNGUARD_KILLED_KEEP_NS (30ULL * 1000000000ULL) /* keep dropping a reset connection */
#define CONNGUARD_EVENT_RING  1024
#define CONNGUARD_EVENTS_PER_READ 256
#define CONNGUARD_TOP_N       8

/* Connection states / flags — same values as kern/xdp_bridge.c. 0 = free
 * slot (the XDP side has no free state: its LRU map just has no entry). */
#define CONNGUARD_FREE   0
#define CONNGUARD_SYN    1 /* unused since the half-open table */
#define CONNGUARD_EST    2
#define CONNGUARD_CLOSED 3
#define CONNGUARD_KILLED 4

#define CONNGUARD_F_CLIENT_DATA 0x01
#define CONNGUARD_F_REPORTED    0x02

typedef enum
{
  CONNGUARD_ROLE_NONE = 0,
  CONNGUARD_ROLE_WAN,
  CONNGUARD_ROLE_LAN,
} connguard_role_t;

enum
{
  CONNGUARD_MODE_MONITOR = 0,
  CONNGUARD_MODE_RESET = 1,
};

enum
{
  CONNGUARD_R_SLOW_REQUEST,
  CONNGUARD_R_SILENT_HOLD,
  CONNGUARD_R_SLOW_READ,
  CONNGUARD_R_CONN_LIMIT,
  CONNGUARD_R_CONN_RATE,
  CONNGUARD_R_COUNT,
};

enum
{
  CONNGUARD_A_MONITOR,
  CONNGUARD_A_RESET,
  CONNGUARD_A_RESET_FAILED,
  CONNGUARD_A_REPORT,
};

/* One tracked connection: exactly one cache line, so a slot pair is two
 * aligned lines (the table is cache-line aligned and pairs start at even
 * slots) — node.c prefetches both per packet. IPs in network byte order,
 * ports and rcv_nxt in host byte order. Field meanings are those of
 * kern/xdp_bridge.c's struct app_conn; what only a reset needs is kept
 * apart in connguard_conn_cold_t. */
typedef struct
{
  u32 client_ip;
  u32 server_ip;
  u16 client_port;
  u16 server_port;
  u8 state;
  u8 flags;
  u8 server_idx;
  u8 pad;
  u32 rcv_nxt;
  u32 wait_bytes;
  u32 wait_segs;
  u32 pad2;
  u64 start_ns;
  u64 wait_start_ns;
  u64 zero_win_ns;
  u64 pad3;
} connguard_conn_t;

STATIC_ASSERT_SIZEOF (connguard_conn_t, CLIB_CACHE_LINE_BYTES);

/* The rest of a conns[] slot, at the same index in conns_cold[]: written
 * once when the connection is tracked, read only to send a reset.
 * server_sw_if_index is the LAN interface the server is behind (where the
 * client's packets are transmitted — and where a reset goes). */
typedef struct
{
  u32 server_sw_if_index;
  u8 dst_mac[6];
  u8 src_mac[6];
} connguard_conn_cold_t;

/* A handshake in progress (client SYN seen) — see node.c's package doc
 * comment. Same 4-tuple form as connguard_conn_t. */
typedef struct
{
  u32 client_ip;
  u32 server_ip;
  u16 client_port;
  u16 server_port;
  u8 used;
  u8 synacked; /* the server answered with a SYN-ACK */
  u16 pad;
  u32 rcv_nxt; /* client ISN + 1 */
  u32 server_sw_if_index;
  u64 start_ns;
  u8 dst_mac[6];
  u8 src_mac[6];
} connguard_halfopen_t;

typedef struct
{
  u64 syn;
  u64 synack;
  u64 rst;
} connguard_health_t;

typedef struct
{
  u64 seq;
  i64 ts; /* unix seconds */
  u32 client, server;
  u16 port;
  u8 reason, action;
  u32 value;
} connguard_event_t;

typedef struct
{
  u32 ip;
  u32 news;
} connguard_top_t;

typedef struct
{
  u32 ip;
  u32 active;
  u32 news;
  int ntop;
  connguard_top_t top[CONNGUARD_TOP_N];
} connguard_server_snap_t;

typedef struct
{
  int guard_enabled;
  int mode;
  int req_timeout_sec;
  int req_min_rate;
  int silent_timeout_sec;
  int read_timeout_sec;
  int max_conn;
  int max_rate;
} connguard_settings_t;

typedef struct
{
  /* Datapath recording on (Guard and/or Health). The nodes are attached
   * to the LAN-role interfaces only while this is set. */
  volatile u32 enabled;
  connguard_settings_t s;

  /* Per sw_if_index: connguard_role_t, and whether this plugin's two
   * features are currently attached there. */
  u8 *role_by_sw_if_index;
  u8 *feature_on_by_sw_if_index;

  /* {server_ip, port} -> server index. key = (server_ip << 32) | port. */
  clib_bihash_8_8_t svc_table;
  /* svc_port_bitmap: bit p set = some protected server has port p — a
   * superset of svc_table's ports, tested before it so a TCP packet whose
   * service-side port no server protects (a LAN client's ephemeral port,
   * an unprotected service) skips the bihash. Changed only by the
   * `connguard service` CLI, with the workers stopped. */
  u64 svc_port_bitmap[65536 / 64];
  u32 servers[CONNGUARD_MAX_SERVERS];
  u32 n_servers;

  /* conns: n_conn_slots slots, 2-way set associative (see node.c's
   * connguard_slot_find), written by the worker threads without locks and
   * read by the scan process. */
  connguard_conn_t *conns;
  connguard_conn_cold_t *conns_cold;

  /* halfopen: n_halfopen_slots slots, same 2-way design — client SYNs
   * wait here until the handshake completes, so a spoofed-source SYN
   * flood never pushes tracked connections out of conns[]. */
  connguard_halfopen_t *halfopen;

  /* Slot counts (even) and the aggregation table's (power of 2). Changed
   * only by the CLI, with the workers stopped; tables_epoch counts those
   * changes so a scan that suspended meanwhile stops. */
  u32 n_conn_slots;
  u32 n_halfopen_slots;
  u32 n_agg_slots;
  u32 tables_epoch;

  /* health[thread_index * CONNGUARD_MAX_SERVERS + server_idx] */
  connguard_health_t *health;
  u32 n_threads;

  /* Scan-process state (main thread only). */
  void *agg;
  /* agg_used: the agg slots this scan filled, in the order it filled
   * them (n_agg_used of them) — the second pass walks only these instead
   * of every slot. A connection fills at most 2 slots, so
   * CONNGUARD_AGG_USED_PER_CONN per conns[] slot always suffices. */
  u32 *agg_used;
  u32 n_agg_used;
  void *dedup;
  u32 agg_gen;
  u64 prev_scan_ns;
  u32 tracked;
  u64 interval_ms;
  connguard_server_snap_t snap[CONNGUARD_MAX_SERVERS];
  u32 n_snap;

  connguard_event_t events[CONNGUARD_EVENT_RING];
  u64 event_seq;
  u64 detected[CONNGUARD_R_COUNT];
  u64 reset_total;
  u64 reset_failed;
  u32 rand_seed;

  /* Client packets dropped because their connection was reset — per
   * thread, summed by the CLI. */
  vlib_simple_counter_main_t dropped_counters;

  u8 initialized;

  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} connguard_main_t;

extern connguard_main_t connguard_main;

extern vlib_node_registration_t connguard_in_node;
extern vlib_node_registration_t connguard_out_node;

void connguard_ensure_init (void);

/* connguard_now_ns: the clock every conns[] timestamp uses. vlib_time_now
 * is kept in step across worker threads by VPP itself. */
static_always_inline u64
connguard_now_ns (vlib_main_t *vm)
{
  return (u64) (vlib_time_now (vm) * 1e9);
}

static_always_inline u32
connguard_hash3 (u32 a, u32 b, u32 c)
{
  u64 h = (u64) a * 0x9E3779B97F4A7C15ULL;
  h ^= (u64) b * 0xC2B2AE3D27D4EB4FULL;
  h ^= (u64) c * 0x165667B19E3779F9ULL;
  return (u32) (h ^ (h >> 29));
}

/* The even slot of a connection's pair (base, base+1) in a table of
 * n_slots slots (even, >= 2) — the same hash and slot choice as
 * kern/xdp_bridge.c's app_ho_base. */
static_always_inline u32
connguard_pair_base (u32 n_slots, u32 client_ip, u32 server_ip,
		     u16 client_port, u16 server_port)
{
  return (connguard_hash3 (client_ip, server_ip,
			   ((u32) client_port << 16) | server_port) %
	  (n_slots / 2)) *
	 2;
}

static_always_inline u32
connguard_slot_base (connguard_main_t *cm, u32 client_ip, u32 server_ip,
		     u16 client_port, u16 server_port)
{
  return connguard_pair_base (cm->n_conn_slots, client_ip, server_ip,
			      client_port, server_port);
}

static_always_inline u32
connguard_halfopen_base (connguard_main_t *cm, u32 client_ip, u32 server_ip,
			 u16 client_port, u16 server_port)
{
  return connguard_pair_base (cm->n_halfopen_slots, client_ip, server_ip,
			      client_port, server_port);
}

#endif /* __included_connguard_h__ */
