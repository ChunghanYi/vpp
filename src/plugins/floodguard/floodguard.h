/* SPDX-License-Identifier: Apache-2.0 */

/*
 * floodguard.h — mighty_xddos Flood Guard (VPP mode): Broadcast Filter
 * storm policing, SYN/UDP/ICMP-flood victim policing and the SYN Reset
 * Challenge, replacing the earlier policer classify chain and synchallenge
 * plugin (see node.c's package doc comment). Broadcast Filter storm
 * policing uses the policer plugin's own policer objects, looked up by
 * name; victim flood limiting uses this plugin's own token buckets, one
 * per (victim, flood type, worker), so victims never share a bucket and
 * workers never contend for one.
 */

#ifndef __included_floodguard_h__
#define __included_floodguard_h__

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vppinfra/bihash_8_8.h>
#include <policer/policer.h>

#define FLOODGUARD_VICTIM_BUCKETS 1024
#define FLOODGUARD_VICTIM_MEMORY  (4 << 20)

/* SYN Reset Challenge whitelist (verified client IPv4s). bihash_8_8
 * allocates from the main heap (BIHASH_USE_HEAP) with no memory bound of
 * its own, so the entry count is capped instead (challenge_whitelist_max,
 * set by virtserver from the link speed: "floodguard syn-challenge
 * whitelist-size <n>"); the table gets one bucket per two entries. */
#define FLOODGUARD_CHALLENGE_DEFAULT_WHITELIST_MAX 65536
#define FLOODGUARD_CHALLENGE_WHITELIST_MIN	   1024
#define FLOODGUARD_CHALLENGE_WHITELIST_MAX	   (16 << 20)
/* Challenge cookie time slot: a RST is accepted for the cookie of the
 * current or the previous slot, i.e. 8-16s after the challenge. */
#define FLOODGUARD_CHALLENGE_COOKIE_SLOT_SEC 8
/* Verified-client TTL until virtserver sets one (its own default). */
#define FLOODGUARD_CHALLENGE_DEFAULT_WHITELIST_TTL_SEC 300

/* What a packet was classified as — also the drop counter index. The
 * Broadcast Filter kinds are checked in the policer classify chain's own
 * order (ARP, L2 broadcast, L2 control, L2 multicast), then the flood
 * kinds. SYN_CHALLENGE counts what the challenge drops: unverified RSTs
 * and SYNs from a source that can never answer. */
typedef enum
{
  FLOODGUARD_KIND_NONE = 0,
  FLOODGUARD_KIND_ARP,
  FLOODGUARD_KIND_BROADCAST,
  FLOODGUARD_KIND_CTRL,
  FLOODGUARD_KIND_MULTICAST,
  FLOODGUARD_KIND_SYN,
  FLOODGUARD_KIND_UDP,
  FLOODGUARD_KIND_ICMP,
  FLOODGUARD_KIND_SYN_CHALLENGE,
  FLOODGUARD_KIND_IPV6, /* transit IPv6 (floodguard_if_t.ip6_drop) */
  FLOODGUARD_N_KIND,
} floodguard_kind_t;

#define FLOODGUARD_N_L2_KIND 4 /* ARP .. MULTICAST */
#define FLOODGUARD_N_FLOOD   3 /* SYN, UDP, ICMP (policed) */

/* Victim table value: one bit per armed flood type plus the destination
 * port it is limited to (0 = every port), the same "one session per type,
 * wildcard or port-scoped" model as the classify tables, and the victim's
 * floodguard_victim_t pool index. SYN_CHALLENGE is victim-wide: the WAN
 * Service Port ACL ahead of the victim node already keeps closed ports
 * away from it. */
#define FLOODGUARD_V_SYN	   (1ULL << 32)
#define FLOODGUARD_V_UDP	   (1ULL << 33)
#define FLOODGUARD_V_ICMP	   (1ULL << 34)
#define FLOODGUARD_V_SYN_CHALLENGE (1ULL << 35)
#define FLOODGUARD_V_ANY                                                      \
  (FLOODGUARD_V_SYN | FLOODGUARD_V_UDP | FLOODGUARD_V_ICMP |                  \
   FLOODGUARD_V_SYN_CHALLENGE)
#define FLOODGUARD_V_SYN_PORT(v) ((u16) ((v) >> 16))
#define FLOODGUARD_V_UDP_PORT(v) ((u16) (v))
#define FLOODGUARD_V_INDEX_SHIFT 40
#define FLOODGUARD_V_INDEX(v)	 ((u32) ((v) >> FLOODGUARD_V_INDEX_SHIFT))
#define FLOODGUARD_V_MAX_INDEX	 ((1U << (64 - FLOODGUARD_V_INDEX_SHIFT)) - 1)

/* Feature arcs a node is attached to on an interface (floodguard_if_t.arcs):
 * the storm node on each L2 input arc, and the victim node on the IPv4 one. */
#define FLOODGUARD_ARC_STORM_IP4   (1 << 0)
#define FLOODGUARD_ARC_STORM_IP6   (1 << 1)
#define FLOODGUARD_ARC_STORM_NONIP (1 << 2)
#define FLOODGUARD_ARC_VICTIM	   (1 << 3)

/* Per-interface state. policer: Broadcast Filter policers, indexed by
 * kind - 1 (~0 = none). enabled: storm/victim policing ("interface ...
 * enable"). ip6_drop: every IPv6 frame entering the bridge on this
 * interface is dropped — the product never forwards IPv6 ("interface ...
 * ip6-drop enable"), set independently of enabled so a port out of the
 * Policy binding scope keeps it. arcs is what those two need attached. */
typedef struct
{
  u32 policer[FLOODGUARD_N_L2_KIND];
  u8 enabled;
  u8 ip6_drop;
  u8 arcs; /* FLOODGUARD_ARC_* currently attached; 0 = none */
} floodguard_if_t;

/* Victim flood token bucket, used by one worker only (no lock). */
typedef struct
{
  u64 tokens;
  u64 last_tick; /* clib_cpu_time_now () */
} floodguard_bucket_t;

/* One worker's buckets for one victim, a cache line of its own. */
typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  floodguard_bucket_t bucket[FLOODGUARD_N_FLOOD];
} floodguard_victim_thread_t;

/* Victim record (floodguard_main_t.victim_pool): per-worker buckets,
 * indexed by thread index. */
typedef struct
{
  floodguard_victim_thread_t *threads;
} floodguard_victim_t;

/* Flood limit of one type (floodguard_main_t.flood). rate_pps/burst are
 * the whole box's limit ("floodguard flood ... rate <pps> burst <n>",
 * rate 0 = not limited); each of n_share_threads workers gets an equal
 * share (floodguard_flood_share), recomputed by the main thread only when
 * the limit or the share count changes. Workers read the share fields without a lock: each is a
 * single aligned u64 store, and a packet that sees the old share of one
 * field and the new share of another while it changes is harmless. */
typedef struct
{
  u32 rate_pps;
  u32 burst;
  u64 ticks_per_token; /* per worker; 0 = not limited */
  u64 burst_per_thread;
  u64 fill_ticks; /* ticks to refill a worker's whole bucket */
} floodguard_flood_t;

/* Flood limit counters (floodguard_main_t.flood_counters/victim_counters). */
typedef enum
{
  FLOODGUARD_FLOOD_CONFORM, /* within the limit, forwarded */
  FLOODGUARD_FLOOD_VIOLATE, /* over the limit, dropped */
  FLOODGUARD_N_FLOOD_COUNTER,
} floodguard_flood_counter_t;

/* SYN Reset Challenge counters (floodguard_main_t.challenge_counters). */
typedef enum
{
  FLOODGUARD_CHALLENGE_CHALLENGED, /* SYN-ACK reflected to an unverified source */
  FLOODGUARD_CHALLENGE_VERIFIED,   /* RST matched, source whitelisted */
  FLOODGUARD_CHALLENGE_PERMITTED,  /* verified source's SYN passed */
  FLOODGUARD_CHALLENGE_WHITELIST_FULL, /* RST matched, whitelist at its cap */
  FLOODGUARD_CHALLENGE_SWEPT_WHITELIST,
  FLOODGUARD_N_CHALLENGE_COUNTER,
} floodguard_challenge_counter_t;

typedef struct
{
  floodguard_if_t *ifs; /* by sw_if_index */

  /* Victim dst IPv4 (network order, zero-extended) -> FLOODGUARD_V_* value. */
  clib_bihash_8_8_t victims;
  u32 n_victims;
  floodguard_victim_t *victim_pool;

  /* Victim flood limits: SYN, UDP, ICMP. n_share_threads: the number of
   * shares each limit is split into — the workers polling the rx queues of
   * the interfaces the victim node is on, set by virtserver from the rx
   * placement ("floodguard flood share <n>", ddos/floodguard_vpp.go);
   * every worker until then (the strict side). */
  floodguard_flood_t flood[FLOODGUARD_N_FLOOD];
  u32 n_share_threads;

  /* SYN Reset Challenge. Stateless per challenge: the SYN-ACK's ack is a
   * SipHash-2-4 cookie of the 4-tuple and time slot under cookie_key
   * (random, generated at init; cookie_key_ready = 0 turns the challenge
   * off). whitelist: verified client IPv4 -> expiry (seconds, vlib time),
   * created on the first challenge victim with challenge_whitelist_buckets
   * buckets, holding at most challenge_whitelist_max entries
   * (n_whitelist, updated atomically by the workers). */
  u64 cookie_key[2];
  u8 cookie_key_ready;
  clib_bihash_8_8_t challenge_whitelist;
  u8 challenge_tables_ready;
  u32 challenge_whitelist_buckets;
  u32 challenge_whitelist_max;
  volatile u32 n_whitelist;
  u32 challenge_whitelist_ttl_sec;

  /* The policer plugin's state, resolved on first use through its
   * exported accessors (policer.h). */
  policer_main_t *pm;
  vlib_combined_counter_main_t *policer_counters;

  vlib_simple_counter_main_t drop_counters[FLOODGUARD_N_KIND];
  vlib_simple_counter_main_t challenge_counters[FLOODGUARD_N_CHALLENGE_COUNTER];
  /* Flood limit counters: whole box (index 0) and per victim (by pool
   * index; a victim armed with the SYN Reset Challenge counts permitted
   * SYNs as SYN conform and challenged ones as SYN violate). */
  vlib_simple_counter_main_t flood_counters[FLOODGUARD_N_FLOOD]
					   [FLOODGUARD_N_FLOOD_COUNTER];
  vlib_simple_counter_main_t victim_counters[FLOODGUARD_N_FLOOD]
					    [FLOODGUARD_N_FLOOD_COUNTER];

  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} floodguard_main_t;

extern floodguard_main_t floodguard_main;
extern vlib_node_registration_t floodguard_l2_ip4_node;
extern vlib_node_registration_t floodguard_l2_ip6_node;
extern vlib_node_registration_t floodguard_l2_nonip_node;
extern vlib_node_registration_t floodguard_victim_node;

#endif /* __included_floodguard_h__ */
