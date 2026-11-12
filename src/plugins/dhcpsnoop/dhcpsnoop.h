/* SPDX-License-Identifier: Apache-2.0 */

/*
 * dhcpsnoop.h — mighty_lb DHCP Snooping, VPP mode (network mode l2):
 * copies the DHCP frames the L2 bridge forwards to etad (eta/etad
 * dhcp_snoop, the device table behind Device Inventory) through the memif
 * etad already reads, and — Rogue DHCP Server Blocking — drops the replies
 * of DHCP servers that are not trusted. See node.c's package doc comment
 * for the packet path; the Kernel/XDP mode counterpart is
 * ebpf/xdp_bridge/kern/xdp_bridge.c's dhcp_stage, and both must behave the
 * same.
 */

#ifndef __included_dhcpsnoop_h__
#define __included_dhcpsnoop_h__

#include <vlib/vlib.h>
#include <vnet/vnet.h>

#define DHCPSNOOP_PORT_SERVER 67
#define DHCPSNOOP_PORT_CLIENT 68
#define DHCPSNOOP_BOOTREPLY   2
/* trusted servers: virtserver cmd.InventoryMaxTrusted (xdp_bridge's
 * DHCP_TRUSTED_MAX) */
#define DHCPSNOOP_MAX_TRUSTED 64
#define DHCPSNOOP_MIN_BURST   16

/* Header put in front of every copied frame — the shared memif's framing
 * (eta.h's eta_frame_hdr_t layout); etad's memif_source.cc tells the users
 * apart by the magic. Host byte order. */
#define DHCPSNOOP_FRAME_MAGIC	  0x31434844 /* "DHC1" */
#define DHCPSNOOP_FRAME_F_WAN	  0x1	     /* received on the WAN-role port */
#define DHCPSNOOP_FRAME_F_DROPPED 0x2	     /* dropped as a rogue server's reply */
typedef struct
{
  u32 magic;
  u32 sw_if_index; /* interface the frame was received on */
  u32 flags;	   /* DHCPSNOOP_FRAME_F_* (etad dhcp_snoop.h DHCP_FRAME_*) */
  u32 reserved;
} dhcpsnoop_frame_hdr_t;

typedef enum
{
  DHCPSNOOP_ROLE_NONE = 0,
  DHCPSNOOP_ROLE_WAN,
  DHCPSNOOP_ROLE_LAN,
} dhcpsnoop_role_t;

/* Per-thread token bucket for the copies. */
typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  f64 tokens;
  f64 last;
} dhcpsnoop_per_thread_t;

/* Counters (simple counters, index DHCPSNOOP_CNT_*) — "show dhcpsnoop",
 * read by virtserver (inventory) like xdp_bridge's stats 60-63. */
enum
{
  DHCPSNOOP_CNT_COPIED,	      /* frames copied to the output */
  DHCPSNOOP_CNT_RATE_LIMITED, /* not copied: over the rate */
  DHCPSNOOP_CNT_NO_BUFFER,    /* not copied: no buffer */
  DHCPSNOOP_CNT_ROGUE_DROPPED, /* replies of untrusted servers dropped */
  DHCPSNOOP_N_CNT,
};

typedef struct
{
  int capture;		  /* copy DHCP frames to output_sw_if_index */
  int guard;		  /* Rogue DHCP Server Blocking */
  u32 output_sw_if_index; /* the memif etad reads */
  u32 rate;		  /* frames/s for the whole box, 0 = unlimited */
  u32 burst_total;	  /* token bucket depth for the whole box */
  f64 rate_per_thread;
  f64 burst;

  /* trusted DHCP servers / relay agents, IPv4 network order. Changed only
   * by the CLI (worker barrier held), read only for BOOTREPLYs. */
  u32 trusted[DHCPSNOOP_MAX_TRUSTED];
  u32 n_trusted;

  u8 *role_by_sw_if_index;	 /* dhcpsnoop_role_t */
  u8 *feature_on_by_sw_if_index; /* l2-input-ip4 feature attached */
  dhcpsnoop_per_thread_t *per_thread;

  vlib_simple_counter_main_t counters[DHCPSNOOP_N_CNT];

  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} dhcpsnoop_main_t;

extern dhcpsnoop_main_t dhcpsnoop_main;
extern vlib_node_registration_t dhcpsnoop_node;

#endif /* __included_dhcpsnoop_h__ */
