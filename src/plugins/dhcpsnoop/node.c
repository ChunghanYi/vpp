/* SPDX-License-Identifier: Apache-2.0 */

/*
 * node.c — mighty_lb DHCP Snooping (VPP mode) packet path.
 *
 * One node, "dhcpsnoop", on the "l2-input-ip4" arc of the L2 bridge's
 * ports (role wan/lan), attached only while capture or guard is on —
 * otherwise on no packet's path at all. It runs before the input ACL and
 * floodguard, as xdp_bridge runs dhcp_stage ahead of its mitigation
 * stages: every DHCP exchange is seen (and a rogue reply dropped) whatever
 * they decide.
 *
 * The IPv4 header is at l2.l2_len — behind up to two 802.1Q / 802.1ad tags
 * on a VLAN trunk link (the bridge keeps tags; the L2 arc classifies by the
 * ethertype behind them). Per packet, anything that is not IPv4 UDP with
 * both ports in {67, 68} costs a protocol and a port compare.
 *
 * A DHCP frame:
 *   - guard on, a BOOTREPLY (op 2) from UDP 67 whose source address is not
 *     a trusted server (strict: only the listed servers — and relay agents,
 *     which source the relayed reply — on every port): dropped, counted;
 *   - capture on: copied whole (tags included; etad reads up to two) with a
 *     dhcpsnoop_frame_hdr_t in front to the memif, rate limited per thread
 *     (token bucket) — a dropped reply too, flagged, as the evidence of the
 *     rogue server.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/l2/l2_input.h>
#include <vnet/feature/feature.h>

#include <dhcpsnoop/dhcpsnoop.h>

typedef enum
{
  DHCPSNOOP_NEXT_DROP,
  DHCPSNOOP_N_NEXT,
} dhcpsnoop_next_t;

static_always_inline int
dhcpsnoop_trusted (dhcpsnoop_main_t *sm, u32 addr)
{
  u32 i;
  for (i = 0; i < sm->n_trusted; i++)
    if (sm->trusted[i] == addr)
      return 1;
  return 0;
}

static_always_inline int
dhcpsnoop_take_token (dhcpsnoop_main_t *sm, dhcpsnoop_per_thread_t *pt,
		      f64 now)
{
  if (sm->rate == 0)
    return 1;
  pt->tokens += (now - pt->last) * sm->rate_per_thread;
  pt->last = now;
  if (pt->tokens > sm->burst)
    pt->tokens = sm->burst;
  if (pt->tokens < 1)
    return 0;
  pt->tokens -= 1;
  return 1;
}

/* dhcpsnoop_frame: the frame's UDP header when it is an IPv4 UDP datagram
 * with both ports in {67, 68}, else 0. */
static_always_inline udp_header_t *
dhcpsnoop_frame (vlib_buffer_t *b, ip4_header_t **ipp)
{
  u8 *eth = vlib_buffer_get_current (b);
  u8 *end = eth + b->current_length;
  u32 l2 = vnet_buffer (b)->l2.l2_len;
  ip4_header_t *ip = (ip4_header_t *) (eth + l2);

  if (PREDICT_FALSE ((u8 *) (ip + 1) > end) || ip->protocol != IP_PROTOCOL_UDP)
    return 0;
  udp_header_t *udp = (udp_header_t *) ((u8 *) ip + ip4_header_bytes (ip));
  if ((u8 *) (udp + 1) > end)
    return 0;
  u16 sp = clib_net_to_host_u16 (udp->src_port);
  u16 dp = clib_net_to_host_u16 (udp->dst_port);
  if ((sp != DHCPSNOOP_PORT_SERVER && sp != DHCPSNOOP_PORT_CLIENT) ||
      (dp != DHCPSNOOP_PORT_SERVER && dp != DHCPSNOOP_PORT_CLIENT))
    return 0;
  *ipp = ip;
  return udp;
}

/* dhcpsnoop_slow: one DHCP frame (rare) — the guard and the copy, out of
 * line so the per-packet loop stays small. Returns 1 to drop it. */
static never_inline int
dhcpsnoop_slow (vlib_main_t *vm, dhcpsnoop_main_t *sm,
		dhcpsnoop_per_thread_t *pt, vlib_buffer_t *b, ip4_header_t *ip,
		udp_header_t *udp, u32 *copies, u32 *n_copies, u32 *n_limited,
		u32 *n_no_buffer, u32 *n_rogue)
{
  u8 *end = (u8 *) vlib_buffer_get_current (b) + b->current_length;
  u8 *op = (u8 *) (udp + 1);
  int drop = 0;

  if (sm->guard &&
      udp->src_port == clib_host_to_net_u16 (DHCPSNOOP_PORT_SERVER) &&
      op < end && *op == DHCPSNOOP_BOOTREPLY &&
      !dhcpsnoop_trusted (sm, ip->src_address.as_u32))
    {
      drop = 1;
      (*n_rogue)++;
    }
  if (!sm->capture)
    return drop;
  if (!dhcpsnoop_take_token (sm, pt, vlib_time_now (vm)))
    {
      (*n_limited)++;
      return drop;
    }
  vlib_buffer_t *c = vlib_buffer_copy (vm, b);
  if (PREDICT_FALSE (c == 0))
    {
      (*n_no_buffer)++;
      return drop;
    }
  u32 rx = vnet_buffer (b)->sw_if_index[VLIB_RX];
  int wan = rx < vec_len (sm->role_by_sw_if_index) &&
	    sm->role_by_sw_if_index[rx] == DHCPSNOOP_ROLE_WAN;
  dhcpsnoop_frame_hdr_t *h;
  vlib_buffer_advance (c, -(word) sizeof (*h));
  h = vlib_buffer_get_current (c);
  h->magic = DHCPSNOOP_FRAME_MAGIC;
  h->sw_if_index = rx;
  h->flags = (wan ? DHCPSNOOP_FRAME_F_WAN : 0) |
	     (drop ? DHCPSNOOP_FRAME_F_DROPPED : 0);
  h->reserved = 0;
  vnet_buffer (c)->sw_if_index[VLIB_TX] = sm->output_sw_if_index;
  copies[(*n_copies)++] = vlib_get_buffer_index (vm, c);
  return drop;
}

VLIB_NODE_FN (dhcpsnoop_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  dhcpsnoop_main_t *sm = &dhcpsnoop_main;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  u32 copies[VLIB_FRAME_SIZE];
  u32 n_copies = 0, n_limited = 0, n_no_buffer = 0, n_rogue = 0;
  u32 thread_index = vm->thread_index;
  dhcpsnoop_per_thread_t *pt = vec_elt_at_index (sm->per_thread, thread_index);
  int active = sm->capture || sm->guard;

  vlib_get_buffers (vm, from, bufs, n_left);

  while (n_left > 0)
    {
      ip4_header_t *ip = 0;
      udp_header_t *udp;

      if (n_left > 2)
	{
	  vlib_prefetch_buffer_header (b[2], LOAD);
	  CLIB_PREFETCH (vlib_buffer_get_current (b[2]), CLIB_CACHE_LINE_BYTES,
			 LOAD);
	}
      vnet_feature_next_u16 (next, b[0]);
      if (PREDICT_TRUE (active) && PREDICT_FALSE ((udp = dhcpsnoop_frame (b[0], &ip)) != 0) &&
	  dhcpsnoop_slow (vm, sm, pt, b[0], ip, udp, copies, &n_copies,
			  &n_limited, &n_no_buffer, &n_rogue))
	next[0] = DHCPSNOOP_NEXT_DROP;
      b++;
      next++;
      n_left--;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  if (n_copies)
    {
      vnet_hw_interface_t *hw =
	vnet_get_sup_hw_interface (sm->vnet_main, sm->output_sw_if_index);
      vlib_frame_t *f = vlib_get_frame_to_node (vm, hw->output_node_index);
      clib_memcpy_fast (vlib_frame_vector_args (f), copies,
			n_copies * sizeof (u32));
      f->n_vectors = n_copies;
      vlib_put_frame_to_node (vm, hw->output_node_index, f);
      vlib_increment_simple_counter (&sm->counters[DHCPSNOOP_CNT_COPIED],
				     thread_index, 0, n_copies);
    }
  if (n_limited)
    vlib_increment_simple_counter (&sm->counters[DHCPSNOOP_CNT_RATE_LIMITED],
				   thread_index, 0, n_limited);
  if (n_no_buffer)
    vlib_increment_simple_counter (&sm->counters[DHCPSNOOP_CNT_NO_BUFFER],
				   thread_index, 0, n_no_buffer);
  if (n_rogue)
    vlib_increment_simple_counter (&sm->counters[DHCPSNOOP_CNT_ROGUE_DROPPED],
				   thread_index, 0, n_rogue);
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (dhcpsnoop_node) = {
  .name = "dhcpsnoop",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = DHCPSNOOP_N_NEXT,
  .next_nodes = { [DHCPSNOOP_NEXT_DROP] = "error-drop" },
};

/* Ahead of the input ACL (WAN policy, attacker blocklist) and floodguard:
 * xdp_bridge's dhcp_stage runs ahead of its mitigation stages too. */
VNET_FEATURE_INIT (dhcpsnoop_feature, static) = {
  .arc_name = "l2-input-ip4",
  .node_name = "dhcpsnoop",
  .runs_before = VNET_FEATURES ("acl-plugin-in-ip4-l2", "floodguard-l2-ip4",
				"l2-input-feat-arc-end"),
};
