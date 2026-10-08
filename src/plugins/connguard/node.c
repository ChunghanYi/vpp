/* SPDX-License-Identifier: Apache-2.0 */

/*
 * node.c — mighty_xddos Application Filter (VPP mode) packet path: records
 * the TCP connections of admin-listed protected services (server IP +
 * port) so connguard.c's once-a-second scan can find slow
 * application-layer attacks (Slowloris, slow POST, slow read, idle
 * connection holding) per connection, and counts each protected server's
 * SYN / SYN-ACK / RST exchanged with WAN-side clients for Server Health
 * Detection. VPP counterpart of
 * ebpf/xdp_bridge/kern/xdp_bridge.c's app_filter_track — same recorded
 * fields, same meaning, see that function's map doc comment.
 *
 * Two nodes, attached ONLY to LAN-role interfaces (servers are on the LAN
 * side, clients on the WAN side) and only while the feature is enabled —
 * disabled, neither node is on any packet's path at all:
 *
 *   connguard-out  ("interface-output" arc of a LAN interface): client →
 *                  server packets that arrived on a WAN-role interface, at
 *                  the moment they are actually transmitted to the server.
 *                  Running on the output side, after the ACL / classify /
 *                  policer stages, means a SYN those stages dropped is
 *                  never counted — it never reached the server, so it
 *                  must not lower the server's SYN-ACK response ratio.
 *                  Client packets of a connection the scan has reset are
 *                  dropped here.
 *   connguard-in   ("device-input" arc of a LAN interface): server →
 *                  client packets (SYN-ACK, RST, FIN, data).
 *
 * WAN interfaces get nothing. On a LAN interface, a TCP packet whose
 * service-side port no protected server uses costs one bitmap test
 * (svc_port_bitmap); one on a protected port, one bihash lookup.
 *
 * conns[] is a fixed, 2-way set-associative slot table rather than a
 * bihash: worker threads create entries and update them in place without
 * any lock or memory allocation, and a colliding new connection simply
 * takes over the older slot — the equivalent of the XDP side's LRU
 * eviction. Races between two workers on one slot can only make a
 * heuristic reading slightly off, never corrupt memory; readers always
 * re-check the 4-tuple.
 *
 * A client SYN only goes into the separate halfopen[] table (same
 * design); the connection enters conns[] — the table everything is judged
 * on — once the client ACKs the server's SYN-ACK, which a spoofed source
 * never does. So a spoofed-source SYN flood can't push tracked
 * connections out, and a half-open connection is never judged (see
 * kern/xdp_bridge.c's app_halfopen_map for the live finding behind this).
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/tcp/tcp_packet.h>
#include <vnet/feature/feature.h>

#include <connguard/connguard.h>

typedef enum
{
  CONNGUARD_NEXT_DROP,
  CONNGUARD_N_NEXT,
} connguard_next_t;

static_always_inline int
connguard_slot_match (connguard_conn_t *c, u32 cip, u32 sip, u16 cp, u16 sp)
{
  return c->state != CONNGUARD_FREE && c->client_ip == cip &&
	 c->server_ip == sip && c->client_port == cp && c->server_port == sp;
}

static_always_inline connguard_conn_t *
connguard_slot_find (connguard_main_t *cm, u32 cip, u32 sip, u16 cp, u16 sp)
{
  u32 base = connguard_slot_base (cm, cip, sip, cp, sp);
  connguard_conn_t *c0 = &cm->conns[base];
  connguard_conn_t *c1 = &cm->conns[base + 1];

  if (connguard_slot_match (c0, cip, sip, cp, sp))
    return c0;
  if (connguard_slot_match (c1, cip, sip, cp, sp))
    return c1;
  return 0;
}

/* connguard_slot_victim: how willing a slot is to be taken over by a new
 * connection — higher is more willing. */
static_always_inline u64
connguard_slot_victim (connguard_conn_t *c, u64 now)
{
  switch (c->state)
    {
    case CONNGUARD_FREE:
    case CONNGUARD_CLOSED:
      return ~0ULL;
    case CONNGUARD_KILLED:
      if (now - c->wait_start_ns >= CONNGUARD_KILLED_KEEP_NS)
	return ~0ULL;
      return 0; /* still dropping the reset client's packets */
    case CONNGUARD_SYN:
      if (now - c->start_ns >= CONNGUARD_SYN_STALE_NS)
	return ~0ULL - 1;
      break;
    default:
      break;
    }
  return now - c->start_ns; /* otherwise the older one */
}

static_always_inline connguard_conn_t *
connguard_slot_claim (connguard_main_t *cm, u64 now, u32 cip, u32 sip, u16 cp,
		      u16 sp)
{
  u32 base = connguard_slot_base (cm, cip, sip, cp, sp);
  connguard_conn_t *c0 = &cm->conns[base];
  connguard_conn_t *c1 = &cm->conns[base + 1];

  if (connguard_slot_match (c0, cip, sip, cp, sp))
    return c0;
  if (connguard_slot_match (c1, cip, sip, cp, sp))
    return c1;
  return connguard_slot_victim (c1, now) > connguard_slot_victim (c0, now) ?
	   c1 :
	   c0;
}

static_always_inline int
connguard_ho_match (connguard_halfopen_t *o, u32 cip, u32 sip, u16 cp, u16 sp)
{
  return o->used && o->client_ip == cip && o->server_ip == sip &&
	 o->client_port == cp && o->server_port == sp;
}

static_always_inline connguard_halfopen_t *
connguard_ho_find (connguard_main_t *cm, u32 cip, u32 sip, u16 cp, u16 sp)
{
  u32 base = connguard_halfopen_base (cm, cip, sip, cp, sp);
  connguard_halfopen_t *o0 = &cm->halfopen[base];
  connguard_halfopen_t *o1 = &cm->halfopen[base + 1];

  if (connguard_ho_match (o0, cip, sip, cp, sp))
    return o0;
  if (connguard_ho_match (o1, cip, sip, cp, sp))
    return o1;
  return 0;
}

/* connguard_ho_claim: the pair's matching slot, else a free one, else the
 * older one. */
static_always_inline connguard_halfopen_t *
connguard_ho_claim (connguard_main_t *cm, u64 now, u32 cip, u32 sip, u16 cp,
		    u16 sp)
{
  u32 base = connguard_halfopen_base (cm, cip, sip, cp, sp);
  connguard_halfopen_t *o0 = &cm->halfopen[base];
  connguard_halfopen_t *o1 = &cm->halfopen[base + 1];

  if (connguard_ho_match (o0, cip, sip, cp, sp))
    return o0;
  if (connguard_ho_match (o1, cip, sip, cp, sp))
    return o1;
  if (!o0->used)
    return o0;
  if (!o1->used)
    return o1;
  return (now - o1->start_ns) > (now - o0->start_ns) ? o1 : o0;
}

/* One packet's parsed fields, kept between the node's two passes (see
 * connguard_node_inline). IPs in network byte order, ports and seq in host
 * byte order, as in connguard_conn_t. */
typedef struct
{
  ethernet_header_t *eth;
  u32 cip, sip;
  u16 cp, sp;
  u32 seq;
  u32 plen;
  u32 tx_sw_if_index;
  u16 window; /* as on the wire: only compared with 0 */
  u8 fl;
  u8 sidx;
} connguard_pkt_t;

/* connguard_parse: fills p for a TCP packet to or from a protected
 * service; 0 for anything else (left alone). is_c2s: client → server
 * (connguard-out); tx_sw_if_index is then the LAN interface the server
 * sits behind. */
static_always_inline int
connguard_parse (connguard_main_t *cm, vlib_buffer_t *b, int is_c2s,
		 u32 tx_sw_if_index, connguard_pkt_t *p)
{
  ethernet_header_t *eth = vlib_buffer_get_current (b);
  u8 *end = (u8 *) eth + b->current_length;

  if ((u8 *) (eth + 1) > end ||
      eth->type != clib_host_to_net_u16 (ETHERNET_TYPE_IP4))
    return 0;
  ip4_header_t *ip = (ip4_header_t *) (eth + 1);
  if ((u8 *) (ip + 1) > end || ip->protocol != IP_PROTOCOL_TCP)
    return 0;
  tcp_header_t *tcp = (tcp_header_t *) ((u8 *) ip + ip4_header_bytes (ip));
  if ((u8 *) (tcp + 1) > end)
    return 0;

  u16 sport = clib_net_to_host_u16 (tcp->src_port);
  u16 dport = clib_net_to_host_u16 (tcp->dst_port);
  if (is_c2s)
    {
      p->cip = ip->src_address.as_u32;
      p->sip = ip->dst_address.as_u32;
      p->cp = sport;
      p->sp = dport;
    }
  else
    {
      p->cip = ip->dst_address.as_u32;
      p->sip = ip->src_address.as_u32;
      p->cp = dport;
      p->sp = sport;
    }

  if (!((cm->svc_port_bitmap[p->sp >> 6] >> (p->sp & 63)) & 1))
    return 0;
  clib_bihash_kv_8_8_t kv, val;
  kv.key = ((u64) p->sip << 32) | p->sp;
  if (clib_bihash_search_8_8 (&cm->svc_table, &kv, &val))
    return 0;
  if (val.value >= CONNGUARD_MAX_SERVERS)
    return 0;

  u32 hdr_len = ip4_header_bytes (ip) + tcp_header_bytes (tcp);
  u32 tot_len = clib_net_to_host_u16 (ip->length);
  p->eth = eth;
  p->sidx = (u8) val.value;
  p->plen = tot_len > hdr_len ? tot_len - hdr_len : 0;
  p->seq = clib_net_to_host_u32 (tcp->seq_number);
  p->window = tcp->window;
  p->fl = tcp->flags;
  p->tx_sw_if_index = tx_sw_if_index;
  return 1;
}

/* connguard_prefetch_range: every cache line of [addr, addr + size). */
static_always_inline void
connguard_prefetch_range (void *addr, uword size, int is_store)
{
  uword a = pointer_to_uword (addr) & ~(uword) (CLIB_CACHE_LINE_BYTES - 1);
  uword last = pointer_to_uword (addr) + size - 1;
  for (; a <= last; a += CLIB_CACHE_LINE_BYTES)
    {
      if (is_store)
	clib_prefetch_store ((void *) a);
      else
	clib_prefetch_load ((void *) a);
    }
}

/* connguard_prefetch: the slot pair connguard_process will touch first
 * for p — the same choice of table it makes below. A server-to-client
 * pure ACK touches nothing. */
static_always_inline void
connguard_prefetch (connguard_main_t *cm, const connguard_pkt_t *p,
		    int is_c2s)
{
  u8 fl = p->fl;
  int syn_only = (fl & TCP_FLAG_SYN) && !(fl & TCP_FLAG_ACK);
  int synack = (fl & TCP_FLAG_SYN) && (fl & TCP_FLAG_ACK);

  if (is_c2s ? syn_only : synack)
    {
      u32 base = connguard_halfopen_base (cm, p->cip, p->sip, p->cp, p->sp);
      connguard_prefetch_range (&cm->halfopen[base],
				2 * sizeof (connguard_halfopen_t), 1);
      return;
    }
  if (!is_c2s && !(fl & (TCP_FLAG_RST | TCP_FLAG_FIN)) && p->plen == 0)
    return;
  u32 base = connguard_slot_base (cm, p->cip, p->sip, p->cp, p->sp);
  connguard_prefetch_range (&cm->conns[base], 2 * sizeof (connguard_conn_t),
			    is_c2s);
}

/* connguard_process: records p; returns 1 when the packet must be dropped
 * (client packet of a connection the scan has reset). */
static_always_inline int
connguard_process (vlib_main_t *vm, connguard_main_t *cm,
		   const connguard_pkt_t *p, int is_c2s, u64 now)
{
  u32 cip = p->cip, sip = p->sip;
  u16 cp = p->cp, sp = p->sp;
  u32 plen = p->plen;
  u8 fl = p->fl;
  connguard_health_t *h =
    &cm->health[vm->thread_index * CONNGUARD_MAX_SERVERS + p->sidx];
  connguard_conn_t *c;

  if (is_c2s)
    {
      if ((fl & TCP_FLAG_SYN) && !(fl & TCP_FLAG_ACK))
	{
	  h->syn++;
	  connguard_halfopen_t *o =
	    connguard_ho_claim (cm, now, cip, sip, cp, sp);
	  /* Free the slot first so a concurrent reader never matches a
	   * half-written 4-tuple, publish it last. */
	  o->used = 0;
	  CLIB_MEMORY_STORE_BARRIER ();
	  o->client_ip = cip;
	  o->server_ip = sip;
	  o->client_port = cp;
	  o->server_port = sp;
	  o->synacked = 0;
	  o->rcv_nxt = p->seq + 1;
	  o->server_sw_if_index = p->tx_sw_if_index;
	  o->start_ns = now;
	  clib_memcpy_fast (o->dst_mac, p->eth->dst_address, 6);
	  clib_memcpy_fast (o->src_mac, p->eth->src_address, 6);
	  CLIB_MEMORY_STORE_BARRIER ();
	  o->used = 1;
	  return 0;
	}
      c = connguard_slot_find (cm, cip, sip, cp, sp);
      if (!c)
	{
	  /* The client's ACK of the server's SYN-ACK completes the
	   * handshake: only now does the connection get tracked. */
	  if (!(fl & TCP_FLAG_ACK) ||
	      (fl & (TCP_FLAG_SYN | TCP_FLAG_RST | TCP_FLAG_FIN)))
	    return 0;
	  connguard_halfopen_t *o = connguard_ho_find (cm, cip, sip, cp, sp);
	  if (!o || !o->synacked)
	    return 0;
	  c = connguard_slot_claim (cm, now, cip, sip, cp, sp);
	  c->state = CONNGUARD_FREE;
	  CLIB_MEMORY_STORE_BARRIER ();
	  c->client_ip = cip;
	  c->server_ip = sip;
	  c->client_port = cp;
	  c->server_port = sp;
	  c->flags = 0;
	  c->server_idx = p->sidx;
	  c->rcv_nxt = o->rcv_nxt;
	  c->wait_bytes = 0;
	  c->wait_segs = 0;
	  c->start_ns = o->start_ns;
	  c->wait_start_ns = 0;
	  c->zero_win_ns = 0;
	  connguard_conn_cold_t *cold = &cm->conns_cold[c - cm->conns];
	  cold->server_sw_if_index = o->server_sw_if_index;
	  clib_memcpy_fast (cold->dst_mac, o->dst_mac, 6);
	  clib_memcpy_fast (cold->src_mac, o->src_mac, 6);
	  CLIB_MEMORY_STORE_BARRIER ();
	  c->state = CONNGUARD_EST;
	  o->used = 0;
	}
      if (c->state == CONNGUARD_KILLED)
	return 1;
      if (c->state == CONNGUARD_CLOSED)
	return 0;
      if (fl & (TCP_FLAG_RST | TCP_FLAG_FIN))
	{
	  c->state = CONNGUARD_CLOSED;
	  return 0;
	}
      if (p->window == 0)
	{
	  if (!c->zero_win_ns)
	    c->zero_win_ns = now;
	}
      else if (c->zero_win_ns)
	c->zero_win_ns = 0;
      if (plen > 0)
	{
	  u32 seg_end = p->seq + plen;
	  if ((i32) (seg_end - c->rcv_nxt) > 0)
	    {
	      c->rcv_nxt = seg_end;
	      c->flags |= CONNGUARD_F_CLIENT_DATA;
	      if (!c->wait_start_ns)
		{
		  c->wait_start_ns = now;
		  c->wait_bytes = 0;
		  c->wait_segs = 0;
		}
	      c->wait_bytes += plen;
	      c->wait_segs++;
	    }
	}
      return 0;
    }

  /* server → client. A SYN-ACK or RST counts toward Server Health only
   * when it answers a WAN client's connection (a halfopen[] or conns[]
   * entry exists), the same basis the SYN counter has — see
   * kern/xdp_bridge.c's app_filter_track. */
  if ((fl & TCP_FLAG_SYN) && (fl & TCP_FLAG_ACK))
    {
      connguard_halfopen_t *o = connguard_ho_find (cm, cip, sip, cp, sp);
      if (o)
	{
	  h->synack++;
	  o->synacked = 1;
	}
      return 0;
    }
  if (fl & TCP_FLAG_RST)
    {
      c = connguard_slot_find (cm, cip, sip, cp, sp);
      if (c || connguard_ho_find (cm, cip, sip, cp, sp))
	h->rst++;
      if (c && c->state != CONNGUARD_KILLED)
	c->state = CONNGUARD_CLOSED;
      return 0;
    }
  if (!(fl & TCP_FLAG_FIN) && plen == 0)
    return 0; /* pure ACK: nothing to record */
  c = connguard_slot_find (cm, cip, sip, cp, sp);
  if (!c || c->state == CONNGUARD_KILLED)
    return 0;
  if (fl & TCP_FLAG_FIN)
    {
      c->state = CONNGUARD_CLOSED;
      return 0;
    }
  /* The server answered: whatever the client was sending is complete. */
  if (c->wait_start_ns)
    {
      c->wait_start_ns = 0;
      c->wait_bytes = 0;
      c->wait_segs = 0;
    }
  return 0;
}

/* connguard_node_inline: two passes over the frame. The first parses every
 * packet and prefetches the slot pair it will touch; the second records
 * them. conns[]/halfopen[] are far larger than the CPU caches, so done one
 * packet at a time nearly every lookup waits on memory — measured
 * 2026-10-08 (release, pg, 653,425 tracked connections in 1,048,576 slots,
 * 47 MB vs a 30 MB L3): connguard-out 260 clocks/packet with random
 * connections vs ~100 when the same packets hit 1,000 connections. */
static_always_inline uword
connguard_node_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		       vlib_frame_t *frame, int is_out)
{
  connguard_main_t *cm = &connguard_main;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_vectors = frame->n_vectors;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE];
  u16 nexts[VLIB_FRAME_SIZE];
  connguard_pkt_t pkts[VLIB_FRAME_SIZE];
  u8 tracked[VLIB_FRAME_SIZE];
  u32 n_dropped = 0, i;
  int enabled = cm->enabled && cm->conns != 0 && cm->halfopen != 0 &&
		vm->thread_index < cm->n_threads;

  vlib_get_buffers (vm, from, bufs, n_vectors);

  /* Pass 1: next node, parse, prefetch. */
  for (i = 0; i < n_vectors; i++)
    {
      vlib_buffer_t *b = bufs[i];
      u32 next0;

      if (i + 4 < n_vectors)
	{
	  vlib_prefetch_buffer_header (bufs[i + 4], LOAD);
	  CLIB_PREFETCH (bufs[i + 4]->data + bufs[i + 4]->current_data,
			 CLIB_CACHE_LINE_BYTES, LOAD);
	}

      vnet_feature_next (&next0, b);
      nexts[i] = (u16) next0;
      tracked[i] = 0;
      if (PREDICT_FALSE (!enabled))
	continue;

      if (is_out)
	{
	  u32 rx = vnet_buffer (b)->sw_if_index[VLIB_RX];
	  if (rx >= vec_len (cm->role_by_sw_if_index) ||
	      cm->role_by_sw_if_index[rx] != CONNGUARD_ROLE_WAN)
	    continue;
	  tracked[i] = connguard_parse (
	    cm, b, 1, vnet_buffer (b)->sw_if_index[VLIB_TX], &pkts[i]);
	}
      else
	tracked[i] = connguard_parse (cm, b, 0, 0, &pkts[i]);
      if (tracked[i])
	connguard_prefetch (cm, &pkts[i], is_out);
    }

  /* Pass 2: record (the slots are in cache by now). */
  if (enabled)
    {
      u64 now = connguard_now_ns (vm);
      for (i = 0; i < n_vectors; i++)
	{
	  if (!tracked[i])
	    continue;
	  if (PREDICT_FALSE (connguard_process (vm, cm, &pkts[i], is_out, now)))
	    {
	      nexts[i] = CONNGUARD_NEXT_DROP;
	      n_dropped++;
	    }
	}
    }

  if (n_dropped)
    vlib_increment_simple_counter (&cm->dropped_counters, vm->thread_index, 0,
				   n_dropped);

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, n_vectors);
  return n_vectors;
}

VLIB_NODE_FN (connguard_out_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return connguard_node_inline (vm, node, frame, 1 /* is_out */);
}

VLIB_NODE_FN (connguard_in_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return connguard_node_inline (vm, node, frame, 0 /* is_out */);
}

VLIB_REGISTER_NODE (connguard_out_node) = {
  .name = "connguard-out",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = CONNGUARD_N_NEXT,
  .next_nodes = {
    [CONNGUARD_NEXT_DROP] = "error-drop",
  },
};

VLIB_REGISTER_NODE (connguard_in_node) = {
  .name = "connguard-in",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = CONNGUARD_N_NEXT,
  .next_nodes = {
    [CONNGUARD_NEXT_DROP] = "error-drop",
  },
};
