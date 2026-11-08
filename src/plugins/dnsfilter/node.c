/* SPDX-License-Identifier: Apache-2.0 */

/*
 * node.c — mighty_lb DNS Sinkhole, VPP mode packet path. Two nodes:
 *
 *   dnsfilter-lan — l2-input-ip4 arc of each LAN port, after the input ACL
 *   (attacker blocklist, WAN policy) like xdp_bridge's stage after its
 *   mitigation. Untagged IPv4, first fragment, toward the WAN (destination
 *   MAC unknown in the bridge domain or learned on a WAN port; never the
 *   BVI, never a LAN port — a LAN-side DNS server keeps its queries):
 *     dport 853, block_dot             -> drop (dot_dropped)
 *     dport 443, block_doh_ip, TCP SYN
 *       or QUIC long header, DoH IP    -> drop (doh_dropped)
 *     dport 53, intercept:
 *       engine not answering           -> bridged (bypass_daemon_down)
 *       over the client's qps          -> drop (client_limit_dropped)
 *       over the global qps / table full -> bridged (bypass_global_limit)
 *       else                           -> return entry stored, destination
 *                                         MAC = the tap's Linux end, sent
 *                                         to the tap (redirected)
 *   Everything else continues on the arc untouched: the cost for non-DNS
 *   traffic is the protocol/port test.
 *
 *   dnsfilter-return — device-input arc of the tap: the engine's answers
 *   (a UDP answer also frees its return entry)
 *   (Linux routes them out of the tap toward a fixed neighbour, see
 *   virtserver/dnsf/linux.go). Source port 53 and a return entry for
 *   (destination ip, port, proto): MACs restored (source = the client's
 *   gateway, destination = the client) and sent straight out of the LAN
 *   port the query came in on (returned). Anything else from the tap is
 *   dropped (return_dropped) — nothing from the host side may enter the
 *   bridge.
 *
 * The answers bypass the bridge (interface-output), as floodguard's SYN
 * challenge replies do: they are the resolver's answer on the ingress
 * port, not bridged traffic. Same scope as the kernel mode: IPv4 only,
 * untagged frames only.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/feature/feature.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/tcp/tcp_packet.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/l2/l2_fib.h>
#include <dnsfilter/dnsfilter.h>

#define DNSFILTER_PORT_DNS 53
#define DNSFILTER_PORT_DOT 853
#define DNSFILTER_PORT_DOH 443

typedef enum
{
  DNSFILTER_NEXT_DROP,
  DNSFILTER_NEXT_OUTPUT,
  DNSFILTER_N_NEXT,
} dnsfilter_next_t;

typedef enum
{
  DNSFILTER_VERDICT_PASS,
  DNSFILTER_VERDICT_REDIRECT,
  DNSFILTER_VERDICT_BYPASS,
  DNSFILTER_VERDICT_DROP,
  DNSFILTER_VERDICT_RETURN,
} dnsfilter_verdict_t;

typedef struct
{
  u32 sw_if_index;
  u8 verdict;
  u16 dport;
} dnsfilter_trace_t;

static char *dnsfilter_error_strings[] = { "dropped by the DNS Sinkhole" };

static u8 *
format_dnsfilter_trace (u8 *s, va_list *args)
{
  static const char *const names[] = { "pass", "redirect", "bypass", "drop",
				       "return" };
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  dnsfilter_trace_t *t = va_arg (*args, dnsfilter_trace_t *);
  return format (s, "dnsfilter: sw_if_index %u port %u %s", t->sw_if_index,
		 t->dport, t->verdict < ARRAY_LEN (names) ? names[t->verdict] : "?");
}

static_always_inline void
dnsfilter_trace (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b,
		 u16 dport, dnsfilter_verdict_t verdict)
{
  if (PREDICT_FALSE (b->flags & VLIB_BUFFER_IS_TRACED))
    {
      dnsfilter_trace_t *t = vlib_add_trace (vm, node, b, sizeof (*t));
      t->sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_RX];
      t->verdict = verdict;
      t->dport = dport;
    }
}

static_always_inline void
dnsfilter_count (vlib_main_t *vm, dnsfilter_main_t *dm, dnsfilter_counter_t c)
{
  vlib_increment_simple_counter (&dm->counters[c], vm->thread_index, 0, 1);
}

/* (ip, port, proto), all as on the wire. */
static_always_inline u64
dnsfilter_key (u32 ip, u16 port, u8 proto)
{
  return ((u64) ip << 32) | ((u64) port << 16) | proto;
}

/* dnsfilter_toward_wan: the destination MAC is unknown in the bridge
 * domain or learned on a WAN port (a cross-connect has no bridge domain:
 * every miss counts as WAN — a LAN port's peer is the WAN). */
static_always_inline int
dnsfilter_toward_wan (dnsfilter_main_t *dm, vlib_buffer_t *b, const u8 *dst)
{
  clib_bihash_kv_8_8_t kv;
  l2fib_entry_result_t r;
  u32 sw;

  kv.key = l2fib_make_key (dst, vnet_buffer (b)->l2.bd_index);
  if (clib_bihash_search_8_8 (&l2fib_main.mac_table, &kv, &kv))
    return 1;
  r.raw = kv.value;
  if (l2fib_entry_result_is_set_BVI (&r))
    return 0;
  sw = r.fields.sw_if_index;
  return sw < vec_len (dm->roles) && dm->roles[sw] == DNSFILTER_ROLE_WAN;
}

/* dnsfilter_client_over: counts a query in the client's 1-second window;
 * 1 = over client_qps. A full client table stops limiting new clients. */
static_always_inline int
dnsfilter_client_over (dnsfilter_main_t *dm, u32 client_ip, u32 now)
{
  clib_bihash_kv_8_8_t kv, val;
  u32 count = 1;

  kv.key = client_ip;
  if (clib_bihash_search_8_8 (&dm->clients, &kv, &val) == 0)
    {
      if ((u32) (val.value >> 32) == now)
	count = (u32) val.value + 1;
    }
  else if (dm->n_clients >= DNSFILTER_CLIENT_MAX)
    return 0;
  else
    clib_atomic_fetch_add (&dm->n_clients, 1);
  kv.value = ((u64) now << 32) | count;
  clib_bihash_add_del_8_8 (&dm->clients, &kv, 1 /* add/replace */);
  return count > dm->client_qps;
}

/* dnsfilter_exempt: 1 = the client is not under the per-client limit. */
static_always_inline int
dnsfilter_exempt (dnsfilter_main_t *dm, u32 client_ip)
{
  clib_bihash_kv_8_8_t kv, val;

  if (!dm->n_exempt)
    return 0;
  kv.key = client_ip;
  return clib_bihash_search_8_8 (&dm->exempt, &kv, &val) == 0;
}

/* dnsfilter_global_over: all workers' 1-second window; 1 = over. */
static_always_inline int
dnsfilter_global_over (dnsfilter_main_t *dm, u32 now)
{
  if (dm->global_sec != now)
    {
      dm->global_sec = now;
      dm->global_count = 0;
    }
  return clib_atomic_add_fetch (&dm->global_count, 1) > dm->global_qps;
}

/* dnsfilter_remember: stores / refreshes the client's return entry;
 * 0 = the table is full (the query is bridged unfiltered). */
static_always_inline int
dnsfilter_remember (dnsfilter_main_t *dm, u64 key, const u8 *eth,
		    u32 sw_if_index, u32 now)
{
  clib_bihash_kv_8_16_t kv, val;
  dnsfilter_ret_t r;

  kv.key = key;
  if (clib_bihash_search_8_16 (&dm->ret, &kv, &val))
    {
      if (dm->n_ret >= DNSFILTER_RET_MAX)
	return 0;
      clib_atomic_fetch_add (&dm->n_ret, 1);
    }
  clib_memcpy_fast (r.client_mac, eth + 6, 6);
  clib_memcpy_fast (r.gw_mac, eth, 6);
  r.sw_if_index = (u16) sw_if_index;
  r.seen = (u16) now;
  kv.value[0] = r.as_u64[0];
  kv.value[1] = r.as_u64[1];
  clib_bihash_add_del_8_16 (&dm->ret, &kv, 1 /* add/replace */);
  return 1;
}

VLIB_NODE_FN (dnsfilter_lan_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  dnsfilter_main_t *dm = &dnsfilter_main;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  u32 now = dnsfilter_now_sec (vm);

  vlib_get_buffers (vm, from, bufs, n_left);

  while (n_left > 0)
    {
      u8 *eth = vlib_buffer_get_current (b[0]);
      u8 *end = eth + b[0]->current_length;
      ip4_header_t *ip;
      u8 *l4;
      u16 sport, dport = 0;
      u8 proto;
      dnsfilter_verdict_t verdict = DNSFILTER_VERDICT_PASS;

      if (n_left > 2)
	vlib_prefetch_buffer_header (b[2], LOAD);

      vnet_feature_next_u16 (next, b[0]);

      /* untagged IPv4 TCP/UDP, first fragment, to a unicast MAC */
      if (vnet_buffer (b[0])->l2.l2_len != sizeof (ethernet_header_t) ||
	  (eth[0] & 1))
	goto done;
      ip = (ip4_header_t *) (eth + sizeof (ethernet_header_t));
      if ((u8 *) (ip + 1) > end)
	goto done;
      proto = ip->protocol;
      if ((proto != IP_PROTOCOL_UDP && proto != IP_PROTOCOL_TCP) ||
	  ip4_get_fragment_offset (ip) != 0)
	goto done;
      l4 = (u8 *) ip + ip4_header_bytes (ip);
      if (l4 + sizeof (udp_header_t) > end)
	goto done;
      sport = ((udp_header_t *) l4)->src_port;
      dport = clib_net_to_host_u16 (((udp_header_t *) l4)->dst_port);
      if (dport != DNSFILTER_PORT_DNS && dport != DNSFILTER_PORT_DOT &&
	  dport != DNSFILTER_PORT_DOH)
	goto done;

      /* Each branch settles its own cheap conditions before the l2fib
       * lookup (dnsfilter_toward_wan): most LAN -> WAN traffic is HTTPS,
       * and only a new connection to a DoH address may pay for it. */
      if (dport == DNSFILTER_PORT_DOT)
	{
	  if (dm->block_dot && dnsfilter_toward_wan (dm, b[0], eth))
	    {
	      verdict = DNSFILTER_VERDICT_DROP;
	      dnsfilter_count (vm, dm, DNSFILTER_CNT_DOT_DROPPED);
	    }
	  goto done;
	}

      if (dport == DNSFILTER_PORT_DOH)
	{
	  int first;
	  clib_bihash_kv_8_8_t kv, val;

	  if (!dm->block_doh_ip || !dm->n_doh_ips)
	    goto done;
	  if (proto == IP_PROTOCOL_TCP)
	    {
	      tcp_header_t *t = (tcp_header_t *) l4;
	      first = (u8 *) (t + 1) <= end &&
		      (t->flags & (TCP_FLAG_SYN | TCP_FLAG_ACK)) == TCP_FLAG_SYN;
	    }
	  else /* QUIC long header (Initial / 0-RTT / Handshake) */
	    first = l4 + sizeof (udp_header_t) < end &&
		    (l4[sizeof (udp_header_t)] & 0x80);
	  if (!first)
	    goto done;
	  kv.key = ip->dst_address.as_u32;
	  if (clib_bihash_search_8_8 (&dm->doh_ips, &kv, &val) == 0 &&
	      dnsfilter_toward_wan (dm, b[0], eth))
	    {
	      verdict = DNSFILTER_VERDICT_DROP;
	      dnsfilter_count (vm, dm, DNSFILTER_CNT_DOH_DROPPED);
	    }
	  goto done;
	}

      /* dport 53 */
      if (!dm->intercept || dm->tap_sw_if_index == ~0 ||
	  !dnsfilter_toward_wan (dm, b[0], eth))
	goto done;
      if (!dm->daemon_ok)
	{
	  verdict = DNSFILTER_VERDICT_BYPASS;
	  dnsfilter_count (vm, dm, DNSFILTER_CNT_BYPASS_DAEMON_DOWN);
	  goto done;
	}
      if (dm->client_qps && !dnsfilter_exempt (dm, ip->src_address.as_u32) &&
	  dnsfilter_client_over (dm, ip->src_address.as_u32, now))
	{
	  verdict = DNSFILTER_VERDICT_DROP;
	  dnsfilter_count (vm, dm, DNSFILTER_CNT_CLIENT_LIMIT_DROPPED);
	  goto done;
	}
      if ((dm->global_qps && dnsfilter_global_over (dm, now)) ||
	  !dnsfilter_remember (dm,
			       dnsfilter_key (ip->src_address.as_u32, sport,
					      proto),
			       eth, vnet_buffer (b[0])->sw_if_index[VLIB_RX],
			       now))
	{
	  verdict = DNSFILTER_VERDICT_BYPASS;
	  dnsfilter_count (vm, dm, DNSFILTER_CNT_BYPASS_GLOBAL_LIMIT);
	  goto done;
	}
      clib_memcpy_fast (eth, dm->host_mac.bytes, 6);
      vnet_buffer (b[0])->sw_if_index[VLIB_TX] = dm->tap_sw_if_index;
      next[0] = DNSFILTER_NEXT_OUTPUT;
      verdict = DNSFILTER_VERDICT_REDIRECT;
      dnsfilter_count (vm, dm, DNSFILTER_CNT_REDIRECTED);

    done:
      if (verdict == DNSFILTER_VERDICT_DROP)
	{
	  next[0] = DNSFILTER_NEXT_DROP;
	  b[0]->error = node->errors[0];
	}
      dnsfilter_trace (vm, node, b[0], dport, verdict);
      b++;
      next++;
      n_left--;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);
  return frame->n_vectors;
}

VLIB_NODE_FN (dnsfilter_return_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  dnsfilter_main_t *dm = &dnsfilter_main;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;

  vlib_get_buffers (vm, from, bufs, n_left);

  while (n_left > 0)
    {
      u8 *eth = vlib_buffer_get_current (b[0]);
      u8 *end = eth + b[0]->current_length;
      ethernet_header_t *e = (ethernet_header_t *) eth;
      ip4_header_t *ip = (ip4_header_t *) (e + 1);
      clib_bihash_kv_8_16_t kv, val;
      dnsfilter_ret_t r;
      u8 *l4;

      next[0] = DNSFILTER_NEXT_DROP;

      if ((u8 *) (ip + 1) > end ||
	  e->type != clib_host_to_net_u16 (ETHERNET_TYPE_IP4) ||
	  (ip->protocol != IP_PROTOCOL_UDP && ip->protocol != IP_PROTOCOL_TCP))
	goto miss;
      l4 = (u8 *) ip + ip4_header_bytes (ip);
      if (l4 + sizeof (udp_header_t) > end ||
	  ((udp_header_t *) l4)->src_port !=
	    clib_host_to_net_u16 (DNSFILTER_PORT_DNS))
	goto miss;
      kv.key = dnsfilter_key (ip->dst_address.as_u32,
			      ((udp_header_t *) l4)->dst_port, ip->protocol);
      if (clib_bihash_search_8_16 (&dm->ret, &kv, &val))
	goto miss;
      r.as_u64[0] = val.value[0];
      r.as_u64[1] = val.value[1];
      clib_memcpy_fast (e->dst_address, r.client_mac, 6);
      clib_memcpy_fast (e->src_address, r.gw_mac, 6);
      vnet_buffer (b[0])->sw_if_index[VLIB_TX] = r.sw_if_index;
      /* A UDP query has exactly one answer: free its entry now (a TCP
       * connection keeps it for the next query, the sweep ends it). */
      if (ip->protocol == IP_PROTOCOL_UDP &&
	  clib_bihash_add_del_8_16 (&dm->ret, &kv, 0 /* del */) == 0)
	clib_atomic_fetch_sub (&dm->n_ret, 1);
      next[0] = DNSFILTER_NEXT_OUTPUT;
      dnsfilter_count (vm, dm, DNSFILTER_CNT_RETURNED);
      dnsfilter_trace (vm, node, b[0], DNSFILTER_PORT_DNS,
		       DNSFILTER_VERDICT_RETURN);
      goto next_buffer;

    miss:
      b[0]->error = node->errors[0];
      dnsfilter_count (vm, dm, DNSFILTER_CNT_RETURN_DROPPED);
      dnsfilter_trace (vm, node, b[0], 0, DNSFILTER_VERDICT_DROP);

    next_buffer:
      b++;
      next++;
      n_left--;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (dnsfilter_lan_node) = {
  .name = "dnsfilter-lan",
  .vector_size = sizeof (u32),
  .format_trace = format_dnsfilter_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (dnsfilter_error_strings),
  .error_strings = dnsfilter_error_strings,
  .n_next_nodes = DNSFILTER_N_NEXT,
  .next_nodes = { [DNSFILTER_NEXT_DROP] = "error-drop",
		  [DNSFILTER_NEXT_OUTPUT] = "interface-output" },
};

VLIB_REGISTER_NODE (dnsfilter_return_node) = {
  .name = "dnsfilter-return",
  .vector_size = sizeof (u32),
  .format_trace = format_dnsfilter_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (dnsfilter_error_strings),
  .error_strings = dnsfilter_error_strings,
  .n_next_nodes = DNSFILTER_N_NEXT,
  .next_nodes = { [DNSFILTER_NEXT_DROP] = "error-drop",
		  [DNSFILTER_NEXT_OUTPUT] = "interface-output" },
};

/* After the input ACL (attacker blocklist, WAN policy) and floodguard's
 * storm node, as xdp_bridge runs its DNS stage after its mitigation. */
VNET_FEATURE_INIT (dnsfilter_lan_feature, static) = {
  .arc_name = "l2-input-ip4",
  .node_name = "dnsfilter-lan",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-l2", "floodguard-l2-ip4"),
  .runs_before = VNET_FEATURES ("l2-input-feat-arc-end"),
};

/* The tap's frames never reach ethernet-input: only answers leave here. */
VNET_FEATURE_INIT (dnsfilter_return_feature, static) = {
  .arc_name = "device-input",
  .node_name = "dnsfilter-return",
  .runs_before = VNET_FEATURES ("ethernet-input"),
};
