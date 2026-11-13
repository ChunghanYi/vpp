/* SPDX-License-Identifier: Apache-2.0 */

/*
 * node.c — mighty_lb DNS Sinkhole, VPP mode packet path. Two nodes:
 *
 *   dnsfilter-lan — l2-input-ip4 arc of each LAN port, after the input ACL
 *   (attacker blocklist, WAN policy) like xdp_bridge's stage after its
 *   mitigation. IPv4 (untagged or behind one or two VLAN tags, l2_len),
 *   first fragment, toward the WAN (destination
 *   MAC unknown in the bridge domain or learned on a WAN port; never the
 *   BVI, never a LAN port — a LAN-side DNS server keeps its queries):
 *     dport 853, block_dot             -> drop (dot_dropped)
 *     dport 443, block_doh_ip, TCP SYN
 *       or QUIC long header, DoH IP    -> drop (doh_dropped)
 *     dport 53 (intercept or fastpath):
 *       UDP query counted per client (Busiest / Active Clients)
 *       over the client's qps          -> drop (client_limit_dropped)
 *       fastpath, UDP: the block table (dnsfilter_judge) — blocked ->
 *         answered in place, out of the port it came in on (fp_blocked),
 *         reported to etad ("DNF1" frame on the events interface)
 *       no intercept (Fast mode)       -> bridged (fp_passed)
 *       engine not answering           -> bridged (bypass_daemon_down)
 *       over the global qps / table full -> bridged (bypass_global_limit)
 *       else                           -> return entry stored (with the
 *                                         VLAN tags, taken off the frame),
 *                                         destination MAC = the tap's Linux
 *                                         end, sent to the tap (redirected)
 *     (without fastpath the engine's health is checked first, as before)
 *   Everything else continues on the arc untouched: the cost for non-DNS
 *   traffic is the protocol/port test.
 *
 *   dnsfilter-return — device-input arc of the tap: the engine's answers
 *   (a UDP answer also frees its return entry)
 *   (Linux routes them out of the tap toward a fixed neighbour, see
 *   virtserver/dnsf/linux.go). Source port 53 and a return entry for
 *   (destination ip, port, proto): MACs restored (source = the client's
 *   gateway, destination = the client), the query's VLAN tags put back,
 *   and sent straight out of the LAN port the query came in on (returned). Anything else from the tap is
 *   dropped (return_dropped) — nothing from the host side may enter the
 *   bridge.
 *
 * The answers bypass the bridge (interface-output), as floodguard's SYN
 * challenge replies do: they are the resolver's answer on the ingress
 * port, not bridged traffic. Same scope as the kernel mode: IPv4 only;
 * a VLAN trunk link's tags (up to two) are kept on every answer.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/feature/feature.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/tcp/tcp_packet.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/l2/l2_fib.h>
#include <vppinfra/time.h>
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
  DNSFILTER_VERDICT_BLOCK,
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
  static const char *const names[] = { "pass",	 "redirect", "bypass",
				       "drop",	 "return",   "block" };
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
dnsfilter_remember (dnsfilter_main_t *dm, u64 key, const u8 *eth, u32 l2_len,
		    u32 sw_if_index, u32 now)
{
  clib_bihash_kv_8_24_t kv, val;
  dnsfilter_ret_t r;

  kv.key = key;
  if (clib_bihash_search_8_24 (&dm->ret, &kv, &val))
    {
      if (dm->n_ret >= DNSFILTER_RET_MAX)
	return 0;
      clib_atomic_fetch_add (&dm->n_ret, 1);
    }
  clib_memcpy_fast (r.client_mac, eth + 6, 6);
  clib_memcpy_fast (r.gw_mac, eth, 6);
  r.sw_if_index = (u16) sw_if_index;
  r.seen = (u16) now;
  r.tags[0] = r.tags[1] = 0;
  clib_memcpy_fast (r.tags, eth + 12, l2_len - sizeof (ethernet_header_t));
  kv.value[0] = r.as_u64[0];
  kv.value[1] = r.as_u64[1];
  kv.value[2] = r.as_u64[2];
  clib_bihash_add_del_8_24 (&dm->ret, &kv, 1 /* add/replace */);
  return 1;
}

/* ─── Fast path ─────────────────────────────────────────────────────── */

/* The query being judged: name[] is the wire name with every length byte
 * replaced by '.', lowercased ("\3www\7example\3com" -> ".www.example.com"),
 * name_len without the root 0. */
typedef struct
{
  u8 name[DNSFILTER_QNAME_MAX + 1];
  u32 name_len;
  u16 qtype;
  u16 qclass;
  u8 has_opt;
  u32 cats; /* the blocking bits */
} dnsfilter_query_t;

/* the DNS header's offset behind an L2 header of l2 bytes */
#define DNSFILTER_DNS_OFF(l2)                                                 \
  ((l2) + sizeof (ip4_header_t) + sizeof (udp_header_t))

/* dnsfilter_parse: 1 for a query the fast path judges — an option-less
 * IPv4 header, a standard query (QR 0, OPCODE 0) with exactly one
 * question whose name has no compression pointer, no '.' inside a label
 * and its end within DNSFILTER_QNAME_MAX (xdp_bridge's dnsf_parse). */
static_always_inline int
dnsfilter_parse (ip4_header_t *ip, u8 *end, dnsfilter_query_t *q)
{
  u8 *dns = (u8 *) ip + sizeof (ip4_header_t) + sizeof (udp_header_t);
  u8 *p;
  u32 i, next = 0;

  if (ip->ip_version_and_header_length != 0x45 || dns + 12 > end)
    return 0;
  if ((dns[2] & 0xf8) || dns[4] || dns[5] != 1)
    return 0;
  q->has_opt = dns[10] | dns[11];
  p = dns + 12;
  for (i = 0; i <= DNSFILTER_QNAME_MAX; i++)
    {
      u8 c;
      if (p + i >= end)
	return 0;
      c = p[i];
      if (i == next)
	{
	  if (c == 0)
	    {
	      if (i == 0 || p + i + 5 > end)
		return 0; /* the root, or no type/class */
	      q->name_len = i;
	      q->qtype = ((u16) p[i + 1] << 8) | p[i + 2];
	      q->qclass = ((u16) p[i + 3] << 8) | p[i + 4];
	      return 1;
	    }
	  if (c & 0xc0)
	    return 0; /* compression pointer / extended label */
	  next = i + c + 1;
	  c = '.';
	}
      else if (c >= 'A' && c <= 'Z')
	c |= 0x20;
      else if (c == '.')
	return 0;
      q->name[i] = c;
    }
  return 0;
}

/* dnsfilter_judge: the blocking bits of q (0 = allowed). Hashed from the
 * last byte to the first (virtserver/dnsf/hashlist.go): the running value
 * at each '.' is the hash of the suffix right of it, looked up — at most
 * DNSFILTER_LOOKUPS_MAX, rightmost first; exact-name bits count only for
 * the whole name; any Allow bit allows. */
static_always_inline u32
dnsfilter_judge (dnsfilter_main_t *dm, clib_bihash_8_8_t *t,
		 dnsfilter_query_t *q)
{
  u64 h = DNSFILTER_FNV_OFFSET;
  u32 acc = 0, lookups = 0;
  int i;

  for (i = (int) q->name_len - 1; i >= 0; i--)
    {
      u8 c = q->name[i];
      if (c == '.')
	{
	  clib_bihash_kv_8_8_t kv = { .key = h };
	  if (clib_bihash_search_8_8 (t, &kv, &kv) == 0)
	    acc |= i == 0 ? (u32) kv.value :
			    ((u32) kv.value & ~(0xffU << DNSFILTER_EXACT_SHIFT));
	  if (i == 0 || ++lookups >= DNSFILTER_LOOKUPS_MAX)
	    break;
	}
      h ^= c;
      h *= DNSFILTER_FNV_PRIME;
    }
  if (acc & DNSFILTER_CAT_ALLOW)
    return 0;
  return (acc | (acc >> DNSFILTER_EXACT_SHIFT)) & dm->cat_mask &
	 DNSFILTER_CAT_BITS;
}

/* dnsfilter_reply: turns the blocked query in b into its answer, in place
 * (xdp_bridge's dnsf_block_reply): same question; A -> 0.0.0.0, AAAA ->
 * ::, other types (or a class other than IN) -> NODATA, TTL block_ttl; a
 * NXDOMAIN-bit name -> NXDOMAIN; everything after the question goes, a
 * query with an additional record (EDNS) gets a minimal OPT back. No room
 * in the buffer for the record: NXDOMAIN (fp_nxdomain). Returns 0 when no
 * answer could be built. The caller sends it back out of the RX port. The
 * VLAN tags between the MACs and the IPv4 header (l2 bytes in all) stay
 * as they are: the answer goes back on the client's VLAN. */
static_always_inline int
dnsfilter_reply (vlib_main_t *vm, dnsfilter_main_t *dm, vlib_buffer_t *b,
		 u32 l2, dnsfilter_query_t *q)
{
  u8 *eth = vlib_buffer_get_current (b);
  ip4_header_t *ip = (ip4_header_t *) (eth + l2);
  udp_header_t *udp = (udp_header_t *) (ip + 1);
  u8 *dns = eth + DNSFILTER_DNS_OFF (l2), *p, mac[6];
  u32 ans = 0, opt = q->has_opt ? 11 : 0, qend, total, room, ttl;
  u8 rcode = 0;
  u32 a;
  u16 port;

  if (q->cats & DNSFILTER_CAT_NXDOMAIN)
    rcode = 3;
  else if (q->qclass == 1 && q->qtype == 1)
    ans = 16;
  else if (q->qclass == 1 && q->qtype == 28)
    ans = 28;
  qend = DNSFILTER_DNS_OFF (l2) + 12 + q->name_len + 1 + 4;
  total = qend + ans + opt;
  room = vlib_buffer_get_default_data_size (vm) - b->current_data;
  if (total > room)
    {
      if (!ans || qend + opt > room)
	return 0;
      ans = 0;
      rcode = 3;
      total = qend + opt;
      vlib_increment_simple_counter (&dm->counters[DNSFILTER_CNT_FP_NXDOMAIN],
				     vm->thread_index, 0, 1);
    }

  clib_memcpy_fast (mac, eth + 6, 6);
  clib_memcpy_fast (eth + 6, eth, 6);
  clib_memcpy_fast (eth, mac, 6);

  a = ip->src_address.as_u32;
  ip->src_address.as_u32 = ip->dst_address.as_u32;
  ip->dst_address.as_u32 = a;
  ip->length = clib_host_to_net_u16 (total - l2);
  ip->ttl = 64;
  ip->flags_and_fragment_offset = 0;
  ip->checksum = ip4_header_checksum (ip);

  port = udp->src_port;
  udp->src_port = udp->dst_port;
  udp->dst_port = port;
  udp->length = clib_host_to_net_u16 (total - l2 - sizeof (ip4_header_t));
  udp->checksum = 0;

  dns[2] = 0x80 | (dns[2] & 0x01); /* QR, RD as asked */
  dns[3] = 0x80 | rcode;	   /* RA */
  dns[6] = 0;
  dns[7] = ans ? 1 : 0; /* ANCOUNT */
  dns[8] = dns[9] = 0;	/* NSCOUNT */
  dns[10] = 0;
  dns[11] = opt ? 1 : 0; /* ARCOUNT */

  p = eth + qend;
  ttl = dm->block_ttl;
  if (ans)
    {
      p[0] = 0xc0;
      p[1] = 0x0c; /* the question's name */
      p[2] = 0;
      p[3] = (u8) q->qtype;
      p[4] = 0;
      p[5] = 1; /* IN */
      p[6] = ttl >> 24;
      p[7] = ttl >> 16;
      p[8] = ttl >> 8;
      p[9] = ttl;
      p[10] = 0;
      p[11] = ans - 12;
      clib_memset (p + 12, 0, ans - 12);
      p += ans;
    }
  if (opt)
    {
      p[0] = 0;
      p[1] = 0;
      p[2] = 41; /* OPT */
      p[3] = DNSFILTER_EDNS_UDP >> 8;
      p[4] = DNSFILTER_EDNS_UDP & 0xff;
      clib_memset (p + 5, 0, 6); /* ext. RCODE, version, flags, rdlength */
    }
  b->current_length = total;
  return 1;
}

/* dnsfilter_event: one "DNF1" frame for a blocked query, collected in
 * evs for the events interface (within DNSFILTER_EVENTS_PER_SEC per
 * worker and second). Returns 0 when it is not logged. */
static_always_inline int
dnsfilter_event (vlib_main_t *vm, dnsfilter_main_t *dm,
		 dnsfilter_per_thread_t *pt, dnsfilter_query_t *q, u32 rx,
		 u32 client_ip, u32 now, u32 *evs, u32 *n_evs)
{
  vlib_buffer_t *e;
  dnsfilter_frame_hdr_t *h;
  dnsfilter_event_t *ev;
  u32 bi;

  if (dm->events_sw_if_index == ~0 || *n_evs >= VLIB_FRAME_SIZE)
    return 0;
  if (pt->event_sec != now)
    {
      pt->event_sec = now;
      pt->event_count = 0;
    }
  if (++pt->event_count > DNSFILTER_EVENTS_PER_SEC)
    return 0;
  if (vlib_buffer_alloc (vm, &bi, 1) != 1)
    return 0;
  e = vlib_get_buffer (vm, bi);
  h = vlib_buffer_get_current (e);
  h->magic = DNSFILTER_FRAME_MAGIC;
  h->sw_if_index = rx;
  h->flags = h->reserved = 0;
  ev = (dnsfilter_event_t *) (h + 1);
  ev->ts_ns = unix_time_now_nsec ();
  ev->client_ip = client_ip;
  ev->cats = q->cats;
  ev->qtype = q->qtype;
  ev->name_len = clib_min (q->name_len, DNSFILTER_EVENT_NAME_MAX);
  clib_memcpy_fast (ev->name, q->name, ev->name_len);
  e->current_length = sizeof (*h) + sizeof (*ev);
  vnet_buffer (e)->sw_if_index[VLIB_RX] = rx;
  vnet_buffer (e)->sw_if_index[VLIB_TX] = dm->events_sw_if_index;
  evs[(*n_evs)++] = bi;
  return 1;
}

/* dnsfilter_client_count: one UDP query of client_ip in this worker's
 * table (Busiest / Active Clients). A full table stops counting new
 * clients. */
static_always_inline void
dnsfilter_client_count (dnsfilter_per_thread_t *pt, u32 client_ip, u32 now)
{
  clib_bihash_kv_8_16_t kv = { .key = client_ip }, val;

  if (clib_bihash_search_8_16 (&pt->stats, &kv, &val) == 0)
    kv.value[0] = val.value[0] + 1;
  else if (pt->n_stats >= DNSFILTER_CLIENT_MAX)
    return;
  else
    {
      kv.value[0] = 1;
      clib_atomic_fetch_add (&pt->n_stats, 1);
    }
  kv.value[1] = now;
  clib_bihash_add_del_8_16 (&pt->stats, &kv, 1 /* add/replace */);
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
  /* the fast path: this worker's state, the table of this frame, unix
   * seconds (shared by every worker: client stats, events) */
  dnsfilter_per_thread_t *pt = vec_elt_at_index (dm->per_thread,
						  vm->thread_index);
  clib_bihash_8_8_t *tbl = dm->block;
  u32 unix_now = 0;
  u32 evs[VLIB_FRAME_SIZE], n_evs = 0, n_lost = 0;
  dnsfilter_query_t q;

  vlib_get_buffers (vm, from, bufs, n_left);

  while (n_left > 0)
    {
      u8 *eth = vlib_buffer_get_current (b[0]);
      u8 *end = eth + b[0]->current_length;
      u32 l2 = vnet_buffer (b[0])->l2.l2_len;
      ip4_header_t *ip;
      u8 *l4;
      u16 sport, dport = 0;
      u8 proto;
      dnsfilter_verdict_t verdict = DNSFILTER_VERDICT_PASS;

      if (n_left > 2)
	vlib_prefetch_buffer_header (b[2], LOAD);

      vnet_feature_next_u16 (next, b[0]);

      /* IPv4 (at most two VLAN tags) TCP/UDP, first fragment, to a
       * unicast MAC */
      if (!dnsfilter_l2_len_ok (l2) || (eth[0] & 1))
	goto done;
      ip = (ip4_header_t *) (eth + l2);
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
      {
	int inspect = dm->intercept && dm->tap_sw_if_index != ~0;
	if ((!inspect && !dm->fastpath) ||
	    !dnsfilter_toward_wan (dm, b[0], eth))
	  goto done;
	if (inspect && !dm->fastpath && !dm->daemon_ok)
	  {
	    /* no fast path: the engine down = no filtering */
	    verdict = DNSFILTER_VERDICT_BYPASS;
	    dnsfilter_count (vm, dm, DNSFILTER_CNT_BYPASS_DAEMON_DOWN);
	    goto done;
	  }
	if (proto == IP_PROTOCOL_UDP)
	  {
	    if (!unix_now)
	      unix_now = (u32) unix_time_now ();
	    dnsfilter_client_count (pt, ip->src_address.as_u32, unix_now);
	  }
	if (dm->client_qps &&
	    !dnsfilter_exempt (dm, ip->src_address.as_u32) &&
	    dnsfilter_client_over (dm, ip->src_address.as_u32, now))
	  {
	    verdict = DNSFILTER_VERDICT_DROP;
	    dnsfilter_count (vm, dm, DNSFILTER_CNT_CLIENT_LIMIT_DROPPED);
	    goto done;
	  }
	if (dm->fastpath && tbl && proto == IP_PROTOCOL_UDP)
	  {
	    if (b[0]->flags & VLIB_BUFFER_NEXT_PRESENT ||
		!dnsfilter_parse (ip, end, &q))
	      dnsfilter_count (vm, dm, DNSFILTER_CNT_FP_SKIPPED);
	    else
	      {
		dnsfilter_count (vm, dm, DNSFILTER_CNT_FP_JUDGED);
		q.cats = dnsfilter_judge (dm, tbl, &q);
		if (q.cats)
		  {
		    u32 rx = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
		    u32 client = ip->src_address.as_u32;
		    if (!unix_now)
		      unix_now = (u32) unix_time_now ();
		    if (!dnsfilter_event (vm, dm, pt, &q, rx, client, unix_now,
					  evs, &n_evs))
		      n_lost++;
		    if (!dnsfilter_reply (vm, dm, b[0], l2, &q))
		      {
			verdict = DNSFILTER_VERDICT_DROP;
			dnsfilter_count (vm, dm, DNSFILTER_CNT_FP_REPLY_FAILED);
			goto done;
		      }
		    vnet_buffer (b[0])->sw_if_index[VLIB_TX] = rx;
		    next[0] = DNSFILTER_NEXT_OUTPUT;
		    verdict = DNSFILTER_VERDICT_BLOCK;
		    dnsfilter_count (vm, dm, DNSFILTER_CNT_FP_BLOCKED);
		    goto done;
		  }
	      }
	  }
	if (!inspect)
	  {
	    dnsfilter_count (vm, dm, DNSFILTER_CNT_FP_PASSED);
	    goto done;
	  }
	if (!dm->daemon_ok)
	  {
	    verdict = DNSFILTER_VERDICT_BYPASS;
	    dnsfilter_count (vm, dm, DNSFILTER_CNT_BYPASS_DAEMON_DOWN);
	    goto done;
	  }
      }
      if ((dm->global_qps && dnsfilter_global_over (dm, now)) ||
	  !dnsfilter_remember (dm,
			       dnsfilter_key (ip->src_address.as_u32, sport,
					      proto),
			       eth, l2, vnet_buffer (b[0])->sw_if_index[VLIB_RX],
			       now))
	{
	  verdict = DNSFILTER_VERDICT_BYPASS;
	  dnsfilter_count (vm, dm, DNSFILTER_CNT_BYPASS_GLOBAL_LIMIT);
	  goto done;
	}
      if (l2 != sizeof (ethernet_header_t))
	{
	  /* the tap's Linux end has no VLAN: the tags (saved in the return
	   * entry) come off, the MACs move up over them */
	  u32 n = l2 - sizeof (ethernet_header_t);
	  memmove (eth + n, eth, 12);
	  vlib_buffer_advance (b[0], n);
	  eth += n;
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

  if (n_evs)
    {
      vnet_hw_interface_t *hw =
	vnet_get_sup_hw_interface (dm->vnet_main, dm->events_sw_if_index);
      vlib_frame_t *f = vlib_get_frame_to_node (vm, hw->output_node_index);
      clib_memcpy_fast (vlib_frame_vector_args (f), evs, n_evs * sizeof (u32));
      f->n_vectors = n_evs;
      vlib_put_frame_to_node (vm, hw->output_node_index, f);
    }
  if (n_lost)
    vlib_increment_simple_counter (&dm->counters[DNSFILTER_CNT_FP_EVENT_LOST],
				   vm->thread_index, 0, n_lost);
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
      clib_bihash_kv_8_24_t kv, val;
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
      if (clib_bihash_search_8_24 (&dm->ret, &kv, &val))
	goto miss;
      r.as_u64[0] = val.value[0];
      r.as_u64[1] = val.value[1];
      r.as_u64[2] = val.value[2];
      if (r.tags[0])
	{
	  /* the query's VLAN tags go back in front of the ethertype; the
	   * buffer's headroom takes them */
	  u32 n = r.tags[1] ? 8 : 4;
	  vlib_buffer_advance (b[0], -(word) n);
	  e = vlib_buffer_get_current (b[0]);
	  clib_memcpy_fast ((u8 *) e + 12, r.tags, n);
	}
      clib_memcpy_fast (e->dst_address, r.client_mac, 6);
      clib_memcpy_fast (e->src_address, r.gw_mac, 6);
      vnet_buffer (b[0])->sw_if_index[VLIB_TX] = r.sw_if_index;
      /* A UDP query has exactly one answer: free its entry now (a TCP
       * connection keeps it for the next query, the sweep ends it). */
      if (ip->protocol == IP_PROTOCOL_UDP &&
	  clib_bihash_add_del_8_24 (&dm->ret, &kv, 0 /* del */) == 0)
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
