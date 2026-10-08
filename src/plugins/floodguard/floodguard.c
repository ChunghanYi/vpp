/* SPDX-License-Identifier: Apache-2.0 */

/*
 * floodguard.c — mighty_xddos Flood Guard (VPP mode) control plane.
 * virtserver drives it through vppctl (ddos/floodguard_vpp.go):
 *
 *   floodguard interface <interface> enable [arp <policer>] [broadcast <policer>]
 *                                         [ctrl <policer>] [multicast <policer>]
 *   floodguard interface <interface> disable
 *   floodguard interface <interface> ip6-drop enable|disable
 *   floodguard interface <interface> wan-reply enable|disable
 *   floodguard wan-reply ports [tcp <list>] [udp <list>] [all]
 *   floodguard flood syn|udp|icmp rate <pps> burst <packets>
 *   floodguard flood share <workers>
 *   floodguard victim add <ip4> syn|udp|icmp [port <n>]
 *   floodguard victim add <ip4> syn-challenge
 *   floodguard victim del <ip4> syn|udp|icmp|syn-challenge
 *   floodguard victim clear
 *   floodguard syn-challenge [whitelist-ttl <seconds>] [whitelist-size <n>]
 *   show floodguard [victims]
 *
 * "enable" replaces the interface's whole Broadcast Filter configuration
 * (a policer left out = that kind is not policed). The victim node is
 * always attached to an enabled interface (victim policing and the SYN
 * Reset Challenge); the storm nodes only while some Broadcast Filter
 * policer is set. "ip6-drop" drops every IPv6 frame entering the bridge on
 * the interface (storm IPv6 node, ahead of the ACL), independently of
 * enable/disable.
 *
 * "wan-reply" (WAN interface, independent of enable/disable too) lets
 * server replies — and ICMP destination-unreachable/time-exceeded, always —
 * leave without passing the output ACL (node.c's floodguard-wan-reply);
 * "wan-reply ports" replaces the whole port set —
 * <list> as "80,443,8000-8100", "all" for every IPv4 packet, no argument
 * to clear it.
 *
 * "flood" sets one flood type's limit for the whole box (rate 0 = not
 * limited); every victim armed for that type gets its own bucket with
 * that limit, split evenly over the workers polling the victim
 * interfaces' rx queues ("flood share", see floodguard_flood_share).
 */

#include <sys/random.h>

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/format.h>
#include <vnet/l2/l2_in_out_feat_arc.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

#include <floodguard/floodguard.h>

floodguard_main_t floodguard_main;

static const char *const floodguard_l2_kind_keywords[FLOODGUARD_N_L2_KIND] = {
  "arp", "broadcast", "ctrl", "multicast"
};

static const char *const floodguard_flood_keywords[FLOODGUARD_N_FLOOD] = {
  "syn", "udp", "icmp"
};

static const u64 floodguard_flood_bits[FLOODGUARD_N_FLOOD] = {
  FLOODGUARD_V_SYN, FLOODGUARD_V_UDP, FLOODGUARD_V_ICMP
};

static const char *const
  floodguard_flood_stat_names[FLOODGUARD_N_FLOOD][FLOODGUARD_N_FLOOD_COUNTER] = {
    { "/floodguard/flood/syn/conform", "/floodguard/flood/syn/violate" },
    { "/floodguard/flood/udp/conform", "/floodguard/flood/udp/violate" },
    { "/floodguard/flood/icmp/conform", "/floodguard/flood/icmp/violate" },
  };

static const char *const floodguard_drop_counter_names[FLOODGUARD_N_KIND] = {
  [FLOODGUARD_KIND_NONE] = "none",
  [FLOODGUARD_KIND_ARP] = "arp",
  [FLOODGUARD_KIND_BROADCAST] = "broadcast",
  [FLOODGUARD_KIND_CTRL] = "l2-control",
  [FLOODGUARD_KIND_MULTICAST] = "multicast",
  [FLOODGUARD_KIND_SYN] = "syn",
  [FLOODGUARD_KIND_UDP] = "udp",
  [FLOODGUARD_KIND_ICMP] = "icmp",
  [FLOODGUARD_KIND_SYN_CHALLENGE] = "syn-challenge",
  [FLOODGUARD_KIND_IPV6] = "ipv6",
};

static const char *const floodguard_drop_stat_names[FLOODGUARD_N_KIND] = {
  [FLOODGUARD_KIND_NONE] = "/floodguard/drops/none",
  [FLOODGUARD_KIND_ARP] = "/floodguard/drops/arp",
  [FLOODGUARD_KIND_BROADCAST] = "/floodguard/drops/broadcast",
  [FLOODGUARD_KIND_CTRL] = "/floodguard/drops/l2-control",
  [FLOODGUARD_KIND_MULTICAST] = "/floodguard/drops/multicast",
  [FLOODGUARD_KIND_SYN] = "/floodguard/drops/syn",
  [FLOODGUARD_KIND_UDP] = "/floodguard/drops/udp",
  [FLOODGUARD_KIND_ICMP] = "/floodguard/drops/icmp",
  [FLOODGUARD_KIND_SYN_CHALLENGE] = "/floodguard/drops/syn-challenge",
  [FLOODGUARD_KIND_IPV6] = "/floodguard/drops/ipv6",
};

static const char *const
  floodguard_challenge_counter_names[FLOODGUARD_N_CHALLENGE_COUNTER] = {
    [FLOODGUARD_CHALLENGE_CHALLENGED] = "challenged",
    [FLOODGUARD_CHALLENGE_VERIFIED] = "verified",
    [FLOODGUARD_CHALLENGE_PERMITTED] = "permitted",
    [FLOODGUARD_CHALLENGE_WHITELIST_FULL] = "whitelist-full",
    [FLOODGUARD_CHALLENGE_SWEPT_WHITELIST] = "swept-whitelist",
  };

static const char *const
  floodguard_challenge_stat_names[FLOODGUARD_N_CHALLENGE_COUNTER] = {
    [FLOODGUARD_CHALLENGE_CHALLENGED] = "/floodguard/challenge/challenged",
    [FLOODGUARD_CHALLENGE_VERIFIED] = "/floodguard/challenge/verified",
    [FLOODGUARD_CHALLENGE_PERMITTED] = "/floodguard/challenge/permitted",
    [FLOODGUARD_CHALLENGE_WHITELIST_FULL] =
      "/floodguard/challenge/whitelist-full",
    [FLOODGUARD_CHALLENGE_SWEPT_WHITELIST] =
      "/floodguard/challenge/swept-whitelist",
  };

static u64
floodguard_challenge_count (floodguard_main_t *fm,
			    floodguard_challenge_counter_t c)
{
  return vlib_get_simple_counter (&fm->challenge_counters[c], 0);
}

/* floodguard_default_threads: the share count until virtserver sets one —
 * every worker, so a limit errs on the strict side. */
static u32
floodguard_default_threads (void)
{
  return clib_max (vlib_num_workers (), 1);
}

/* floodguard_flood_share: split flood type i's limit evenly over
 * n_share_threads workers. Main thread. ticks_per_token is the "limited" switch
 * the workers test, so it is written last when a limit is set and first
 * when it is removed. */
static void
floodguard_flood_share (vlib_main_t *vm, floodguard_main_t *fm, int i)
{
  floodguard_flood_t *f = &fm->flood[i];
  u32 n = fm->n_share_threads;
  u64 rate, burst, tpt;

  if (!f->rate_pps)
    {
      f->ticks_per_token = 0;
      return;
    }
  rate = clib_max (f->rate_pps / n, 1);
  burst = clib_max (f->burst / n, 1);
  tpt = clib_max ((u64) vm->clib_time.clocks_per_second / rate, 1);
  f->burst_per_thread = burst;
  f->fill_ticks = burst * tpt;
  f->ticks_per_token = tpt;
}

/* floodguard_victim_free: release a victim record (CLI barrier). */
static void
floodguard_victim_free (floodguard_main_t *fm, u32 index)
{
  floodguard_victim_t *fv = pool_elt_at_index (fm->victim_pool, index);
  vec_free (fv->threads);
  pool_put (fm->victim_pool, fv);
}

/* floodguard_victim_alloc: a new victim record with empty buckets and
 * zeroed counters (CLI barrier; a pool index can be reused). */
static u32
floodguard_victim_alloc (floodguard_main_t *fm)
{
  floodguard_victim_t *fv;
  u32 index, t, c;

  pool_get_zero (fm->victim_pool, fv);
  vec_validate_aligned (fv->threads, vlib_get_n_threads () - 1,
			CLIB_CACHE_LINE_BYTES);
  index = fv - fm->victim_pool;
  for (t = 0; t < FLOODGUARD_N_FLOOD; t++)
    for (c = 0; c < FLOODGUARD_N_FLOOD_COUNTER; c++)
      {
	vlib_validate_simple_counter (&fm->victim_counters[t][c], index);
	vlib_zero_simple_counter (&fm->victim_counters[t][c], index);
      }
  return index;
}

/* floodguard_whitelist_buckets: one bucket per two whitelist entries. */
static u32
floodguard_whitelist_buckets (u32 max_entries)
{
  return max_entries / 2;
}

/* floodguard_challenge_tables: create the SYN Reset Challenge whitelist on
 * the first challenge victim, sized for challenge_whitelist_max. Main
 * thread, with the workers stopped (CLI barrier): the victim node only
 * reads it once a challenge victim exists, which is armed after this
 * returns. */
static void
floodguard_challenge_tables (floodguard_main_t *fm)
{
  if (fm->challenge_tables_ready)
    return;
  fm->challenge_whitelist_buckets =
    floodguard_whitelist_buckets (fm->challenge_whitelist_max);
  clib_bihash_init_8_8 (&fm->challenge_whitelist,
			"floodguard challenge whitelist",
			fm->challenge_whitelist_buckets, 0);
  fm->n_whitelist = 0;
  fm->challenge_tables_ready = 1;
}

/* floodguard_policer_main: the policer plugin's state, resolved once
 * through its exported accessors (plugins load in any order, so not at
 * init time). */
static policer_main_t *
floodguard_policer_main (floodguard_main_t *fm)
{
  if (!fm->pm)
    {
      fm->policer_counters = policer_get_counters ();
      fm->pm = fm->policer_counters ? policer_get_main () : 0;
    }
  return fm->pm;
}

/* floodguard_policer_index: policer name -> index, or an error. */
static clib_error_t *
floodguard_policer_index (floodguard_main_t *fm, u8 *name, u32 *index)
{
  policer_main_t *pm = floodguard_policer_main (fm);
  uword *p;

  if (!pm)
    return clib_error_return (0, "policer plugin not loaded");
  vec_add1 (name, 0);
  p = hash_get_mem (pm->policer_index_by_name, name);
  if (!p)
    {
      clib_error_t *e = clib_error_return (0, "policer '%s' not found", name);
      vec_free (name);
      return e;
    }
  vec_free (name);
  *index = p[0];
  return 0;
}

/* floodguard_wanted_arcs: the nodes ifc's settings need — the victim node
 * while enabled, the storm nodes while some Broadcast Filter policer is
 * set, the IPv6 storm node while ip6_drop is on, and the WAN reply node
 * while wan_reply is on. */
static u8
floodguard_wanted_arcs (floodguard_if_t *ifc)
{
  u8 want = 0;
  int i, storm = 0;

  for (i = 0; i < FLOODGUARD_N_L2_KIND; i++)
    if (ifc->policer[i] != ~0)
      storm = 1;
  if (ifc->enabled)
    {
      want |= FLOODGUARD_ARC_VICTIM;
      if (storm)
	want |= FLOODGUARD_ARC_STORM_IP4 | FLOODGUARD_ARC_STORM_IP6 |
		FLOODGUARD_ARC_STORM_NONIP;
    }
  if (ifc->ip6_drop)
    want |= FLOODGUARD_ARC_STORM_IP6;
  if (ifc->wan_reply)
    want |= FLOODGUARD_ARC_WAN_REPLY;
  return want;
}

static void
floodguard_set_arcs (floodguard_if_t *ifc, u32 sw_if_index, u8 want)
{
  static const struct
  {
    u8 bit;
    const char *arc;
    const char *node;
  } arcs[] = {
    { FLOODGUARD_ARC_STORM_IP4, "l2-input-ip4", "floodguard-l2-ip4" },
    { FLOODGUARD_ARC_STORM_IP6, "l2-input-ip6", "floodguard-l2-ip6" },
    { FLOODGUARD_ARC_STORM_NONIP, "l2-input-nonip", "floodguard-l2-nonip" },
    { FLOODGUARD_ARC_VICTIM, "l2-input-ip4", "floodguard-victim" },
    { FLOODGUARD_ARC_WAN_REPLY, "l2-output-ip4", "floodguard-wan-reply" },
  };
  int i;

  for (i = 0; i < ARRAY_LEN (arcs); i++)
    {
      int on = (want & arcs[i].bit) != 0;
      if (on == ((ifc->arcs & arcs[i].bit) != 0))
	continue;
      vnet_l2_feature_enable_disable (arcs[i].arc, arcs[i].node, sw_if_index,
				      on, 0, 0);
    }
  ifc->arcs = want;
}

static clib_error_t *
floodguard_interface_command_fn (vlib_main_t *vm, unformat_input_t *input,
				 vlib_cli_command_t *cmd)
{
  floodguard_main_t *fm = &floodguard_main;
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index = ~0, policer[FLOODGUARD_N_L2_KIND];
  int enable = -1, ip6_drop = -1, wan_reply = -1, i;
  clib_error_t *error = 0;
  u8 *name = 0;

  for (i = 0; i < FLOODGUARD_N_L2_KIND; i++)
    policer[i] = ~0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      int matched = 0;
      if (unformat (input, "ip6-drop enable"))
	ip6_drop = 1;
      else if (unformat (input, "ip6-drop disable"))
	ip6_drop = 0;
      else if (unformat (input, "wan-reply enable"))
	wan_reply = 1;
      else if (unformat (input, "wan-reply disable"))
	wan_reply = 0;
      else if (unformat (input, "enable"))
	enable = 1;
      else if (unformat (input, "disable"))
	enable = 0;
      else if (unformat (input, "%U", unformat_vnet_sw_interface, vnm,
			 &sw_if_index))
	;
      else
	{
	  for (i = 0; i < FLOODGUARD_N_L2_KIND; i++)
	    if (unformat (input, floodguard_l2_kind_keywords[i]))
	      {
		if (!unformat (input, "%s", &name))
		  return clib_error_return (0, "%s: policer name expected",
					    floodguard_l2_kind_keywords[i]);
		if ((error = floodguard_policer_index (fm, name, &policer[i])))
		  return error;
		name = 0;
		matched = 1;
		break;
	      }
	  if (!matched)
	    return clib_error_return (0, "unknown input '%U'",
				      format_unformat_error, input);
	}
    }
  if (sw_if_index == ~0 ||
      (enable >= 0) + (ip6_drop >= 0) + (wan_reply >= 0) != 1)
    return clib_error_return (
      0, "specify an interface and one of enable|disable, ip6-drop "
	 "enable|disable or wan-reply enable|disable");
  /* The WAN reply node skips to the arc end, so it must be the ACL node's
   * only follower on this arc (node.c). */
  if (wan_reply == 1 &&
      vnet_feature_is_enabled ("l2-output-ip4", "gso-l2-ip4", sw_if_index))
    return clib_error_return (
      0, "wan-reply: gso-l2-ip4 is enabled on %U", format_vnet_sw_if_index_name,
      vnm, sw_if_index);

  floodguard_if_t empty = { .policer = { ~0, ~0, ~0, ~0 } };
  vec_validate_init_empty (fm->ifs, sw_if_index, empty);
  floodguard_if_t *ifc = vec_elt_at_index (fm->ifs, sw_if_index);
  if (ip6_drop >= 0)
    ifc->ip6_drop = ip6_drop;
  else if (wan_reply >= 0)
    ifc->wan_reply = wan_reply;
  else
    {
      /* enable replaces the whole storm/victim configuration; disable
       * clears it. */
      ifc->enabled = enable;
      for (i = 0; i < FLOODGUARD_N_L2_KIND; i++)
	ifc->policer[i] = enable ? policer[i] : ~0;
    }
  floodguard_set_arcs (ifc, sw_if_index, floodguard_wanted_arcs (ifc));
  return 0;
}

static clib_error_t *
floodguard_victim_command_fn (vlib_main_t *vm, unformat_input_t *input,
			      vlib_cli_command_t *cmd)
{
  floodguard_main_t *fm = &floodguard_main;
  ip4_address_t addr;
  int is_add = -1, clear = 0, type = -1, i;
  u32 port = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "add %U", unformat_ip4_address, &addr))
	is_add = 1;
      else if (unformat (input, "del %U", unformat_ip4_address, &addr))
	is_add = 0;
      else if (unformat (input, "clear"))
	clear = 1;
      else if (unformat (input, "syn-challenge"))
	type = FLOODGUARD_N_FLOOD;
      else if (unformat (input, "port %u", &port))
	{
	  if (port > 65535)
	    return clib_error_return (0, "port out of range");
	}
      else
	{
	  for (i = 0; i < FLOODGUARD_N_FLOOD; i++)
	    if (unformat (input, floodguard_flood_keywords[i]))
	      {
		type = i;
		break;
	      }
	  if (i == FLOODGUARD_N_FLOOD)
	    return clib_error_return (0, "unknown input '%U'",
				      format_unformat_error, input);
	}
    }

  if (clear)
    {
      floodguard_victim_t *fv;
      pool_foreach (fv, fm->victim_pool)
	vec_free (fv->threads);
      pool_free (fm->victim_pool);
      clib_bihash_free_8_8 (&fm->victims);
      clib_bihash_init_8_8 (&fm->victims, "floodguard victims",
			    FLOODGUARD_VICTIM_BUCKETS,
			    FLOODGUARD_VICTIM_MEMORY);
      fm->n_victims = 0;
      return 0;
    }
  if (is_add < 0 || type < 0)
    return clib_error_return (
      0, "specify add|del <ip4> and syn|udp|icmp|syn-challenge");
  if (type == FLOODGUARD_N_FLOOD)
    {
      if (port)
	return clib_error_return (0, "syn-challenge takes no port");
      if (is_add)
	floodguard_challenge_tables (fm);
    }
  if (port && type == FLOODGUARD_N_FLOOD - 1)
    return clib_error_return (0, "icmp has no port");

  clib_bihash_kv_8_8_t kv, val;
  kv.key = addr.as_u32;
  int exists = clib_bihash_search_8_8 (&fm->victims, &kv, &val) == 0;
  u64 v = exists ? val.value : 0;
  u64 was = v;

  switch (type)
    {
    case 0:
      v &= ~(FLOODGUARD_V_SYN | (0xffffULL << 16));
      if (is_add)
	v |= FLOODGUARD_V_SYN | ((u64) port << 16);
      break;
    case 1:
      v &= ~(FLOODGUARD_V_UDP | 0xffffULL);
      if (is_add)
	v |= FLOODGUARD_V_UDP | port;
      break;
    case 2:
      v &= ~FLOODGUARD_V_ICMP;
      if (is_add)
	v |= FLOODGUARD_V_ICMP;
      break;
    default:
      v &= ~FLOODGUARD_V_SYN_CHALLENGE;
      if (is_add)
	v |= FLOODGUARD_V_SYN_CHALLENGE;
    }
  if (v & FLOODGUARD_V_ANY)
    {
      if (!exists)
	{
	  if (pool_elts (fm->victim_pool) > FLOODGUARD_V_MAX_INDEX)
	    return clib_error_return (0, "victim table full");
	  v |= (u64) floodguard_victim_alloc (fm) << FLOODGUARD_V_INDEX_SHIFT;
	}
      else if (type < FLOODGUARD_N_FLOOD &&
	       !(was & floodguard_flood_bits[type]))
	{
	  /* Newly armed type: its buckets start full (last_tick 0). */
	  floodguard_victim_t *fv =
	    pool_elt_at_index (fm->victim_pool, FLOODGUARD_V_INDEX (v));
	  floodguard_victim_thread_t *vt;
	  vec_foreach (vt, fv->threads)
	    clib_memset (&vt->bucket[type], 0, sizeof (vt->bucket[type]));
	}
      kv.value = v;
      if (clib_bihash_add_del_8_8 (&fm->victims, &kv, 1))
	{
	  if (!exists)
	    floodguard_victim_free (fm, FLOODGUARD_V_INDEX (v));
	  return clib_error_return (0, "victim table full");
	}
      if (!exists)
	fm->n_victims++;
    }
  else if (exists)
    {
      clib_bihash_add_del_8_8 (&fm->victims, &kv, 0);
      floodguard_victim_free (fm, FLOODGUARD_V_INDEX (v));
      fm->n_victims--;
    }
  return 0;
}

static clib_error_t *
floodguard_flood_command_fn (vlib_main_t *vm, unformat_input_t *input,
			     vlib_cli_command_t *cmd)
{
  floodguard_main_t *fm = &floodguard_main;
  u32 rate = ~0, burst = ~0, share = 0;
  int type = -1, i;

  if (unformat (input, "share %u", &share))
    {
      if (share < 1 || share > vlib_get_n_threads ())
	return clib_error_return (0, "share must be 1-%u",
				  vlib_get_n_threads ());
      if (share != fm->n_share_threads)
	{
	  fm->n_share_threads = share;
	  for (i = 0; i < FLOODGUARD_N_FLOOD; i++)
	    floodguard_flood_share (vm, fm, i);
	}
      return 0;
    }

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "rate %u", &rate))
	;
      else if (unformat (input, "burst %u", &burst))
	;
      else
	{
	  for (i = 0; i < FLOODGUARD_N_FLOOD; i++)
	    if (unformat (input, floodguard_flood_keywords[i]))
	      {
		type = i;
		break;
	      }
	  if (i == FLOODGUARD_N_FLOOD)
	    return clib_error_return (0, "unknown input '%U'",
				      format_unformat_error, input);
	}
    }
  if (type < 0 || rate == ~0 || burst == ~0)
    return clib_error_return (
      0, "specify syn|udp|icmp rate <pps> burst <packets>");
  if (rate && !burst)
    return clib_error_return (0, "burst must be > 0");

  fm->flood[type].rate_pps = rate;
  fm->flood[type].burst = burst;
  floodguard_flood_share (vm, fm, type);
  return 0;
}

static u8 *
format_floodguard_policer (u8 *s, va_list *args)
{
  floodguard_main_t *fm = va_arg (*args, floodguard_main_t *);
  u32 pi = va_arg (*args, u32);

  if (pi == ~0)
    return format (s, "-");
  if (!fm->pm || pool_is_free_index (fm->pm->policers, pi))
    return format (s, "%u (invalid)", pi);
  return format (s, "%s", pool_elt_at_index (fm->pm->policers, pi)->name);
}

typedef struct
{
  vlib_main_t *vm;
  u32 n;
} floodguard_show_ctx_t;

static int
floodguard_show_victim (clib_bihash_kv_8_8_t *kv, void *arg)
{
  floodguard_show_ctx_t *ctx = arg;
  floodguard_main_t *fm = &floodguard_main;
  ip4_address_t addr = { .as_u32 = (u32) kv->key };
  u64 v = kv->value;
  u32 index = FLOODGUARD_V_INDEX (v);
  u8 *s = format (0, "  %U:", format_ip4_address, &addr);
  int t;

  if (v & FLOODGUARD_V_SYN)
    s = FLOODGUARD_V_SYN_PORT (v) ?
	  format (s, " syn port %u", FLOODGUARD_V_SYN_PORT (v)) :
	  format (s, " syn");
  if (v & FLOODGUARD_V_UDP)
    s = FLOODGUARD_V_UDP_PORT (v) ?
	  format (s, " udp port %u", FLOODGUARD_V_UDP_PORT (v)) :
	  format (s, " udp");
  if (v & FLOODGUARD_V_ICMP)
    s = format (s, " icmp");
  if (v & FLOODGUARD_V_SYN_CHALLENGE)
    s = format (s, " syn-challenge");
  vlib_cli_output (ctx->vm, "%v", s);
  vec_free (s);
  /* virtserver parses these lines (ddos/floodguard_vpp.go). */
  for (t = 0; t < FLOODGUARD_N_FLOOD; t++)
    if (v & (floodguard_flood_bits[t] |
	     (t == 0 ? FLOODGUARD_V_SYN_CHALLENGE : 0)))
      vlib_cli_output (
	ctx->vm, "    %s conform %llu violate %llu",
	floodguard_flood_keywords[t],
	vlib_get_simple_counter (
	  &fm->victim_counters[t][FLOODGUARD_FLOOD_CONFORM], index),
	vlib_get_simple_counter (
	  &fm->victim_counters[t][FLOODGUARD_FLOOD_VIOLATE], index));
  ctx->n++;
  return BIHASH_WALK_CONTINUE;
}

/* floodguard_ports_from_bitmap: set dst's bits from a parsed port list. */
static clib_error_t *
floodguard_ports_from_bitmap (u8 *dst, uword *ports, const char *proto)
{
  uword port;

  if (clib_bitmap_last_set (ports) > 65535)
    return clib_error_return (0, "%s: port above 65535", proto);
  clib_bitmap_foreach (port, ports)
    dst[port >> 3] |= 1 << (port & 7);
  return 0;
}

static clib_error_t *
floodguard_wan_reply_command_fn (vlib_main_t *vm, unformat_input_t *input,
				 vlib_cli_command_t *cmd)
{
  floodguard_main_t *fm = &floodguard_main;
  u8 tcp[sizeof (fm->wan_reply_tcp)] = {}, udp[sizeof (fm->wan_reply_udp)] = {};
  uword *ports = 0;
  clib_error_t *error = 0;
  u8 all = 0;

  if (!unformat (input, "ports"))
    return clib_error_return (0, "expected 'ports'");
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "tcp %U", unformat_bitmap_list, &ports))
	error = floodguard_ports_from_bitmap (tcp, ports, "tcp");
      else if (unformat (input, "udp %U", unformat_bitmap_list, &ports))
	error = floodguard_ports_from_bitmap (udp, ports, "udp");
      else if (unformat (input, "all"))
	all = 1;
      else
	error = clib_error_return (0, "unknown input '%U'",
				   format_unformat_error, input);
      clib_bitmap_free (ports);
      if (error)
	return error;
    }
  /* Not mp-safe: the workers are stopped while the sets change. */
  clib_memcpy_fast (fm->wan_reply_tcp, tcp, sizeof (tcp));
  clib_memcpy_fast (fm->wan_reply_udp, udp, sizeof (udp));
  fm->wan_reply_all = all;
  return 0;
}

/* format_floodguard_ports: a port bitmap as "80,443,8000-8100" ("none"). */
static u8 *
format_floodguard_ports (u8 *s, va_list *args)
{
  const u8 *bitmap = va_arg (*args, const u8 *);
  u32 port = 0, first;
  int n = 0;

  while (port < 65536)
    {
      if (!((bitmap[port >> 3] >> (port & 7)) & 1))
	{
	  port++;
	  continue;
	}
      first = port;
      while (port + 1 < 65536 &&
	     ((bitmap[(port + 1) >> 3] >> ((port + 1) & 7)) & 1))
	port++;
      s = format (s, "%s%u", n++ ? "," : "", first);
      if (port != first)
	s = format (s, "-%u", port);
      port++;
    }
  if (!n)
    s = format (s, "none");
  return s;
}

static clib_error_t *
show_floodguard_command_fn (vlib_main_t *vm, unformat_input_t *input,
			    vlib_cli_command_t *cmd)
{
  floodguard_main_t *fm = &floodguard_main;
  vnet_main_t *vnm = vnet_get_main ();
  int victims = unformat (input, "victims");
  u32 sw_if_index;
  int i;

  floodguard_policer_main (fm);
  if (victims)
    {
      floodguard_show_ctx_t ctx = { .vm = vm };
      clib_bihash_foreach_key_value_pair_8_8 (&fm->victims,
					      floodguard_show_victim, &ctx);
      vlib_cli_output (vm, "Victims: %u", ctx.n);
      return 0;
    }

  vlib_cli_output (vm, "Flood Guard:");
  vlib_cli_output (vm, "  Interfaces:");
  vec_foreach_index (sw_if_index, fm->ifs)
    {
      floodguard_if_t *ifc = vec_elt_at_index (fm->ifs, sw_if_index);
      if (!ifc->arcs)
	continue;
      vlib_cli_output (vm,
		       "    %U: %s, arp %U, broadcast %U, ctrl %U, multicast %U, "
		       "ip6-drop %s, wan-reply %s",
		       format_vnet_sw_if_index_name, vnm, sw_if_index,
		       ifc->enabled ? "enabled" : "disabled",
		       format_floodguard_policer, fm, ifc->policer[0],
		       format_floodguard_policer, fm, ifc->policer[1],
		       format_floodguard_policer, fm, ifc->policer[2],
		       format_floodguard_policer, fm, ifc->policer[3],
		       ifc->ip6_drop ? "on" : "off",
		       ifc->wan_reply ? "on" : "off");
    }
  if (fm->wan_reply_all)
    vlib_cli_output (vm, "  WAN reply ports: all");
  else
    vlib_cli_output (vm, "  WAN reply ports: tcp %U, udp %U, + ICMP errors",
		     format_floodguard_ports, fm->wan_reply_tcp,
		     format_floodguard_ports, fm->wan_reply_udp);
  vlib_cli_output (vm, "  WAN replies past the output ACL: %llu",
		   vlib_get_simple_counter (&fm->wan_reply_skipped, 0));
  vlib_cli_output (vm, "  Victims: %u", fm->n_victims);
  /* virtserver parses the "<type>: ... conform <n>, violate <n>" lines
   * (ddos/floodguard_vpp.go). */
  vlib_cli_output (vm, "  Flood limits (split over %u worker%s):",
		   fm->n_share_threads, fm->n_share_threads == 1 ? "" : "s");
  for (i = 0; i < FLOODGUARD_N_FLOOD; i++)
    {
      floodguard_flood_t *f = &fm->flood[i];
      u64 conform = vlib_get_simple_counter (
	&fm->flood_counters[i][FLOODGUARD_FLOOD_CONFORM], 0);
      u64 violate = vlib_get_simple_counter (
	&fm->flood_counters[i][FLOODGUARD_FLOOD_VIOLATE], 0);
      if (f->rate_pps)
	vlib_cli_output (vm,
			 "    %s: rate %u pps, burst %u, conform %llu, "
			 "violate %llu",
			 floodguard_flood_keywords[i], f->rate_pps, f->burst,
			 conform, violate);
      else
	vlib_cli_output (vm, "    %s: off, conform %llu, violate %llu",
			 floodguard_flood_keywords[i], conform, violate);
    }
  vlib_cli_output (vm, "  Drops:");
  for (i = FLOODGUARD_KIND_ARP; i < FLOODGUARD_N_KIND; i++)
    vlib_cli_output (vm, "    %-13s %llu", floodguard_drop_counter_names[i],
		     vlib_get_simple_counter (&fm->drop_counters[i], 0));
  /* virtserver parses these labels (ddos/floodguard_vpp.go). */
  vlib_cli_output (vm, "  SYN Reset Challenge:");
  vlib_cli_output (vm, "    Whitelist TTL:     %us",
		   fm->challenge_whitelist_ttl_sec);
  vlib_cli_output (
    vm, "    Challenged (SYN-ACK reflected): %llu",
    floodguard_challenge_count (fm, FLOODGUARD_CHALLENGE_CHALLENGED));
  vlib_cli_output (
    vm, "    Verified (RST matched):         %llu",
    floodguard_challenge_count (fm, FLOODGUARD_CHALLENGE_VERIFIED));
  vlib_cli_output (
    vm, "    Permitted (already verified):   %llu",
    floodguard_challenge_count (fm, FLOODGUARD_CHALLENGE_PERMITTED));
  vlib_cli_output (
    vm,
    "    Whitelist:                      %u/%u (refused at cap %llu, "
    "expired %llu)",
    fm->n_whitelist, fm->challenge_whitelist_max,
    floodguard_challenge_count (fm, FLOODGUARD_CHALLENGE_WHITELIST_FULL),
    floodguard_challenge_count (fm, FLOODGUARD_CHALLENGE_SWEPT_WHITELIST));
  if (!fm->cookie_key_ready)
    vlib_cli_output (vm, "    Disabled: no cookie key (see VPP log)");
  return 0;
}

static clib_error_t *
floodguard_challenge_command_fn (vlib_main_t *vm, unformat_input_t *input,
				 vlib_cli_command_t *cmd)
{
  floodguard_main_t *fm = &floodguard_main;
  u32 ttl = 0, size = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "whitelist-ttl %u", &ttl))
	{
	  if (ttl == 0)
	    return clib_error_return (0, "whitelist-ttl must be > 0");
	}
      else if (unformat (input, "whitelist-size %u", &size))
	{
	  if (size < FLOODGUARD_CHALLENGE_WHITELIST_MIN ||
	      size > FLOODGUARD_CHALLENGE_WHITELIST_MAX)
	    return clib_error_return (0, "whitelist-size must be %u-%u",
				      FLOODGUARD_CHALLENGE_WHITELIST_MIN,
				      FLOODGUARD_CHALLENGE_WHITELIST_MAX);
	}
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }
  if (!ttl && !size)
    return clib_error_return (
      0, "specify whitelist-ttl <seconds> and/or whitelist-size <n>");
  if (ttl)
    fm->challenge_whitelist_ttl_sec = ttl;
  if (size && size != fm->challenge_whitelist_max)
    {
      fm->challenge_whitelist_max = size;
      /* An existing table keeps its entries while its bucket count still
       * fits the new size; otherwise it is rebuilt and the verified
       * clients are challenged once more. Workers are stopped (CLI
       * barrier). */
      if (fm->challenge_tables_ready &&
	  floodguard_whitelist_buckets (size) !=
	    fm->challenge_whitelist_buckets)
	{
	  clib_bihash_free_8_8 (&fm->challenge_whitelist);
	  fm->challenge_tables_ready = 0;
	  floodguard_challenge_tables (fm);
	}
    }
  return 0;
}

/* floodguard_challenge_sweep_whitelist: drop expired entries — a bihash
 * never evicts on its own. Walked bucket by bucket with a time budget,
 * like l2fib_scan. */
static void
floodguard_challenge_sweep_whitelist (vlib_main_t *vm, floodguard_main_t *fm)
{
  clib_bihash_8_8_t *h = &fm->challenge_whitelist;
  u64 now = (u64) vlib_time_now (vm);
  f64 last_start = vlib_time_now (vm);
  u32 n_swept = 0, i, j, k;

  for (i = 0; i < h->nbuckets; i++)
    {
      if (vlib_time_now (vm) - last_start > 20e-6)
	{
	  vlib_process_suspend (vm, 100e-6);
	  last_start = vlib_time_now (vm);
	}
      clib_bihash_bucket_8_8_t *b = clib_bihash_get_bucket_8_8 (h, i);
      if (clib_bihash_bucket_is_empty_8_8 (b))
	continue;
      clib_bihash_value_8_8_t *v = clib_bihash_get_value_8_8 (h, b->offset);
      for (j = 0; j < (1U << b->log2_pages); j++, v++)
	for (k = 0; k < 7 /* bihash_8_8 KVP per page */; k++)
	  {
	    if (clib_bihash_is_free_8_8 (&v->kvp[k]) ||
		now < v->kvp[k].value)
	      continue;
	    clib_bihash_kv_8_8_t kv = v->kvp[k];
	    if (clib_bihash_add_del_8_8 (h, &kv, 0) == 0)
	      {
	        clib_atomic_fetch_sub (&fm->n_whitelist, 1);
	        n_swept++;
	      }
	    if (clib_bihash_bucket_is_empty_8_8 (b))
	      goto next_bucket;
	  }
    next_bucket:;
    }
  if (n_swept)
    vlib_increment_simple_counter (
      &fm->challenge_counters[FLOODGUARD_CHALLENGE_SWEPT_WHITELIST],
      vm->thread_index, 0, n_swept);
}

/* floodguard_challenge_sweep_process: once a second, walk the whitelist
 * only while it holds entries, so an idle box pays nothing. */
static uword
floodguard_challenge_sweep_process (vlib_main_t *vm, vlib_node_runtime_t *rt,
				    vlib_frame_t *f)
{
  floodguard_main_t *fm = &floodguard_main;

  while (1)
    {
      vlib_process_wait_for_event_or_clock (vm, 1.0);
      vlib_process_get_events (vm, 0);
      if (fm->challenge_tables_ready && fm->n_whitelist)
	floodguard_challenge_sweep_whitelist (vm, fm);
    }
  return 0;
}

VLIB_REGISTER_NODE (floodguard_challenge_sweep_node, static) = {
  .function = floodguard_challenge_sweep_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "floodguard-challenge-sweep",
};


VLIB_CLI_COMMAND (floodguard_interface_command, static) = {
  .path = "floodguard interface",
  .short_help = "floodguard interface <interface> enable [arp <policer>] "
		"[broadcast <policer>] [ctrl <policer>] [multicast <policer>] "
		"| floodguard interface <interface> disable "
		"| floodguard interface <interface> ip6-drop enable|disable "
		"| floodguard interface <interface> wan-reply enable|disable",
  .function = floodguard_interface_command_fn,
};

VLIB_CLI_COMMAND (floodguard_victim_command, static) = {
  .path = "floodguard victim",
  .short_help = "floodguard victim add <ip4> syn|udp|icmp [port <n>] | "
		"floodguard victim add <ip4> syn-challenge | "
		"floodguard victim del <ip4> syn|udp|icmp|syn-challenge | "
		"floodguard victim clear",
  .function = floodguard_victim_command_fn,
};

VLIB_CLI_COMMAND (floodguard_flood_command, static) = {
  .path = "floodguard flood",
  .short_help = "floodguard flood syn|udp|icmp rate <pps> burst <packets> | "
		"floodguard flood share <workers>",
  .function = floodguard_flood_command_fn,
};

VLIB_CLI_COMMAND (floodguard_challenge_command, static) = {
  .path = "floodguard syn-challenge",
  .short_help = "floodguard syn-challenge [whitelist-ttl <seconds>] "
		"[whitelist-size <n>]",
  .function = floodguard_challenge_command_fn,
};

VLIB_CLI_COMMAND (floodguard_wan_reply_command, static) = {
  .path = "floodguard wan-reply",
  .short_help =
    "floodguard wan-reply ports [tcp <list>] [udp <list>] [all]",
  .function = floodguard_wan_reply_command_fn,
};

VLIB_CLI_COMMAND (show_floodguard_command, static) = {
  .path = "show floodguard",
  .short_help = "show floodguard [victims]",
  .function = show_floodguard_command_fn,
  /* virtserver polls this every few seconds: without a worker barrier.
   * It still runs on the main thread, so the victims table, policer pool
   * and counter vectors — changed only by the barrier-taking commands
   * above — can't change underneath it; the rest are counters. */
  .is_mp_safe = 1,
};

static clib_error_t *
floodguard_init (vlib_main_t *vm)
{
  floodguard_main_t *fm = &floodguard_main;
  int i;

  fm->vlib_main = vm;
  fm->vnet_main = vnet_get_main ();
  fm->n_share_threads = floodguard_default_threads ();
  clib_bihash_init_8_8 (&fm->victims, "floodguard victims",
			FLOODGUARD_VICTIM_BUCKETS, FLOODGUARD_VICTIM_MEMORY);
  for (i = 0; i < FLOODGUARD_N_KIND; i++)
    {
      fm->drop_counters[i].name = (char *) floodguard_drop_counter_names[i];
      fm->drop_counters[i].stat_segment_name =
	(char *) floodguard_drop_stat_names[i];
      vlib_validate_simple_counter (&fm->drop_counters[i], 0);
      vlib_zero_simple_counter (&fm->drop_counters[i], 0);
    }
  for (i = 0; i < FLOODGUARD_N_CHALLENGE_COUNTER; i++)
    {
      fm->challenge_counters[i].name =
	(char *) floodguard_challenge_counter_names[i];
      fm->challenge_counters[i].stat_segment_name =
	(char *) floodguard_challenge_stat_names[i];
      vlib_validate_simple_counter (&fm->challenge_counters[i], 0);
      vlib_zero_simple_counter (&fm->challenge_counters[i], 0);
    }
  for (i = 0; i < FLOODGUARD_N_FLOOD; i++)
    for (int c = 0; c < FLOODGUARD_N_FLOOD_COUNTER; c++)
      {
	vlib_simple_counter_main_t *cm = &fm->flood_counters[i][c];
	cm->name = (char *) floodguard_flood_stat_names[i][c];
	cm->stat_segment_name = (char *) floodguard_flood_stat_names[i][c];
	vlib_validate_simple_counter (cm, 0);
	vlib_zero_simple_counter (cm, 0);
      }
  fm->wan_reply_skipped.name = "wan-reply-skipped";
  fm->wan_reply_skipped.stat_segment_name = "/floodguard/wan-reply/skipped";
  vlib_validate_simple_counter (&fm->wan_reply_skipped, 0);
  vlib_zero_simple_counter (&fm->wan_reply_skipped, 0);
  fm->challenge_whitelist_ttl_sec =
    FLOODGUARD_CHALLENGE_DEFAULT_WHITELIST_TTL_SEC;
  fm->challenge_whitelist_max = FLOODGUARD_CHALLENGE_DEFAULT_WHITELIST_MAX;

  /* The challenge cookie key: a fresh random secret every start, never
   * shown. Without it the challenge is off (SYNs pass untouched) rather
   * than VPP failing to start. */
  {
    u8 *k = (u8 *) fm->cookie_key;
    size_t got = 0;
    while (got < sizeof (fm->cookie_key))
      {
	ssize_t n = getrandom (k + got, sizeof (fm->cookie_key) - got, 0);
	if (n < 0)
	  {
	    if (errno == EINTR)
	      continue;
	    break;
	  }
	got += n;
      }
    fm->cookie_key_ready = got == sizeof (fm->cookie_key) &&
			   (fm->cookie_key[0] | fm->cookie_key[1]) != 0;
    if (!fm->cookie_key_ready)
      clib_warning ("floodguard: SYN Reset Challenge key not set (%s) - "
		    "challenge disabled, SYNs are forwarded",
		    strerror (errno));
  }
  return 0;
}

VLIB_INIT_FUNCTION (floodguard_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "mighty_xddos Flood Guard (storm, flood and SYN challenge)",
};
