/* SPDX-License-Identifier: Apache-2.0 */

/*
 * dnsfilter.c — mighty_lb DNS Sinkhole, VPP mode: state, sweep and CLI.
 * CLI-only like the project's other plugins: virtserver
 * (virtserver/dnsf/datapath_vpp.go) drives it, the operator never does.
 *
 *   dnsfilter interface <if> lan|wan|none
 *   dnsfilter tap <if> host-mac <mac> | dnsfilter tap none
 *   dnsfilter config [intercept on|off] [dot on|off] [doh on|off]
 *                    [client-qps <n>] [global-qps <n>]
 *   dnsfilter health up|down
 *   dnsfilter doh-ip load <file> | dnsfilter doh-ip clear
 *   dnsfilter exempt set [<ip> ...]   (replaces the set; none = empty)
 *   dnsfilter reset
 *   show dnsfilter
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vnet/feature/feature.h>
#include <vnet/l2/l2_input.h>
#include <vnet/l2/l2_in_out_feat_arc.h>
#include <fcntl.h>
#include <vpp/app/version.h>
#include <dnsfilter/dnsfilter.h>

dnsfilter_main_t dnsfilter_main;

static const char *const dnsfilter_counter_names[] = {
#define _(sym, name, desc) name,
  foreach_dnsfilter_counter
#undef _
};

static const char *const dnsfilter_counter_stat_names[] = {
#define _(sym, name, desc) "/dnsfilter/" name,
  foreach_dnsfilter_counter
#undef _
};

static u64
dnsfilter_counter_total (dnsfilter_main_t *dm, dnsfilter_counter_t c)
{
  return vlib_get_simple_counter (&dm->counters[c], 0);
}

/* ─── Tables ────────────────────────────────────────────────────────── */

static void
dnsfilter_tables_init (dnsfilter_main_t *dm)
{
  clib_bihash_init_8_16 (&dm->ret, "dnsfilter return", DNSFILTER_RET_BUCKETS,
			 DNSFILTER_RET_MEMORY);
  clib_bihash_init_8_8 (&dm->clients, "dnsfilter clients",
			DNSFILTER_CLIENT_BUCKETS, DNSFILTER_CLIENT_MEMORY);
  clib_bihash_init_8_8 (&dm->doh_ips, "dnsfilter doh ips",
			DNSFILTER_DOH_BUCKETS, DNSFILTER_DOH_MEMORY);
  clib_bihash_init_8_8 (&dm->exempt, "dnsfilter exempt",
			DNSFILTER_EXEMPT_BUCKETS, DNSFILTER_EXEMPT_MEMORY);
  dm->n_ret = dm->n_clients = dm->n_doh_ips = dm->n_exempt = 0;
}

/* Called with the workers stopped (CLI barrier). */
static void
dnsfilter_tables_reset (dnsfilter_main_t *dm)
{
  clib_bihash_free_8_16 (&dm->ret);
  clib_bihash_free_8_8 (&dm->clients);
  clib_bihash_free_8_8 (&dm->doh_ips);
  clib_bihash_free_8_8 (&dm->exempt);
  dnsfilter_tables_init (dm);
}

/* ─── Sweep: stale return entries and rate windows ──────────────────── */

typedef struct
{
  u32 now;
  u64 *stale;
} dnsfilter_sweep_ctx_t;

static int
dnsfilter_ret_stale (clib_bihash_kv_8_16_t *kv, void *arg)
{
  dnsfilter_sweep_ctx_t *ctx = arg;
  dnsfilter_ret_t r = { .as_u64 = { kv->value[0], kv->value[1] } };
  if ((u16) ((u16) ctx->now - r.seen) > DNSFILTER_RET_TTL_SEC)
    vec_add1 (ctx->stale, kv->key);
  return BIHASH_WALK_CONTINUE;
}

static int
dnsfilter_client_stale (clib_bihash_kv_8_8_t *kv, void *arg)
{
  dnsfilter_sweep_ctx_t *ctx = arg;
  if ((u32) (kv->value >> 32) + DNSFILTER_CLIENT_TTL_SEC < ctx->now)
    vec_add1 (ctx->stale, kv->key);
  return BIHASH_WALK_CONTINUE;
}

static void
dnsfilter_sweep (vlib_main_t *vm, dnsfilter_main_t *dm)
{
  dnsfilter_sweep_ctx_t ctx = { .now = dnsfilter_now_sec (vm) };
  u64 *k;

  if (dm->n_ret)
    {
      clib_bihash_foreach_key_value_pair_8_16 (&dm->ret, dnsfilter_ret_stale,
					       &ctx);
      vec_foreach (k, ctx.stale)
	{
	  clib_bihash_kv_8_16_t kv = { .key = *k };
	  if (clib_bihash_add_del_8_16 (&dm->ret, &kv, 0) == 0)
	    clib_atomic_fetch_sub (&dm->n_ret, 1);
	}
      vec_reset_length (ctx.stale);
    }
  if (dm->n_clients)
    {
      clib_bihash_foreach_key_value_pair_8_8 (&dm->clients,
					      dnsfilter_client_stale, &ctx);
      vec_foreach (k, ctx.stale)
	{
	  clib_bihash_kv_8_8_t kv = { .key = *k };
	  if (clib_bihash_add_del_8_8 (&dm->clients, &kv, 0) == 0)
	    clib_atomic_fetch_sub (&dm->n_clients, 1);
	}
    }
  vec_free (ctx.stale);
}

/* dnsfilter_sweep_process: every DNSFILTER_SWEEP_INTERVAL, only while
 * the tables hold entries, so an idle box pays nothing. */
static uword
dnsfilter_sweep_process (vlib_main_t *vm, vlib_node_runtime_t *rt,
			 vlib_frame_t *f)
{
  dnsfilter_main_t *dm = &dnsfilter_main;

  while (1)
    {
      vlib_process_wait_for_event_or_clock (vm, DNSFILTER_SWEEP_INTERVAL);
      vlib_process_get_events (vm, 0);
      if (dm->n_ret || dm->n_clients)
	dnsfilter_sweep (vm, dm);
    }
  return 0;
}

VLIB_REGISTER_NODE (dnsfilter_sweep_node, static) = {
  .function = dnsfilter_sweep_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "dnsfilter-sweep",
};

/* ─── CLI ───────────────────────────────────────────────────────────── */

static void
dnsfilter_set_role (dnsfilter_main_t *dm, u32 sw_if_index,
		    dnsfilter_role_t role)
{
  vec_validate_init_empty (dm->roles, sw_if_index, DNSFILTER_ROLE_NONE);
  int was_lan = dm->roles[sw_if_index] == DNSFILTER_ROLE_LAN;
  int is_lan = role == DNSFILTER_ROLE_LAN;
  if (was_lan != is_lan)
    {
      vnet_l2_feature_enable_disable ("l2-input-ip4", "dnsfilter-lan",
				      sw_if_index, is_lan, 0, 0);
      dm->n_lan += is_lan ? 1 : -1;
    }
  /* The port's L2 input bitmap loses its feature-arc bit whenever it goes
   * through L3 mode (set_int_l2_mode resets the bitmap — a bridge group
   * edit tears its members down and puts them back), while the arc keeps
   * its features: the bit is only set again when the arc's feature count
   * goes 0 -> 1, so the node would silently stop seeing packets. Every
   * "lan" (sent again after each bridge change) puts it back. */
  if (is_lan)
    l2input_intf_bitmap_enable (sw_if_index, L2INPUT_FEAT_INPUT_FEAT_ARC, 1);
  dm->roles[sw_if_index] = role;
}

static void
dnsfilter_set_tap (dnsfilter_main_t *dm, u32 sw_if_index)
{
  if (dm->tap_sw_if_index == sw_if_index)
    return;
  if (dm->tap_sw_if_index != ~0)
    vnet_feature_enable_disable ("device-input", "dnsfilter-return",
				 dm->tap_sw_if_index, 0, 0, 0);
  if (sw_if_index != ~0)
    vnet_feature_enable_disable ("device-input", "dnsfilter-return",
				 sw_if_index, 1, 0, 0);
  dm->tap_sw_if_index = sw_if_index;
}

static clib_error_t *
dnsfilter_interface_command_fn (vlib_main_t *vm, unformat_input_t *input,
				vlib_cli_command_t *cmd)
{
  dnsfilter_main_t *dm = &dnsfilter_main;
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index = ~0;
  int role = -1;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "lan"))
	role = DNSFILTER_ROLE_LAN;
      else if (unformat (input, "wan"))
	role = DNSFILTER_ROLE_WAN;
      else if (unformat (input, "none"))
	role = DNSFILTER_ROLE_NONE;
      else if (unformat (input, "%U", unformat_vnet_sw_interface, vnm,
			 &sw_if_index))
	;
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }
  if (sw_if_index == ~0 || role < 0)
    return clib_error_return (0, "specify an interface and lan|wan|none");
  /* The return entry keeps the port in 16 bits, and tagged frames are not
   * intercepted: main interfaces only. */
  if (role == DNSFILTER_ROLE_LAN &&
      (sw_if_index > 0xffff || vnet_sw_interface_is_sub (vnm, sw_if_index)))
    return clib_error_return (0, "%U: a LAN port must be a main interface",
			      format_vnet_sw_if_index_name, vnm, sw_if_index);
  dnsfilter_set_role (dm, sw_if_index, role);
  return 0;
}

static clib_error_t *
dnsfilter_tap_command_fn (vlib_main_t *vm, unformat_input_t *input,
			  vlib_cli_command_t *cmd)
{
  dnsfilter_main_t *dm = &dnsfilter_main;
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index = ~0;
  mac_address_t mac;
  int have_mac = 0, none = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "none"))
	none = 1;
      else if (unformat (input, "host-mac %U", unformat_mac_address_t, &mac))
	have_mac = 1;
      else if (unformat (input, "%U", unformat_vnet_sw_interface, vnm,
			 &sw_if_index))
	;
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }
  if (none)
    {
      dnsfilter_set_tap (dm, ~0);
      return 0;
    }
  if (sw_if_index == ~0 || !have_mac)
    return clib_error_return (0, "specify the tap and host-mac <mac>");
  mac_address_copy (&dm->host_mac, &mac);
  dnsfilter_set_tap (dm, sw_if_index);
  return 0;
}

static int
dnsfilter_on_off (unformat_input_t *input, const char *word, u8 *out)
{
  u8 *w = format (0, "%s on%c", word, 0);
  u8 *f = format (0, "%s off%c", word, 0);
  int r = 0;
  if (unformat (input, (char *) w))
    *out = 1, r = 1;
  else if (unformat (input, (char *) f))
    *out = 0, r = 1;
  vec_free (w);
  vec_free (f);
  return r;
}

static clib_error_t *
dnsfilter_config_command_fn (vlib_main_t *vm, unformat_input_t *input,
			     vlib_cli_command_t *cmd)
{
  dnsfilter_main_t *dm = &dnsfilter_main;
  u32 n;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (dnsfilter_on_off (input, "intercept", &dm->intercept) ||
	  dnsfilter_on_off (input, "dot", &dm->block_dot) ||
	  dnsfilter_on_off (input, "doh", &dm->block_doh_ip))
	;
      else if (unformat (input, "client-qps %u", &n))
	dm->client_qps = n;
      else if (unformat (input, "global-qps %u", &n))
	dm->global_qps = n;
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }
  return 0;
}

static clib_error_t *
dnsfilter_health_command_fn (vlib_main_t *vm, unformat_input_t *input,
			     vlib_cli_command_t *cmd)
{
  dnsfilter_main_t *dm = &dnsfilter_main;

  if (unformat (input, "up"))
    dm->daemon_ok = 1;
  else if (unformat (input, "down"))
    dm->daemon_ok = 0;
  else
    return clib_error_return (0, "specify up|down");
  return 0;
}

/* dnsfilter doh-ip load <file>: one IPv4 address per line ('#' comments,
 * other lines ignored) — replaces the whole set. */
static clib_error_t *
dnsfilter_doh_command_fn (vlib_main_t *vm, unformat_input_t *input,
			  vlib_cli_command_t *cmd)
{
  dnsfilter_main_t *dm = &dnsfilter_main;
  u8 *path = 0, *line = 0;
  unformat_input_t in;
  ip4_address_t a;
  int fd;

  if (unformat (input, "clear"))
    {
      clib_bihash_free_8_8 (&dm->doh_ips);
      clib_bihash_init_8_8 (&dm->doh_ips, "dnsfilter doh ips",
			    DNSFILTER_DOH_BUCKETS, DNSFILTER_DOH_MEMORY);
      dm->n_doh_ips = 0;
      return 0;
    }
  if (!unformat (input, "load %s", &path))
    return clib_error_return (0, "specify load <file> or clear");
  vec_add1 (path, 0);
  fd = open ((char *) path, O_RDONLY);
  if (fd < 0)
    {
      clib_error_t *e =
	clib_error_return_unix (0, "open '%s'", (char *) path);
      vec_free (path);
      return e;
    }
  vec_free (path);

  clib_bihash_free_8_8 (&dm->doh_ips);
  clib_bihash_init_8_8 (&dm->doh_ips, "dnsfilter doh ips",
			DNSFILTER_DOH_BUCKETS, DNSFILTER_DOH_MEMORY);
  dm->n_doh_ips = 0;
  unformat_init_clib_file (&in, fd);
  while (unformat_check_input (&in) != UNFORMAT_END_OF_INPUT)
    {
      if (!unformat_user (&in, unformat_line, &line))
	break;
      unformat_input_t li;
      unformat_init_vector (&li, line); /* takes line */
      line = 0;
      if (unformat (&li, "%U", unformat_ip4_address, &a) &&
	  dm->n_doh_ips < DNSFILTER_DOH_MAX)
	{
	  clib_bihash_kv_8_8_t kv = { .key = a.as_u32, .value = 1 };
	  if (clib_bihash_add_del_8_8 (&dm->doh_ips, &kv, 1) == 0)
	    dm->n_doh_ips++;
	}
      unformat_free (&li);
    }
  unformat_free (&in);
  close (fd);
  return 0;
}

/* dnsfilter exempt set [<ip> ...]: replaces the exempt client set (CLI
 * barrier: the workers are stopped while the table is rebuilt). */
static clib_error_t *
dnsfilter_exempt_command_fn (vlib_main_t *vm, unformat_input_t *input,
			     vlib_cli_command_t *cmd)
{
  dnsfilter_main_t *dm = &dnsfilter_main;
  ip4_address_t a, *ips = 0, *ip;
  clib_error_t *e = 0;

  if (!unformat (input, "set"))
    return clib_error_return (0, "specify set [<ip> ...]");
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (!unformat (input, "%U", unformat_ip4_address, &a))
	{
	  e = clib_error_return (0, "bad address '%U'", format_unformat_error,
				 input);
	  goto done;
	}
      vec_add1 (ips, a);
    }
  if (vec_len (ips) > DNSFILTER_EXEMPT_MAX)
    {
      e = clib_error_return (0, "at most %u addresses", DNSFILTER_EXEMPT_MAX);
      goto done;
    }
  clib_bihash_free_8_8 (&dm->exempt);
  clib_bihash_init_8_8 (&dm->exempt, "dnsfilter exempt",
			DNSFILTER_EXEMPT_BUCKETS, DNSFILTER_EXEMPT_MEMORY);
  dm->n_exempt = 0;
  vec_foreach (ip, ips)
    {
      clib_bihash_kv_8_8_t kv = { .key = ip->as_u32, .value = 1 };
      if (clib_bihash_add_del_8_8 (&dm->exempt, &kv, 1) == 0)
	dm->n_exempt++;
    }
done:
  vec_free (ips);
  return e;
}

/* dnsfilter reset: everything off and empty (DNS Sinkhole taken down). */
static clib_error_t *
dnsfilter_reset_command_fn (vlib_main_t *vm, unformat_input_t *input,
			    vlib_cli_command_t *cmd)
{
  dnsfilter_main_t *dm = &dnsfilter_main;
  u32 i;

  vec_foreach_index (i, dm->roles)
    if (dm->roles[i] != DNSFILTER_ROLE_NONE)
      dnsfilter_set_role (dm, i, DNSFILTER_ROLE_NONE);
  dnsfilter_set_tap (dm, ~0);
  dm->intercept = dm->daemon_ok = dm->block_dot = dm->block_doh_ip = 0;
  dm->client_qps = dm->global_qps = 0;
  dnsfilter_tables_reset (dm);
  return 0;
}

/* show dnsfilter: "key: value" lines (virtserver parses them; the counter
 * keys are xdp_bridge's dnsf-status names). */
static clib_error_t *
show_dnsfilter_command_fn (vlib_main_t *vm, unformat_input_t *input,
			   vlib_cli_command_t *cmd)
{
  dnsfilter_main_t *dm = &dnsfilter_main;
  vnet_main_t *vnm = vnet_get_main ();
  u32 i;

  vlib_cli_output (vm, "intercept: %u", dm->intercept);
  vlib_cli_output (vm, "daemon_ok: %u", dm->daemon_ok);
  vlib_cli_output (vm, "block_dot: %u", dm->block_dot);
  vlib_cli_output (vm, "block_doh_ip: %u", dm->block_doh_ip);
  vlib_cli_output (vm, "client_qps: %u", dm->client_qps);
  vlib_cli_output (vm, "global_qps: %u", dm->global_qps);
  if (dm->tap_sw_if_index != ~0)
    vlib_cli_output (vm, "tap: %U", format_vnet_sw_if_index_name, vnm,
		     dm->tap_sw_if_index);
  else
    vlib_cli_output (vm, "tap: -");
  vlib_cli_output (vm, "lan_ports: %u", dm->n_lan);
  vec_foreach_index (i, dm->roles)
    if (dm->roles[i] != DNSFILTER_ROLE_NONE)
      vlib_cli_output (vm, "port: %U %s", format_vnet_sw_if_index_name, vnm, i,
		       dm->roles[i] == DNSFILTER_ROLE_LAN ? "lan" : "wan");
  for (i = 0; i < DNSFILTER_N_COUNTER; i++)
    vlib_cli_output (vm, "%s: %llu", dnsfilter_counter_names[i],
		     dnsfilter_counter_total (dm, i));
  vlib_cli_output (vm, "pending_queries: %u", dm->n_ret);
  vlib_cli_output (vm, "tracked_clients: %u", dm->n_clients);
  vlib_cli_output (vm, "doh_addresses: %u", dm->n_doh_ips);
  vlib_cli_output (vm, "exempt_clients: %u", dm->n_exempt);
  return 0;
}

VLIB_CLI_COMMAND (dnsfilter_interface_command, static) = {
  .path = "dnsfilter interface",
  .short_help = "dnsfilter interface <interface> lan|wan|none",
  .function = dnsfilter_interface_command_fn,
};

VLIB_CLI_COMMAND (dnsfilter_tap_command, static) = {
  .path = "dnsfilter tap",
  .short_help = "dnsfilter tap <interface> host-mac <mac> | dnsfilter tap none",
  .function = dnsfilter_tap_command_fn,
};

/* Plain byte/word stores the workers read as they come: no barrier. */
VLIB_CLI_COMMAND (dnsfilter_config_command, static) = {
  .path = "dnsfilter config",
  .short_help = "dnsfilter config [intercept on|off] [dot on|off] "
		"[doh on|off] [client-qps <n>] [global-qps <n>]",
  .function = dnsfilter_config_command_fn,
  .is_mp_safe = 1,
};

VLIB_CLI_COMMAND (dnsfilter_health_command, static) = {
  .path = "dnsfilter health",
  .short_help = "dnsfilter health up|down",
  .function = dnsfilter_health_command_fn,
  .is_mp_safe = 1,
};

VLIB_CLI_COMMAND (dnsfilter_doh_command, static) = {
  .path = "dnsfilter doh-ip",
  .short_help = "dnsfilter doh-ip load <file> | dnsfilter doh-ip clear",
  .function = dnsfilter_doh_command_fn,
};

VLIB_CLI_COMMAND (dnsfilter_exempt_command, static) = {
  .path = "dnsfilter exempt",
  .short_help = "dnsfilter exempt set [<ip> ...]",
  .function = dnsfilter_exempt_command_fn,
};

VLIB_CLI_COMMAND (dnsfilter_reset_command, static) = {
  .path = "dnsfilter reset",
  .short_help = "dnsfilter reset",
  .function = dnsfilter_reset_command_fn,
};

/* virtserver reads it with the page's status poll: no worker barrier (it
 * runs on the main thread, where the role vector only changes). */
VLIB_CLI_COMMAND (show_dnsfilter_command, static) = {
  .path = "show dnsfilter",
  .short_help = "show dnsfilter",
  .function = show_dnsfilter_command_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
dnsfilter_init (vlib_main_t *vm)
{
  dnsfilter_main_t *dm = &dnsfilter_main;
  int i;

  dm->vlib_main = vm;
  dm->vnet_main = vnet_get_main ();
  dm->tap_sw_if_index = ~0;
  dnsfilter_tables_init (dm);
  for (i = 0; i < DNSFILTER_N_COUNTER; i++)
    {
      dm->counters[i].name = (char *) dnsfilter_counter_names[i];
      dm->counters[i].stat_segment_name =
	(char *) dnsfilter_counter_stat_names[i];
      vlib_validate_simple_counter (&dm->counters[i], 0);
      vlib_zero_simple_counter (&dm->counters[i], 0);
    }
  return 0;
}

VLIB_INIT_FUNCTION (dnsfilter_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "mighty_lb DNS Sinkhole datapath (L2 bridge)",
};
