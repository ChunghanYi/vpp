/* SPDX-License-Identifier: Apache-2.0 */

/*
 * eta.c — mighty_xddos ETA (VPP mode) control plane: interface roles,
 * enable/disable and counters. virtserver drives it through vppctl:
 *
 *   eta interface <interface> wan [l3]|lan|none
 *   eta enable output <memif-interface> [rate <packets/s>] [scope inbound|all]
 *                                           (rate 0 = unlimited)
 *   eta disable
 *   show eta
 *
 * The "eta" node is attached to the interface-output arc of every
 * interface with a role while enabled, and detached everywhere otherwise
 * (same scheme as the connguard plugin). Scope "inbound" (only ClientHellos
 * received on a WAN-role interface) leaves the WAN-role interfaces' output
 * — LAN -> WAN traffic only — without the node at all; node.c checks the
 * receive interface for the rest (LAN -> LAN through a LAN output).
 *
 * mighty_lb, network mode l4: the routed WAN interface is "wan l3" — its
 * inbound ClientHellos are taken by eta-ip4 on its ip4-unicast arc (before
 * the load balancer's NAT / tunnel), and the LAN interfaces get no role.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/feature/feature.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

#include <eta/eta.h>

eta_main_t eta_main;

static const char *const eta_counter_names[ETA_N_CNT] = {
  [ETA_CNT_EXPORTED] = "exported",
  [ETA_CNT_RATE_LIMITED] = "rate-limited",
  [ETA_CNT_NO_BUFFER] = "no-buffer",
};

static const char *const eta_counter_stat_names[ETA_N_CNT] = {
  [ETA_CNT_EXPORTED] = "/eta/exported",
  [ETA_CNT_RATE_LIMITED] = "/eta/rate-limited",
  [ETA_CNT_NO_BUFFER] = "/eta/no-buffer",
};

/* eta_apply_rate: split the system-wide rate over the threads that
 * forward packets (the workers, or the main thread without workers). */
static void
eta_apply_rate (eta_main_t *em)
{
  u32 n = vlib_num_workers ();
  if (n == 0)
    n = 1;
  em->rate_per_thread = (f64) em->rate / n;
  em->burst = em->rate_per_thread / 10;
  if (em->burst < ETA_MIN_BURST)
    em->burst = ETA_MIN_BURST;
}

static void
eta_apply_features (eta_main_t *em)
{
  u32 sw_if_index;

  vec_validate_init_empty (em->feature_on_by_sw_if_index,
			   vec_len (em->role_by_sw_if_index), 0);
  for (sw_if_index = 0; sw_if_index < vec_len (em->feature_on_by_sw_if_index);
       sw_if_index++)
    {
      u8 role = sw_if_index < vec_len (em->role_by_sw_if_index) ?
		  em->role_by_sw_if_index[sw_if_index] :
		  ETA_ROLE_NONE;
      int want = em->enabled && role != ETA_ROLE_NONE &&
		 !(em->inbound_only && role == ETA_ROLE_WAN) &&
		 sw_if_index != em->output_sw_if_index;
      if (want == em->feature_on_by_sw_if_index[sw_if_index])
	continue;
      vnet_feature_enable_disable ("interface-output", "eta", sw_if_index,
				   want, 0, 0);
      em->feature_on_by_sw_if_index[sw_if_index] = want;
    }

  vec_validate_init_empty (em->l3_by_sw_if_index,
			   vec_len (em->role_by_sw_if_index), 0);
  vec_validate_init_empty (em->l3_on_by_sw_if_index,
			   vec_len (em->role_by_sw_if_index), 0);
  for (sw_if_index = 0; sw_if_index < vec_len (em->l3_on_by_sw_if_index);
       sw_if_index++)
    {
      int want = em->enabled && sw_if_index < vec_len (em->role_by_sw_if_index) &&
		 em->role_by_sw_if_index[sw_if_index] == ETA_ROLE_WAN &&
		 em->l3_by_sw_if_index[sw_if_index];
      if (want == em->l3_on_by_sw_if_index[sw_if_index])
	continue;
      vnet_feature_enable_disable ("ip4-unicast", "eta-ip4", sw_if_index,
				   want, 0, 0);
      em->l3_on_by_sw_if_index[sw_if_index] = want;
    }
}

static clib_error_t *
eta_interface_command_fn (vlib_main_t *vm, unformat_input_t *input,
			  vlib_cli_command_t *cmd)
{
  eta_main_t *em = &eta_main;
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index = ~0;
  int role = -1, l3 = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "wan"))
	role = ETA_ROLE_WAN;
      else if (unformat (input, "l3"))
	l3 = 1;
      else if (unformat (input, "lan"))
	role = ETA_ROLE_LAN;
      else if (unformat (input, "none"))
	role = ETA_ROLE_NONE;
      else if (unformat (input, "%U", unformat_vnet_sw_interface, vnm,
			 &sw_if_index))
	;
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }
  if (sw_if_index == ~0 || role < 0)
    return clib_error_return (0, "specify an interface and wan|lan|none");
  if (l3 && role != ETA_ROLE_WAN)
    return clib_error_return (0, "l3 is for a wan interface only");

  vec_validate_init_empty (em->role_by_sw_if_index, sw_if_index,
			   ETA_ROLE_NONE);
  vec_validate_init_empty (em->l3_by_sw_if_index, sw_if_index, 0);
  em->role_by_sw_if_index[sw_if_index] = (u8) role;
  em->l3_by_sw_if_index[sw_if_index] = (u8) l3;
  eta_apply_features (em);
  return 0;
}

static clib_error_t *
eta_enable_command_fn (vlib_main_t *vm, unformat_input_t *input,
		       vlib_cli_command_t *cmd)
{
  eta_main_t *em = &eta_main;
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index = ~0, rate = em->rate;
  int inbound_only = em->inbound_only;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "output %U", unformat_vnet_sw_interface, vnm,
		    &sw_if_index))
	;
      else if (unformat (input, "rate %u", &rate))
	;
      else if (unformat (input, "scope inbound"))
	inbound_only = 1;
      else if (unformat (input, "scope all"))
	inbound_only = 0;
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }
  if (sw_if_index == ~0)
    return clib_error_return (0, "specify output <memif-interface>");
  if (vec_len (em->role_by_sw_if_index) > sw_if_index &&
      em->role_by_sw_if_index[sw_if_index] != ETA_ROLE_NONE)
    return clib_error_return (0, "the output interface cannot have a role");

  /* Off while switching outputs, so no thread copies to a stale one. */
  em->enabled = 0;
  vec_validate_aligned (em->per_thread, vlib_get_n_threads () - 1,
			CLIB_CACHE_LINE_BYTES);
  eta_apply_features (em);
  em->output_sw_if_index = sw_if_index;
  em->rate = rate;
  em->inbound_only = inbound_only;
  eta_apply_rate (em);
  em->enabled = 1;
  eta_apply_features (em);
  return 0;
}

static clib_error_t *
eta_disable_command_fn (vlib_main_t *vm, unformat_input_t *input,
			vlib_cli_command_t *cmd)
{
  eta_main_t *em = &eta_main;

  em->enabled = 0;
  eta_apply_features (em);
  return 0;
}

static u64
eta_counter_total (vlib_simple_counter_main_t *cm)
{
  return vlib_get_simple_counter (cm, 0);
}

static clib_error_t *
show_eta_command_fn (vlib_main_t *vm, unformat_input_t *input,
		     vlib_cli_command_t *cmd)
{
  eta_main_t *em = &eta_main;
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index;
  int i;

  if (!em->enabled)
    vlib_cli_output (vm, "ETA: disabled");
  else
    vlib_cli_output (vm, "ETA: enabled, output %U, rate %u packets/s%s, scope %s",
		     format_vnet_sw_if_index_name, vnm, em->output_sw_if_index,
		     em->rate, em->rate ? "" : " (unlimited)",
		     em->inbound_only ? "inbound" : "all");
  for (sw_if_index = 0; sw_if_index < vec_len (em->role_by_sw_if_index);
       sw_if_index++)
    {
      u8 role = em->role_by_sw_if_index[sw_if_index];
      if (role == ETA_ROLE_NONE)
	continue;
      int l3 = sw_if_index < vec_len (em->l3_by_sw_if_index) &&
	       em->l3_by_sw_if_index[sw_if_index];
      int on = (sw_if_index < vec_len (em->feature_on_by_sw_if_index) &&
		em->feature_on_by_sw_if_index[sw_if_index]) ||
	       (sw_if_index < vec_len (em->l3_on_by_sw_if_index) &&
		em->l3_on_by_sw_if_index[sw_if_index]);
      vlib_cli_output (vm, "  %U: %s%s%s", format_vnet_sw_if_index_name, vnm,
		       sw_if_index, role == ETA_ROLE_WAN ? "wan" : "lan",
		       l3 ? " (l3)" : "", on ? "" : " (inactive)");
    }
  for (i = 0; i < ETA_N_CNT; i++)
    vlib_cli_output (vm, "  %s: %llu", eta_counter_names[i],
		     eta_counter_total (&em->counters[i]));
  return 0;
}

VLIB_CLI_COMMAND (eta_interface_command, static) = {
  .path = "eta interface",
  .short_help = "eta interface <interface> wan [l3]|lan|none",
  .function = eta_interface_command_fn,
};

VLIB_CLI_COMMAND (eta_enable_command, static) = {
  .path = "eta enable",
  .short_help = "eta enable output <memif-interface> [rate <packets/s>] [scope inbound|all]",
  .function = eta_enable_command_fn,
};

VLIB_CLI_COMMAND (eta_disable_command, static) = {
  .path = "eta disable",
  .short_help = "eta disable",
  .function = eta_disable_command_fn,
};

VLIB_CLI_COMMAND (show_eta_command, static) = {
  .path = "show eta",
  .short_help = "show eta",
  .function = show_eta_command_fn,
};

static clib_error_t *
eta_init (vlib_main_t *vm)
{
  eta_main_t *em = &eta_main;
  int i;

  em->vlib_main = vm;
  em->vnet_main = vnet_get_main ();
  em->output_sw_if_index = ~0;
  for (i = 0; i < ETA_N_CNT; i++)
    {
      em->counters[i].name = (char *) eta_counter_names[i];
      em->counters[i].stat_segment_name = (char *) eta_counter_stat_names[i];
      vlib_validate_simple_counter (&em->counters[i], 0);
      vlib_zero_simple_counter (&em->counters[i], 0);
    }
  return 0;
}

VLIB_INIT_FUNCTION (eta_init);

VNET_FEATURE_INIT (eta_feature, static) = {
  .arc_name = "interface-output",
  .node_name = "eta",
  .runs_before = VNET_FEATURES ("interface-output-arc-end"),
};

/* mighty_lb: after the input ACL and floodguard (blocked sources use up no
 * copies), before the load balancer's VIP dispatch (lb / cnat) */
VNET_FEATURE_INIT (eta_ip4_feature, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "eta-ip4",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-fa", "floodguard-ip4"),
  .runs_before = VNET_FEATURES ("lb4-vip-dispatch", "ip4-lookup"),
};

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "mighty_xddos ETA ClientHello extraction",
};
