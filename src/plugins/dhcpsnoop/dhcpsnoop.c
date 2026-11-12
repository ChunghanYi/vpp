/* SPDX-License-Identifier: Apache-2.0 */

/*
 * dhcpsnoop.c — mighty_lb DHCP Snooping (VPP mode) control plane:
 * interface roles, capture/guard, trusted servers and counters. virtserver
 * (inventory package) drives it through vppctl:
 *
 *   dhcpsnoop interface <interface> wan|lan|none
 *   dhcpsnoop enable [output <memif-interface>] [rate <frames/s> burst <n>]
 *                    [capture on|off] [guard on|off]
 *   dhcpsnoop disable
 *   dhcpsnoop trusted add|del <ip4> | trusted clear
 *   show dhcpsnoop
 *
 * The node is attached to the l2-input-ip4 arc of every interface with a
 * role while capture or guard is on, and detached everywhere otherwise.
 * Guard needs at least one trusted server (strict, like Kernel mode — with
 * none, every DHCP reply would be dropped); virtserver checks that too.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/feature/feature.h>
#include <vnet/l2/l2_input.h>
#include <vnet/l2/l2_in_out_feat_arc.h>
#include <vnet/ip/ip.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

#include <dhcpsnoop/dhcpsnoop.h>

dhcpsnoop_main_t dhcpsnoop_main;

static const char *const dhcpsnoop_counter_names[DHCPSNOOP_N_CNT] = {
  [DHCPSNOOP_CNT_COPIED] = "copied",
  [DHCPSNOOP_CNT_RATE_LIMITED] = "rate-limited",
  [DHCPSNOOP_CNT_NO_BUFFER] = "no-buffer",
  [DHCPSNOOP_CNT_ROGUE_DROPPED] = "rogue-dropped",
};

static const char *const dhcpsnoop_counter_stat_names[DHCPSNOOP_N_CNT] = {
  [DHCPSNOOP_CNT_COPIED] = "/dhcpsnoop/copied",
  [DHCPSNOOP_CNT_RATE_LIMITED] = "/dhcpsnoop/rate-limited",
  [DHCPSNOOP_CNT_NO_BUFFER] = "/dhcpsnoop/no-buffer",
  [DHCPSNOOP_CNT_ROGUE_DROPPED] = "/dhcpsnoop/rogue-dropped",
};

/* dhcpsnoop_apply_rate: split the box-wide rate and burst over the threads
 * that forward packets (the workers, or the main thread without them). */
static void
dhcpsnoop_apply_rate (dhcpsnoop_main_t *sm)
{
  u32 n = vlib_num_workers ();
  if (n == 0)
    n = 1;
  sm->rate_per_thread = (f64) sm->rate / n;
  sm->burst = (f64) (sm->burst_total ? sm->burst_total : sm->rate) / n;
  if (sm->burst < DHCPSNOOP_MIN_BURST)
    sm->burst = DHCPSNOOP_MIN_BURST;
}

static void
dhcpsnoop_apply_features (dhcpsnoop_main_t *sm)
{
  u32 sw_if_index;
  int active = sm->capture || sm->guard;

  vec_validate_init_empty (sm->feature_on_by_sw_if_index,
			   vec_len (sm->role_by_sw_if_index), 0);
  for (sw_if_index = 0; sw_if_index < vec_len (sm->feature_on_by_sw_if_index);
       sw_if_index++)
    {
      u8 role = sw_if_index < vec_len (sm->role_by_sw_if_index) ?
		  sm->role_by_sw_if_index[sw_if_index] :
		  DHCPSNOOP_ROLE_NONE;
      int want = active && role != DHCPSNOOP_ROLE_NONE;
      if (want)
	/* A bridge edit (L3 mode and back) resets the port's L2 input
	 * bitmap, arc bit included, while the arc keeps its features: put
	 * the bit back every time (see dnsfilter.c dnsfilter_set_role). */
	l2input_intf_bitmap_enable (sw_if_index, L2INPUT_FEAT_INPUT_FEAT_ARC, 1);
      if (want == sm->feature_on_by_sw_if_index[sw_if_index])
	continue;
      vnet_l2_feature_enable_disable ("l2-input-ip4", "dhcpsnoop", sw_if_index,
				      want, 0, 0);
      sm->feature_on_by_sw_if_index[sw_if_index] = want;
    }
}

static clib_error_t *
dhcpsnoop_interface_command_fn (vlib_main_t *vm, unformat_input_t *input,
				vlib_cli_command_t *cmd)
{
  dhcpsnoop_main_t *sm = &dhcpsnoop_main;
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index = ~0;
  int role = -1;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "wan"))
	role = DHCPSNOOP_ROLE_WAN;
      else if (unformat (input, "lan"))
	role = DHCPSNOOP_ROLE_LAN;
      else if (unformat (input, "none"))
	role = DHCPSNOOP_ROLE_NONE;
      else if (unformat (input, "%U", unformat_vnet_sw_interface, vnm,
			 &sw_if_index))
	;
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }
  if (sw_if_index == ~0 || role < 0)
    return clib_error_return (0, "specify an interface and wan|lan|none");
  if (role != DHCPSNOOP_ROLE_NONE && sw_if_index == sm->output_sw_if_index)
    return clib_error_return (0, "the output interface cannot have a role");

  vec_validate_init_empty (sm->role_by_sw_if_index, sw_if_index,
			   DHCPSNOOP_ROLE_NONE);
  sm->role_by_sw_if_index[sw_if_index] = (u8) role;
  dhcpsnoop_apply_features (sm);
  return 0;
}

static clib_error_t *
dhcpsnoop_enable_command_fn (vlib_main_t *vm, unformat_input_t *input,
			     vlib_cli_command_t *cmd)
{
  dhcpsnoop_main_t *sm = &dhcpsnoop_main;
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index = sm->output_sw_if_index, rate = sm->rate,
      burst = sm->burst_total;
  int capture = 1, guard = sm->guard;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "output %U", unformat_vnet_sw_interface, vnm,
		    &sw_if_index))
	;
      else if (unformat (input, "rate %u", &rate))
	;
      else if (unformat (input, "burst %u", &burst))
	;
      else if (unformat (input, "capture on"))
	capture = 1;
      else if (unformat (input, "capture off"))
	capture = 0;
      else if (unformat (input, "guard on"))
	guard = 1;
      else if (unformat (input, "guard off"))
	guard = 0;
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }
  if (capture && sw_if_index == ~0)
    return clib_error_return (0, "specify output <memif-interface>");
  if (sw_if_index != ~0 && vec_len (sm->role_by_sw_if_index) > sw_if_index &&
      sm->role_by_sw_if_index[sw_if_index] != DHCPSNOOP_ROLE_NONE)
    return clib_error_return (0, "the output interface cannot have a role");
  if (guard && sm->n_trusted == 0)
    return clib_error_return (0, "guard needs a trusted server first "
				 "(with none, every DHCP reply would be dropped)");

  vec_validate_aligned (sm->per_thread, vlib_get_n_threads () - 1,
			CLIB_CACHE_LINE_BYTES);
  sm->output_sw_if_index = sw_if_index;
  sm->rate = rate;
  sm->burst_total = burst;
  dhcpsnoop_apply_rate (sm);
  sm->capture = capture;
  sm->guard = guard;
  dhcpsnoop_apply_features (sm);
  return 0;
}

static clib_error_t *
dhcpsnoop_disable_command_fn (vlib_main_t *vm, unformat_input_t *input,
			      vlib_cli_command_t *cmd)
{
  dhcpsnoop_main_t *sm = &dhcpsnoop_main;

  sm->capture = 0;
  sm->guard = 0;
  dhcpsnoop_apply_features (sm);
  return 0;
}

static clib_error_t *
dhcpsnoop_trusted_command_fn (vlib_main_t *vm, unformat_input_t *input,
			      vlib_cli_command_t *cmd)
{
  dhcpsnoop_main_t *sm = &dhcpsnoop_main;
  ip4_address_t a;
  u32 i;

  if (unformat (input, "clear"))
    {
      if (sm->guard)
	return clib_error_return (0, "turn guard off before clearing the "
				     "trusted servers");
      sm->n_trusted = 0;
      return 0;
    }
  if (unformat (input, "add %U", unformat_ip4_address, &a))
    {
      for (i = 0; i < sm->n_trusted; i++)
	if (sm->trusted[i] == a.as_u32)
	  return 0;
      if (sm->n_trusted >= DHCPSNOOP_MAX_TRUSTED)
	return clib_error_return (0, "at most %d trusted servers",
				  DHCPSNOOP_MAX_TRUSTED);
      sm->trusted[sm->n_trusted++] = a.as_u32;
      return 0;
    }
  if (unformat (input, "del %U", unformat_ip4_address, &a))
    {
      for (i = 0; i < sm->n_trusted; i++)
	if (sm->trusted[i] == a.as_u32)
	  break;
      if (i == sm->n_trusted)
	return 0;
      if (sm->guard && sm->n_trusted == 1)
	return clib_error_return (0, "the last trusted server cannot be "
				     "deleted while guard is on");
      sm->trusted[i] = sm->trusted[--sm->n_trusted];
      return 0;
    }
  return clib_error_return (0, "trusted add|del <ip4> | trusted clear");
}

static clib_error_t *
show_dhcpsnoop_command_fn (vlib_main_t *vm, unformat_input_t *input,
			   vlib_cli_command_t *cmd)
{
  dhcpsnoop_main_t *sm = &dhcpsnoop_main;
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index, i;

  vlib_cli_output (vm, "DHCP Snooping: capture %s, guard %s",
		   sm->capture ? "on" : "off", sm->guard ? "on" : "off");
  if (sm->output_sw_if_index != ~0)
    vlib_cli_output (vm, "  output %U, rate %u frames/s%s, burst %u",
		     format_vnet_sw_if_index_name, vnm, sm->output_sw_if_index,
		     sm->rate, sm->rate ? "" : " (unlimited)", sm->burst_total);
  for (sw_if_index = 0; sw_if_index < vec_len (sm->role_by_sw_if_index);
       sw_if_index++)
    {
      u8 role = sm->role_by_sw_if_index[sw_if_index];
      if (role == DHCPSNOOP_ROLE_NONE)
	continue;
      int on = sw_if_index < vec_len (sm->feature_on_by_sw_if_index) &&
	       sm->feature_on_by_sw_if_index[sw_if_index];
      vlib_cli_output (vm, "  %U: %s%s", format_vnet_sw_if_index_name, vnm,
		       sw_if_index, role == DHCPSNOOP_ROLE_WAN ? "wan" : "lan",
		       on ? "" : " (inactive)");
    }
  for (i = 0; i < sm->n_trusted; i++)
    vlib_cli_output (vm, "  trusted %U", format_ip4_address, &sm->trusted[i]);
  for (i = 0; i < DHCPSNOOP_N_CNT; i++)
    vlib_cli_output (vm, "  %s: %llu", dhcpsnoop_counter_names[i],
		     vlib_get_simple_counter (&sm->counters[i], 0));
  return 0;
}

VLIB_CLI_COMMAND (dhcpsnoop_interface_command, static) = {
  .path = "dhcpsnoop interface",
  .short_help = "dhcpsnoop interface <interface> wan|lan|none",
  .function = dhcpsnoop_interface_command_fn,
};

VLIB_CLI_COMMAND (dhcpsnoop_enable_command, static) = {
  .path = "dhcpsnoop enable",
  .short_help = "dhcpsnoop enable [output <memif-interface>] [rate <frames/s>] "
		"[burst <n>] [capture on|off] [guard on|off]",
  .function = dhcpsnoop_enable_command_fn,
};

VLIB_CLI_COMMAND (dhcpsnoop_disable_command, static) = {
  .path = "dhcpsnoop disable",
  .short_help = "dhcpsnoop disable",
  .function = dhcpsnoop_disable_command_fn,
};

VLIB_CLI_COMMAND (dhcpsnoop_trusted_command, static) = {
  .path = "dhcpsnoop trusted",
  .short_help = "dhcpsnoop trusted add|del <ip4> | trusted clear",
  .function = dhcpsnoop_trusted_command_fn,
};

VLIB_CLI_COMMAND (show_dhcpsnoop_command, static) = {
  .path = "show dhcpsnoop",
  .short_help = "show dhcpsnoop",
  .function = show_dhcpsnoop_command_fn,
};

static clib_error_t *
dhcpsnoop_init (vlib_main_t *vm)
{
  dhcpsnoop_main_t *sm = &dhcpsnoop_main;
  int i;

  sm->vlib_main = vm;
  sm->vnet_main = vnet_get_main ();
  sm->output_sw_if_index = ~0;
  vec_validate_aligned (sm->per_thread, vlib_get_n_threads () - 1,
			CLIB_CACHE_LINE_BYTES);
  for (i = 0; i < DHCPSNOOP_N_CNT; i++)
    {
      sm->counters[i].name = (char *) dhcpsnoop_counter_names[i];
      sm->counters[i].stat_segment_name = (char *) dhcpsnoop_counter_stat_names[i];
      vlib_validate_simple_counter (&sm->counters[i], 0);
      vlib_zero_simple_counter (&sm->counters[i], 0);
    }
  return 0;
}

VLIB_INIT_FUNCTION (dhcpsnoop_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "mighty_lb DHCP Snooping",
};
