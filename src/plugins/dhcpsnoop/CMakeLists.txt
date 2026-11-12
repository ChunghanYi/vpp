# mighty_lb: DHCP Snooping (Device Inventory, Rogue DHCP Server Blocking),
# VPP mode. See node.c's package doc comment for the design. CLI-only (no
# .api), same convention as the eta / connguard plugins — virtserver drives
# every VPP feature of this project through vppctl.

add_vpp_plugin(dhcpsnoop
  SOURCES
  dhcpsnoop.c
  node.c

  INSTALL_HEADERS
  dhcpsnoop.h
)
