# mighty_lb: DNS Sinkhole, VPP mode datapath (network mode l2) — LAN DNS
# queries taken to the box's DNS engine through a tap and its answers put
# back on the LAN port. See node.c's package doc comment. CLI-only (no .api),
# the same convention as floodguard: virtserver drives it (virtserver/dnsf).

add_vpp_plugin(dnsfilter
  SOURCES
  dnsfilter.c
  node.c

  INSTALL_HEADERS
  dnsfilter.h
)
