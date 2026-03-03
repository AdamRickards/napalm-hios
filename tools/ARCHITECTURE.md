# Key Architectural Insights

Cross-cutting differentiators that tie the tooling together.

1. **SNOOP passive IP:MAC over VPN** — sFlow sampling with ceiling/floor/early-exit passively fingerprints every end device on a customer's OT network without sending a single frame, all remotely through WireGuard. Service differentiator nobody else is offering

2. **MARCO/POLO self-healing loop** — MARCO scans, compares against POLO's dnsmasq registry, detects missing + unknown. POLO swaps the MAC, timer escalation through DHCP → MOHAWC TFTP pull → factory reset. Fully automated dead switch replacement. The name pairing tells you exactly how it works

3. **VIKTOR -m ring selector** — MRP's own VLAN egress table IS the ring topology. No enrichment, no CLAMPS dependency, no MRP queries. Just `get_vlan_ports()` and you know which devices are in which ring and which ports are inter-switch links. Pure VLAN-level operation that perfectly traces MRP topology because MRP built those VLANs

4. **SNOOP as validator** — three layers of truth: VIKTOR says VLAN 100 should be on port 1/3 (intent). MOPS confirms it's configured (config). SNOOP confirms traffic is actually flowing (reality). The diff between them is where every problem lives

5. **sFlow rogue gateway detection** — monitoring for src IP = non-private on a network that should be 100% RFC1918. Trivially simple, catches unauthorized internet gateways, misconfigured devices, or someone bridging OT to the internet. Private→public is noise (devices seek default gateway). Public→private means the path exists and is being used

6. **BPDU Guard superiority** — RSTP has a discarding state (port held from forwarding until safe). Loop protection has no discarding state (forwards immediately, creates 1-second storm on every recovery). Not documented anywhere that clearly. Operational knowledge turned into CLAMPS code logic

7. **One site visit, everything else remote** — MARCO is the only tool that needs boots on the ground. Everything else — POLO, AARON, STONE, CLAMPS, VIKTOR, MOHAWC, SNOOP — works through one WireGuard tunnel to the Garderos. Commission once, manage forever remotely

8. **SNOOP replacing AARON's L2 dependency** — AARON could map switch-side views remotely but IP-to-MAC needed ARP which was L2. SNOOP killed that gap. The switch already sees every frame — you just ask it to tell you (sFlow sample window), then shut up. Ceiling/floor/early-exit parallelization makes it fast and polite
