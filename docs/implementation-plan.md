# Implementation Plan

Each increment ends with passing tests and a reviewable diff.

## Phase 2: Protocol engine (platform independent)
1. Workspace scaffold, CI matrix (Linux/macOS/Windows), `cargo deny`.
2. `lldp-codec`: TLV framing, mandatory TLVs, End TLV, encoder, decoder,
   validation errors, unit tests.
3. `lldp-codec`: optional TLVs (4-8), management address IPv4/IPv6.
4. `lldp-codec`: organizational TLV framing; 802.1 (PVID, VLAN name,
   PPVID, protocol identity, link aggregation), 802.3 (MAC/PHY, power via
   MDI, link aggregation, max frame size), LLDP-MED (capabilities, network
   policy, location, extended power, inventory).
5. `lldp-codec`: golden vectors from real captures; negative test matrix;
   fuzz targets and seed corpus.
6. `lldp-core`: `PacketIo` trait + mock; `LocalSystem`/`LocalPort` model;
   TTL math; neighbor table with MSAP keys and bounds; statistics.
7. `lldp-core`: transmit state machine with timers and credit; receive
   state machine with expiry; shutdown; events. Tests with paused time.
8. `lldp-config`: schema v1, validation, interface matching, policy
   override merge, fuzz target.

## Phase 3: Windows integration
9. `lldp-windows`: adapter discovery via IP Helper; classification
   (physical Ethernet, Wi-Fi, virtual, VPN); change notifications.
10. `lldp-windows`: Npcap backend (dynamic `wpcap.dll` load, BPF filter,
    recv thread -> mpsc, send); version check.
11. `lldp-windows`: Windows version/SMBIOS lookup; `ms_lldp` binding
    control with state recording.

## Phase 4: Agent and service
12. `winlldp-service`: SCM integration, restricted SID/privileges,
    startup checks, config load, Event Log provider and IDs, statistics.
13. Agent wiring: interface monitor -> ports -> packet channels; reload;
    graceful shutdown with TTL 0.

## Phase 5: Administration
14. `lldp-ipc` contract and named pipe server with ACL and admin checks.
15. `winlldp-cli`: all commands, table and JSON output.
16. PowerShell module `WinLldp` with format views and Pester tests.
17. `winlldp debug` / `diagnostics`.

## Phase 6: Validation
18. Lab: Cisco IOS-XE + Windows 11; Wireshark captures committed as test
    vectors; results recorded in docs/standards-compliance.md.
19. Security review against docs/security.md; fuzz soak.

## Phase 7: Packaging
20. WiX v7 MSI, Npcap prerequisite check, upgrade/rollback, logging.
21. Azure Trusted Signing in GitHub Actions; SBOM.
22. Intune and MECM deployment docs; troubleshooting guide.
