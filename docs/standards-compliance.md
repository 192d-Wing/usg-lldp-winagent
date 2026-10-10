# Standards Compliance (Phase 1 draft)

Status: research draft. Clause numbers marked **verify** must be checked
against the published IEEE text before they are cited in code or tests.
IEEE 802.1AB-2016 is available at no cost through the IEEE GET Program
(IEEE Xplore, free account required).

## 1. Governing standard

| Standard | Status (as of 2026-10) | Relevance |
| --- | --- | --- |
| IEEE Std 802.1AB-2016 | Active base standard (supersedes 802.1AB-2009) | Primary. LLDPDU format, TLVs, state machines, timers, MIB. |
| IEEE Std 802.1ABcu-2021 | Published amendment 1 | YANG data model for LLDP. Useful as a reference schema for the IPC/JSON model. No wire-format change. |
| IEEE Std 802.1ABdh-2021 | Published amendment 2 | "LLDPv2" multiframe LLDPDUs. Not required for a workstation endpoint. Decode defensively, do not implement transmit. |
| P802.1AB-Rev | In ballot, unpublished | Full revision. Track; do not target. |

Sources: IEEE 802.1 project pages for
[P802.1AB-2016-Revision](https://1.ieee802.org/maintenance/p802-1ab-2016-revision-station-and-media-access-control-connectivity-discovery/),
[P802.1ABcu](https://1.ieee802.org/tsn/802-1abcu/), and
[802.1ABdh-2021 on IEEE Xplore](https://ieeexplore.ieee.org/document/9760302).

## 2. Organizationally specific TLV standards

| OUI | Owner | Defining document | TLVs of interest to a workstation |
| --- | --- | --- | --- |
| 00-80-C2 | IEEE 802.1 | IEEE 802.1Q (Annex D, "IEEE 802.1 Organizationally Specific TLVs") | Port VLAN ID (subtype 1), Port and Protocol VLAN ID (2), VLAN Name (3), Protocol Identity (4), Link Aggregation (7). Decode only; a workstation has no reason to transmit VLAN TLVs. |
| 00-12-0F | IEEE 802.3 | IEEE 802.3 Clause 79 | MAC/PHY Configuration/Status (subtype 1), Power via MDI (2), Link Aggregation (3, **deprecated** in favor of the 802.1 TLV), Maximum Frame Size (4), EEE (5), Additional Ethernet Capabilities (7). Decode all; transmit MAC/PHY and Max Frame Size as optional. |
| 00-12-BB | TIA | ANSI/TIA-1057 (LLDP-MED) | Capabilities, Network Policy, Location, Extended Power, Inventory. Decode. Transmit only if explicitly enabled; a Windows workstation is a "Class I generic endpoint" at most. |

Subtype numbers above come from the IEEE 802.1 assigned-numbers document and
802.3 Clause 79 baseline drafts; **verify** against the current published
802.1Q-2022 and 802.3-2022 text before encoding.

## 3. Applicable IETF RFCs

LLDP itself is not an IETF protocol. The following RFCs are referenced by
802.1AB or are needed to represent its data correctly.

| Area | RFC | Why it applies |
| --- | --- | --- |
| Management address family numbers | IANA "Address Family Numbers" registry (RFC 3232 moved it out of RFC 1700) | 802.1AB Management Address TLV subtype field uses IANA AFN values: 1 = IPv4, 2 = IPv6. |
| Interface numbering in Management Address TLV | RFC 2863 (IF-MIB) | Interface numbering subtype 2 is `ifIndex`. Windows `IfIndex` from `GetAdaptersAddresses` maps to this. |
| IPv6 addressing architecture | RFC 4291 | Address classification (link-local, ULA, global) for management address selection. |
| IPv6 scoped addresses | RFC 4007 | Link-local addresses carry a zone; advertise with care or not at all. |
| IPv6 temporary addresses | RFC 8981 (obsoletes RFC 4941) | Must not be advertised by default. Windows exposes `PrefixOrigin`/`SuffixOrigin` so temporary addresses are identifiable. |
| Default address selection | RFC 6724 | Basis for predictable management address ordering. |
| IPv6 text representation | RFC 5952 | CLI/JSON/PowerShell output format. |
| JSON | RFC 8259 | IPC wire format. |
| YANG | RFC 7950 | Only via 802.1ABcu, as a schema reference. |
| SNMP | RFC 3410-3418 | Not planned. Listed to make the exclusion explicit. |

## 4. Compliance matrix (skeleton)

Clause numbers below reflect 802.1AB-2016 as best known; every row is
**verify** until checked against the standard text.

| Standard | Clause | Requirement | Implementation | Test Case | Status |
| --- | --- | --- | --- | --- | --- |
| IEEE 802.1AB-2016 | 7.4 (Table 7-1) | LLDP destination MAC addresses (nearest bridge 01-80-C2-00-00-0E; nearest non-TPMR 01-80-C2-00-00-03; nearest customer bridge 01-80-C2-00-00-00) | lldp-codec `ethernet::LldpDestination` | `lldpdu::ethernet_frame_roundtrip`, `port::own_echo_and_non_lldp_destinations_are_ignored` | Implemented, unit tested; lab pending |
| IEEE 802.1AB-2016 | 8.2 | LLDPDU format and TLV ordering (Chassis ID, Port ID, TTL first; End of LLDPDU last) | lldp-codec `Lldpdu::decode/encode` | `lldpdu::wrong_mandatory_order_rejected`, `missing_mandatory_tlvs_rejected`, `duplicate_mandatory_rejected` | Implemented, unit tested, fuzzed |
| IEEE 802.1AB-2016 | 8.4 | Basic TLV format (7-bit type, 9-bit length) | lldp-codec `tlv` | `lldpdu::bad_tlv_lengths_rejected`, `max_length_tlv_roundtrips`, fuzz `tlv_parse` | Implemented, unit tested, fuzzed |
| IEEE 802.1AB-2016 | 8.5.1 | End of LLDPDU TLV | lldp-codec | `lldpdu::end_tlv_with_length_is_warning`, `missing_end_tlv_is_warning` | Implemented, unit tested; lab pending |
| IEEE 802.1AB-2016 | 8.5.2 | Chassis ID TLV and subtypes | lldp-codec `types::ChassisId` | `lldpdu::invalid_identifiers_rejected`, `encode_rejects_invalid_values` | Implemented, unit tested; lab pending |
| IEEE 802.1AB-2016 | 8.5.3 | Port ID TLV and subtypes | lldp-codec `types::PortId` | `lldpdu::invalid_identifiers_rejected` | Implemented, unit tested; lab pending |
| IEEE 802.1AB-2016 | 8.5.4 | Time To Live TLV; TTL = min(65535, msgTxInterval x msgTxHold + 1) | lldp-codec / lldp-core `TimerParams::ttl` | `lldpdu::zero_ttl_and_max_ttl_decode`, `port::timer_params_validation_and_ttl` | Implemented, unit tested; lab pending |
| IEEE 802.1AB-2016 | 8.5.5 | Port Description TLV | lldp-codec | `lldpdu::full_roundtrip`, `overlong_string_tlv_discarded` | Implemented, unit tested; lab pending |
| IEEE 802.1AB-2016 | 8.5.6 | System Name TLV | lldp-codec | `lldpdu::full_roundtrip`, `duplicate_optional_keeps_first` | Implemented, unit tested; lab pending |
| IEEE 802.1AB-2016 | 8.5.7 | System Description TLV | lldp-codec | `lldpdu::full_roundtrip` | Implemented, unit tested; lab pending |
| IEEE 802.1AB-2016 | 8.5.8 | System Capabilities TLV (Station Only bit for workstation) | lldp-codec `types::SystemCapabilities` | `lldpdu::capabilities_short_names`, `invalid_capabilities_discarded`, `resolver::defaults_advertise_fqdn_os_and_station_only` | Implemented, unit tested; lab pending |
| IEEE 802.1AB-2016 | 8.5.9 | Management Address TLV (AFN, interface numbering, OID) | lldp-codec `types::ManagementAddress` | `lldpdu::management_address_edge_cases`, `resolver::management_address_rules` | Implemented, unit tested; lab pending |
| IEEE 802.1AB-2016 | 8.6 | Organizationally Specific TLV format (type 127, OUI, subtype) | lldp-codec `org` | `lldpdu::org_tlv_too_short_discarded`, `org::*`, fuzz `org_tlv_parse` | Implemented, unit tested; lab pending |
| IEEE 802.1AB-2016 | 9.2 | Transmit, transmit-timer, and receive state machines | lldp-core `port::Port` | `port::link_up_starts_fast_transmission_then_normal_interval`, `receive_adds_updates_and_expires_neighbors`, `new_neighbor_triggers_fast_start` | Implemented, unit tested; fast-period count marked verify |
| IEEE 802.1AB-2016 | 9.2 | Timer parameters: msgTxInterval (default 30), msgTxHold (default 4), msgFastTx (default 1), txFastInit (default 4), txCreditMax (default 5), reinitDelay (default 2) | lldp-core `TimerParams`, lldp-config | `port::credit_limits_bursts_of_local_changes`, `config::range_violations_are_collected_with_paths` | Implemented, unit tested; ranges marked verify |
| IEEE 802.1AB-2016 | 9.2 | Shutdown LLDPDU (TTL = 0) on admin disable / port down | lldp-core `Port::tx_shutdown` | `port::admin_disable_sends_shutdown_and_waits_reinit_delay`, `agent_shutdown_sends_ttl_zero_and_clears`, `runtime::driver_transmits_receives_and_shuts_down` | Implemented, unit tested |
| IEEE 802.1AB-2016 | 9.2 | Receive validation and discard rules; too-many-neighbors handling | lldp-codec, lldp-core `NeighborTable` | `port::too_many_neighbors_drops_newest`, `malformed_frames_are_counted_not_fatal`, `ttl_zero_removes_immediately` | Implemented, unit tested |
| IEEE 802.1AB-2016 | 10 / 11 | Statistics counters (`lldpStatsRxPortFramesTotal`, `...FramesDiscardedTotal`, `...FramesErrors`, `...TLVsDiscardedTotal`, `...TLVsUnrecognizedTotal`, `...AgeoutsTotal`, `lldpStatsTxPortFramesTotal`, etc.) | lldp-core `PortStats` | `port::*` assertions on `stats()` | Implemented, unit tested |

## 5. Lab validation (in progress)

Started 2026-10-09 on a Windows 11 Enterprise 25H2 (build 26200) x64
workstation, Intel I219-LM, Npcap 1.88, attached to a Cisco C9200CX
(IOS-XE 26.01.1) port Gi1/0/10. The runs so far were a non-elevated
`--console` run with a parallel dumpcap capture, so everything that needs
elevation or the switch CLI is still pending.

| Check | Result |
| --- | --- |
| Switch `show lldp neighbors detail` shows the workstation with locally assigned chassis ID, MAC port ID, system name, capabilities S, TTL 121 | pass 2026-10-09 on Gi1/0/10: chassis ID `OOPLL-PNT010`, port ID `fc4c.eac9.2845`, port description, system name, system description "Microsoft Windows 11 Enterprise 25H2 (build 26200) x64", capabilities S / S, two IPv6 management addresses, time remaining 107 s (consistent with TTL 121; the 121 itself was confirmed in the capture) |
| Exactly one neighbor per port (MsLldp unbound) | partial 2026-10-09: elevated, `ms_lldp` is unbound at start (event 1400) and bound again after stop with the recorded state cleared; non-elevated, the unbind fails cleanly with event 1401 and the binding is untouched. Still to confirm on the switch that only one neighbor is listed |
| `winlldp neighbors` shows switch name, port, management addresses, PVID, MAC/PHY | pass 2026-10-09: system name, port ID `Gi1/0/10`, IPv4 and IPv6 management addresses, PVID 250, MAC/PHY (MAU type 30), capabilities bridge and router |
| Wireshark: TLV order, lengths, values as in docs/troubleshooting.md | pass 2026-10-09 for transmit: destination 01:80:c2:00:00:0e, 226-byte frame, TLV types 1,2,3,4,5,6,7,8,8,0, chassis ID subtype 7, port ID subtype 3, TTL 121, Station Only, nothing flagged malformed. Both management addresses were IPv6 (see findings) |
| Fast transmission on link up and on a new neighbor (decision I4) | pass 2026-10-09: 4 frames 1 s apart at start, 4 more starting 0.2 ms after the switch's first LLDPDU, then the 30 s interval |
| Shutdown LLDPDU on service stop clears the switch entry | partial 2026-10-09: a real Ctrl+C in `--console` mode exits cleanly and logs event 1001 (the earlier scripted Ctrl+C never reached the process). On a repeat elevated run, tshark showed the TTL 0 frame at Ctrl+C and the switch entry cleared immediately: pass for console mode. (A first run was reported as not clearing straight away and was not captured.) The same check on `Stop-Service` is still pending |
| Dock / undock, cable pull, sleep / resume handled without restart | pending |
| Config reload without restart | pending |
| Service token holds only SeChangeNotifyPrivilege; restricted SID | pending |
| Silent MSI install, upgrade, uninstall with logs | pending |

Findings from the first run, fixed:

- `GetIfTable2` rows for NDIS filter modules (WFP, QoS, Npcap) were listed
  as interfaces (39 instead of 14). They are now skipped.
- An unplugged USB NIC (operational status not present) was opened on every
  start and logged event 1202. Not-present adapters are now skipped.
- System Description said "Windows 10" on Windows 11 because the registry
  `ProductName` still does. Corrected from the build number.
- `winlldp neighbors` failed with `missing field ttl` once a neighbor
  existed: `NeighborView` had a `ttl` member that collided with the
  flattened LLDPDU's. The duplicate was removed.
- A multi-line System Description (Cisco IOS) was shown as hex. Line breaks
  are now kept.
- The `ms_lldp` restore on stop was not logged because the service reported
  stopped before the binding change finished. It now waits for it.
- With two IPv6 global addresses and `max_per_interface: 2`, the IPv4
  address was not advertised. Each address family now keeps at least one
  slot when the limit is 2 or more (not yet re-checked on the switch).

Findings still open:

- `backend.open()` blocks under the agent lock. In two of the non-elevated
  runs it took 14 to 16 s and IPC calls waited that long; in a third it
  took about 1 s. The cause of the slow opens is not established, and it
  has not been measured under LocalSystem.
- `winlldp diagnostics` exits 0 when a check reports FAIL.

## 6. Explicitly out of scope

- LLDP MIB / SNMP agent (802.1AB Clause 11 as an SNMP surface).
- 802.1ABdh multiframe transmit.
- LLDP-MED transmit beyond Class I capabilities (unless decided in Phase 1).
- Nearest non-TPMR and nearest customer bridge transmit (receive is cheap and will be supported for diagnostics).
