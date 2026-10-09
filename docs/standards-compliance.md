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
| IEEE 802.1AB-2016 | 7.4 (Table 7-1) | LLDP destination MAC addresses (nearest bridge 01-80-C2-00-00-0E; nearest non-TPMR 01-80-C2-00-00-03; nearest customer bridge 01-80-C2-00-00-00) | lldp-core | TBD | Planned |
| IEEE 802.1AB-2016 | 8.2 | LLDPDU format and TLV ordering (Chassis ID, Port ID, TTL first; End of LLDPDU last) | lldp-codec | TBD | Planned |
| IEEE 802.1AB-2016 | 8.4 | Basic TLV format (7-bit type, 9-bit length) | lldp-codec | TBD | Planned |
| IEEE 802.1AB-2016 | 8.5.1 | End of LLDPDU TLV | lldp-codec | TBD | Planned |
| IEEE 802.1AB-2016 | 8.5.2 | Chassis ID TLV and subtypes | lldp-codec | TBD | Planned |
| IEEE 802.1AB-2016 | 8.5.3 | Port ID TLV and subtypes | lldp-codec | TBD | Planned |
| IEEE 802.1AB-2016 | 8.5.4 | Time To Live TLV; TTL = min(65535, msgTxInterval x msgTxHold + 1) | lldp-codec / lldp-core | TBD | Planned |
| IEEE 802.1AB-2016 | 8.5.5 | Port Description TLV | lldp-codec | TBD | Planned |
| IEEE 802.1AB-2016 | 8.5.6 | System Name TLV | lldp-codec | TBD | Planned |
| IEEE 802.1AB-2016 | 8.5.7 | System Description TLV | lldp-codec | TBD | Planned |
| IEEE 802.1AB-2016 | 8.5.8 | System Capabilities TLV (Station Only bit for workstation) | lldp-codec | TBD | Planned |
| IEEE 802.1AB-2016 | 8.5.9 | Management Address TLV (AFN, interface numbering, OID) | lldp-codec | TBD | Planned |
| IEEE 802.1AB-2016 | 8.6 | Organizationally Specific TLV format (type 127, OUI, subtype) | lldp-codec | TBD | Planned |
| IEEE 802.1AB-2016 | 9.2 | Transmit, transmit-timer, and receive state machines | lldp-core | TBD | Planned |
| IEEE 802.1AB-2016 | 9.2 | Timer parameters: msgTxInterval (default 30), msgTxHold (default 4), msgFastTx (default 1), txFastInit (default 4), txCreditMax (default 5), reinitDelay (default 2) | lldp-core / lldp-config | TBD | Planned |
| IEEE 802.1AB-2016 | 9.2 | Shutdown LLDPDU (TTL = 0) on admin disable / port down | lldp-core | TBD | Planned |
| IEEE 802.1AB-2016 | 9.2 | Receive validation and discard rules; too-many-neighbors handling | lldp-codec / lldp-core | TBD | Planned |
| IEEE 802.1AB-2016 | 10 / 11 | Statistics counters (`lldpStatsRxPortFramesTotal`, `...FramesDiscardedTotal`, `...FramesErrors`, `...TLVsDiscardedTotal`, `...TLVsUnrecognizedTotal`, `...AgeoutsTotal`, `lldpStatsTxPortFramesTotal`, etc.) | lldp-core | TBD | Planned |

## 5. Explicitly out of scope

- LLDP MIB / SNMP agent (802.1AB Clause 11 as an SNMP surface).
- 802.1ABdh multiframe transmit.
- LLDP-MED transmit beyond Class I capabilities (unless decided in Phase 1).
- Nearest non-TPMR and nearest customer bridge transmit (receive is cheap and will be supported for diagnostics).
