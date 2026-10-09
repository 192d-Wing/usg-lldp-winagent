# Testing Strategy

## Levels

| Level | Where | Runs on | Gate |
| --- | --- | --- | --- |
| Unit | each crate `src/` and `tests/` | Linux, macOS, Windows CI | every PR |
| Codec golden vectors | `crates/lldp-codec/tests/vectors/` (hex dumps from real switches, Wireshark-verified) | all | every PR |
| Negative/malformed | `crates/lldp-codec/tests/malformed.rs` | all | every PR |
| Fuzz | `fuzz/` (cargo-fuzz, libFuzzer) targets: `lldpdu_decode`, `tlv_parse`, `org_tlv_parse`, `config_parse` | Linux CI, 5 min per target per PR; nightly 1 h | every PR (smoke), nightly |
| State machine | `lldp-core` tests with mock `PacketIo` and `tokio::time::pause` | all | every PR |
| Windows cross-check | `cargo clippy` for x86_64 and aarch64 Windows targets | Linux CI | every PR |
| PowerShell | Pester tests and PSScriptAnalyzer for the WinLldp module | Windows CI | every PR |
| MSI | WiX v7 build and binary smoke test | Windows CI | every PR |
| Windows integration | adapter enumeration, pipe ACL, Event Log against a live system | lab | pre-release |
| Service lifecycle | install, start, reload, stop, uninstall on a Windows VM | lab | pre-release |
| Interoperability | Cisco IOS-XE switch + Windows 11 workstation; Linux lldpd VM | lab | pre-release |
| Wireshark validation | capture on the workstation and on a SPAN port | lab | pre-release |

## Codec test matrix (from PLAN.MD Sections 3.4 and 17)

Positive: minimal LLDPDU (3 mandatory + End); every optional TLV; each
Chassis/Port subtype; management address IPv4, IPv6, multiple; 802.1,
802.3, LLDP-MED org TLVs; unknown basic TLV; unknown org TLV; max-length
TLV (511 octets); LLDPDU filling a 1500-octet frame.

Negative: wrong EtherType; missing each mandatory TLV; duplicates of each
mandatory TLV; wrong order; TLV length past end of PDU; truncated frame;
truncated LLDPDU; zero-length Chassis/Port ID; Chassis ID > 255 octets;
reserved subtypes; management address length mismatch; org TLV shorter
than 4 octets; End TLV with nonzero length; data after End TLV; missing
End TLV (accepted with warning per 802.1AB receive rules, verify); TTL
65535; TTL 0 (shutdown).

## State machine tests
- Initial fast-start sends txFastInit frames at msgFastTx interval.
- Credit never exceeds txCreditMax; burst of local changes is rate limited.
- TTL expiry removes a neighbor at exactly rxTTL seconds (paused clock).
- TTL 0 removes immediately and emits `NeighborRemoved`, not `Expired`.
- Too-many-neighbors drops the newest and counts the discard.
- Admin disable sends one shutdown LLDPDU and then nothing.
- Interface down then up triggers fast-start.
- Config reload with changed Chassis ID triggers shutdown + fresh start.

## Interoperability checklist (Cisco IOS-XE)
On the switch: `show lldp neighbors`, `show lldp neighbors detail`,
`show lldp traffic`, `show lldp entry <name>`. Verify system name, chassis
ID (locally assigned string), port ID (MAC), port description, system
description, capabilities "S" only, management addresses (IPv4 and IPv6),
TTL 121, and that only one neighbor appears per port (MsLldp unbound).
On the workstation: `winlldp neighbors` shows the switch hostname, the
switchport name, management IP, capabilities "Bridge", PVID from the 802.1
TLV, and MAC/PHY speed from the 802.3 TLV.

## Wireshark filters
```text
lldp
eth.type == 0x88cc
eth.dst == 01:80:c2:00:00:0e
lldp.chassis.id.subtype == 7
lldp.tlv.type == 127
lldp.tlv.ttl == 0
```
