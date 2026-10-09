# WinLLDP

A production-oriented IEEE 802.1AB (LLDP) agent for Windows 11 and Windows
Server, written in Rust. It advertises the workstation to directly
connected switches, records LLDP neighbors (switch name, port, management
addresses, VLAN and PoE data), and exposes them through a CLI, a
PowerShell module, and a secured local named pipe.

```powershell
PS> winlldp neighbors
Local Interface  : Ethernet
System Name      : SW-ACCESS-01
Chassis ID       : aa:bb:cc:dd:ee:ff (macaddress)
Port ID          : GigabitEthernet1/0/24 (interfacename)
Port Description : Workstation Access Port
Management IPv4  : 10.10.10.1
Management IPv6  : 2001:db8:10::1
Capabilities     : bridge
TTL Remaining    : 104 seconds

PS> Get-WinLldpNeighbor | Select-Object InterfaceAlias, SystemName, PortId
```

## Layout

| Path | Contents |
| --- | --- |
| `crates/lldp-codec` | LLDPDU encoder/decoder, all TLVs, 802.1 / 802.3 / LLDP-MED decoders. No unsafe, fuzzed. |
| `crates/lldp-core` | Transmit/receive state machines, timers, neighbor table, statistics, agent orchestration. Platform independent. |
| `crates/lldp-config` | Versioned YAML schema, validation, interface matching, advertisement resolver. |
| `crates/lldp-ipc` | Versioned JSON request/response contract and views. |
| `crates/lldp-windows` | Adapter discovery, change monitor, Npcap backend, named pipe server, Event Log, policy, MsLldp binding control. |
| `apps/winlldp-service` | The Windows Service. |
| `apps/winlldp-cli` | `winlldp.exe`. |
| `powershell/WinLldp` | The PowerShell module. |
| `packaging/wix` | WiX v7 MSI. |
| `fuzz` | cargo-fuzz targets. |
| `docs` | Architecture, standards, security, testing, configuration, deployment, troubleshooting, IPC. |

## Build

Rust 1.99 (edition 2024). The portable crates build and test on any OS;
the service and CLI target Windows.

```sh
cargo test --workspace
cargo clippy --workspace --all-targets --target x86_64-pc-windows-msvc   # cross-check from macOS/Linux
cargo build --release -p winlldp-service -p winlldp-cli                  # on Windows
```

See `docs/deployment.md` for the MSI and `docs/testing.md` for the lab
validation plan.

## Status

Phases 1 through 5 of PLAN.MD are implemented and unit tested. Phase 6
(interoperability and Windows validation on real hardware) and Phase 7
(signed release) have not been executed yet; see `docs/standards-compliance.md`
for what is verified and what is pending.
