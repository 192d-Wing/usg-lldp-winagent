# Architecture

Status: design baseline, 2026-10-09. Supersedes the "Research" entries in
PLAN.MD Section 6.5.

## 1. Packet I/O decision

**Npcap, deployed as a separate prerequisite, accessed through a
`PacketIo` trait.**

- Rationale: it is the only signed, HVCI-compatible, ARM64-capable,
  maintained way to send and receive raw Ethernet frames from user mode on
  Windows without writing a kernel driver. See docs/windows-networking.md.
- Not bundled: the MSI neither installs nor chains Npcap. The organization
  deploys Npcap (free edition is acceptable for internal use; the OEM
  internal-use license is the organization's call) before this package.
- Minimum version: Npcap 1.50 (ARM64 support). The service checks the
  `wpcap.dll` version at startup and refuses to start packet I/O if the
  minimum is not met, logging Event ID `NpcapMissing` / `NpcapTooOld`.
- Binding: `wpcap.dll` is loaded dynamically at runtime (`LoadLibrary` from
  `%SystemRoot%\System32\Npcap`), never statically linked, so the service
  binary starts, reports status, and logs a clear error even when Npcap is
  absent.
- Backend substitution: `PacketIo` is the only interface the agent uses.
  Backends: `npcap` (production), `mock` (tests), `lwf` (reserved).

## 2. Process model

One service process, `winlldp-service.exe`, running as LocalSystem with a
restricted service SID and minimal privileges. One Tokio multi-thread
runtime with a small worker count (2). No thread-per-interface: each
interface is a Tokio task that awaits frames from its packet channel and
timer ticks.

```text
+-----------------------------------------------------------------------+
| winlldp-service.exe                                                   |
|                                                                       |
|  SCM glue (windows-service)  ---->  Agent (lldp-core)                 |
|     start/stop/reload/shutdown        |                               |
|                                       |  per-interface Port task      |
|  Interface monitor (lldp-windows) --->|   tx state machine            |
|     NotifyIpInterfaceChange           |   rx state machine            |
|     GetAdaptersAddresses              |   neighbor table              |
|                                       |   statistics                  |
|  PacketIo backend (lldp-windows) <--->|                               |
|     npcap: recv loop -> mpsc          |                               |
|            send()                     v                               |
|                                  Neighbor DB + event bus (broadcast)  |
|                                       |                               |
|  IPC server (lldp-ipc, named pipe) <--+                               |
|  Event Log sink (lldp-windows)     <--+                               |
+-----------------------------------------------------------------------+
            ^                                      ^
            | named pipe, JSON                     | named pipe, JSON
   winlldp.exe (CLI)                      WinLldp PowerShell module
```

## 3. Crates

Seven crates. `lldp-agent` and `lldp-neighbors` from the proposed layout are
folded into `lldp-core`; splitting them added boundaries without reducing
coupling.

| Crate | Depends on | OS-specific | Contents |
| --- | --- | --- | --- |
| `lldp-codec` | none (std only) | No | Ethernet header, TLV framing, mandatory/optional/organizational TLV types, encoder, decoder, validation errors. `#![forbid(unsafe_code)]`. Fuzz target. |
| `lldp-core` | `lldp-codec`, `tokio` | No | Transmit/receive state machines, timers, credit, neighbor table (per port, MSAP-keyed), statistics, local-system model (`LocalSystem`, `LocalPort`), event types, `PacketIo` trait, mock backend. |
| `lldp-config` | `serde`, `serde_yaml` | No | Versioned YAML schema, validation with actionable errors, interface matching rules, policy-override merge. |
| `lldp-ipc` | `serde`, `serde_json` | No | Request/response types, protocol version, error codes, framing. Shared by service and CLI. |
| `lldp-windows` | `windows`, `lldp-core` | Yes | Adapter discovery, interface change notifications, Npcap `PacketIo` backend, named pipe server with security descriptor, Event Log sink, Windows version/SMBIOS lookup, `ms_lldp` binding control. |
| `winlldp-service` | all | Yes | SCM integration, config loading, agent wiring, Event IDs, install/uninstall helpers (`--install`, `--uninstall` for dev use; MSI does it in production). |
| `winlldp-cli` | `lldp-ipc`, `clap` | Yes (pipe client only) | All commands from PLAN.MD Section 10, table and `--json` output. |

`lldp-codec`, `lldp-core`, `lldp-config`, `lldp-ipc` build and test on any
platform. CI runs them on Linux and macOS as well as Windows so the
protocol engine never grows a Windows dependency by accident.

## 4. Key types

### `PacketIo` (lldp-core)

```rust
pub trait PacketIo: Send + Sync {
    fn open(&self, adapter: &AdapterId) -> Result<Box<dyn PacketChannel>, PacketIoError>;
}
pub trait PacketChannel: Send {
    fn mac(&self) -> MacAddr;
    fn send(&mut self, frame: &[u8]) -> Result<(), PacketIoError>;
    /// Receives one complete Ethernet frame already filtered to EtherType 0x88CC.
    fn recv(&mut self) -> impl Future<Output = Result<Bytes, PacketIoError>> + Send;
}
```

Adapter enumeration is deliberately *not* in `PacketIo`; it belongs to the
interface monitor, which uses IP Helper and then asks the backend to open a
channel by adapter GUID.

### Port (lldp-core)

One `Port` per managed interface, owning:

- `admin_status`: Disabled | RxOnly | TxOnly | RxTx (802.1AB `adminStatus`).
- Transmit state machine with `txTTR` timer, `txFast`, `txCredit`,
  `txNow`, `localChange`.
- Receive state machine with per-neighbor `rxTTL` expiry.
- `NeighborTable`: `BTreeMap<Msap, Neighbor>` bounded by
  `max_neighbors_per_port` (default 8; 802.1AB "too many neighbors"
  handling drops the newest).
- `PortStats` mirroring the 802.1AB statistics group.

MSAP (MAC Service Access Point) identity = (Chassis ID subtype+value,
Port ID subtype+value). Destination address scope is part of the key so
nearest-bridge and nearest-customer-bridge neighbors never collide.

### Events

`broadcast::Sender<AgentEvent>` with variants `NeighborAdded`,
`NeighborUpdated`, `NeighborExpired`, `NeighborRemoved`, `InterfaceUp`,
`InterfaceDown`, `InterfaceAdded`, `InterfaceRemoved`, `ConfigReloaded`.
Consumers: Event Log sink (rate limited), statistics, future IPC
subscriptions.

## 5. Data flow

Receive: Npcap thread (blocking `pcap_next_ex` with BPF
`ether proto 0x88cc`) -> bounded `mpsc` (capacity 64 frames per interface;
overflow increments `FramesDiscardedTotal`) -> Port task -> `lldp-codec`
decode -> validation -> neighbor table update -> events.

Transmit: Port task timer fires -> `LocalSystem` snapshot + `LocalPort` ->
`lldp-codec` encode -> `PacketChannel::send`. Encoding is done per
transmission (cheap, few hundred bytes) so address changes are reflected
without cache invalidation logic. Local changes (hostname, addresses,
config reload) set `localChange` which triggers an immediate transmission
subject to `txCredit`.

Shutdown: on admin disable, interface down, config removing an interface,
or service stop, each Tx-capable port sends one LLDPDU with TTL 0 before
closing the channel.

## 6. Local system information

| TLV | Source | Notes |
| --- | --- | --- |
| Chassis ID | Config: `locally_assigned` (default, value = hostname), `smbios_uuid`, `custom`, `mac` | Computed once at startup and on config reload; never changes while running. |
| Port ID | Adapter MAC (subtype 3) default; `interface_name` (subtype 5) optional | Per port. |
| Port Description | `"<alias> (<adapter description>)"` or admin override | Truncated to 255 octets. |
| System Name | FQDN if domain-joined else hostname; config override; privacy toggle | `GetComputerNameExW(ComputerNameDnsFullyQualified)` |
| System Description | `"Microsoft Windows 11 Enterprise 24H2 (x64)"` from `RtlGetVersion` + registry `ProductName`/`DisplayVersion`; optional manufacturer/model from SMBIOS | Each element individually toggleable. |
| Capabilities | `StationOnly` set and enabled. `Bridge` only if a Hyper-V vSwitch or network bridge exists *and* config `advertise_bridge: true`. Never `Router`. | |
| Management Address | Per port: IPv6 GUA, then ULA, then IPv4 non-APIPA. Skip temporary (`SuffixOrigin == Random`), link-local, deprecated, tentative. Interface numbering = ifIndex (RFC 2863). | Config can pin addresses or disable families. |

## 7. Configuration

YAML file at `%ProgramData%\WinLLDP\config.yaml`, ACL: SYSTEM and
Administrators full control, Users read. Schema version field required.
Registry policy overrides at `HKLM\SOFTWARE\Policies\WinLLDP` for:
`Enabled`, `DefaultMode`, `AdvertiseFqdn`, `AdvertiseOsVersion`,
`AdvertiseHardware`, `AdvertiseManagementAddress`. Policy wins over file.
Reload: `winlldp config reload` (IPC) or SCM control code 128.

## 8. IPC

Named pipe `\\.\pipe\WinLLDP`. Security descriptor: read-class requests
allowed for Authenticated Users, mutating requests additionally checked
in-process against the client token (`ImpersonateNamedPipeClient` ->
`CheckTokenMembership(Administrators)`). One JSON object per message,
4-byte big-endian length prefix, 1 MiB max. Request carries
`{"v":1,"op":"ListNeighbors","params":{...}}`; response carries
`{"v":1,"ok":true,"result":...}` or `{"v":1,"ok":false,"error":{"code":"...","message":"..."}}`.
Full contract in docs/ipc.md (written in Phase 5).

## 9. MsLldp coexistence

On transition of a port to `TxOnly` or `RxTx`, the service disables the
`ms_lldp` binding on that adapter via the `MSFT_NetAdapterBindingSettingData`
CIM class (equivalent to `Disable-NetAdapterBinding -ComponentID ms_lldp`),
after recording the previous state under
`HKLM\SOFTWARE\WinLLDP\State\Bindings\<GUID>`. On port disable, uninstall,
or config change back to `RxOnly`, the recorded state is restored. The
behavior is controlled by `windows.manage_mslldp_binding` (default true).

## 10. Deferred

- IPC event subscriptions.
- Neighbor persistence.
- LLDP-MED transmit, 802.1Q TLV transmit.
- First-party LWF backend.
- Juniper, Arista, NX-OS, Aruba interoperability (no hardware).
- ARM64 and Windows Server validation (no hardware; builds are produced).
