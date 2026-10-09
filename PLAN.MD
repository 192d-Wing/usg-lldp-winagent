# Windows LLDP Agent

## Production-Ready IEEE 802.1AB Implementation in Rust

### Role

Act as a senior Windows networking engineer, Rust systems developer,
and IEEE networking standards expert.

Design and implement a production-ready Windows Link Layer Discovery
Protocol (LLDP) agent that can:

1. Receive LLDP advertisements from directly connected network switches.
2. Advertise workstation identity, capabilities, and management information.
3. Maintain a database of LLDP neighbors.
4. Operate continuously as a native Windows Service.
5. Provide a command-line interface for administration and troubleshooting.
6. Expose LLDP information through a secure local IPC channel.
7. Support enterprise deployment through Microsoft Intune and MECM.
8. Meet applicable IEEE standards and Windows security requirements.

**IMPORTANT:** Before writing code, research the applicable standards,
identify Windows-specific limitations, and ask clarification questions.

Do not assume Windows networking APIs support functionality without
verifying the relevant Microsoft documentation.

---

## 1. Technology Stack

Use the following technologies:

| Component | Technology |
| --- | --- |
| Primary language | Rust |
| Rust edition | 2024 |
| Async runtime | Tokio |
| CLI framework | Clap |
| Configuration | YAML |
| Windows integration | Windows API / windows-rs |
| Windows Service | Native Windows Service |
| Local IPC | Windows Named Pipes, versioned JSON request/response |
| PowerShell module | Script module (Windows PowerShell 5.1 and PowerShell 7) |
| Logging | Windows Event Log + structured logs |
| Installer | WiX Toolset v7 / MSI |
| Testing | Cargo test, integration tests, cargo-fuzz |
| CI/CD | GitHub Actions |

### Supported operating systems

- Windows 11 Enterprise
- Windows 11 Enterprise LTSC
- Windows Server 2022
- Windows Server 2025

Support x86_64 and ARM64 where feasible.

### Design principles

- Memory-safe implementation.
- Minimal unsafe Rust.
- Modular architecture.
- Separation of protocol logic from operating system integration.
- Minimal privileges.
- No unnecessary background services.
- No telemetry sent externally by default.
- IPv6-first design.
- Enterprise security and manageability.
- Native Windows integration when feasible.

---

## 2. Standards Compliance

The implementation must comply with applicable IEEE LLDP standards.

### 2.1 IEEE 802.1AB

IEEE 802.1AB defines the Link Layer Discovery Protocol.

Implement:

- LLDPDU encoding and decoding.
- Mandatory LLDP TLVs.
- Optional LLDP TLVs.
- LLDP transmit state machine.
- LLDP receive state machine.
- LLDP neighbor information database.
- LLDP administrative states.
- LLDP timers.
- LLDP expiration mechanisms.
- LLDP shutdown advertisements.
- LLDP statistics.
- Appropriate LLDP multicast addressing.
- Error handling and protocol validation.

Verify the currently applicable IEEE 802.1AB revision and amendments.

Use authoritative IEEE documentation whenever possible.

### 2.2 Additional IEEE Standards

Evaluate implementation of:

- IEEE 802.1 organizational TLVs.
- IEEE 802.3 organizational TLVs.
- IEEE 802.1Q VLAN information.
- IEEE 802.1AX link aggregation information.
- ANSI/TIA-1057 LLDP-MED.

Implement optional extensions only when technically applicable to
Windows workstation endpoints.

### 2.3 RFC Compliance

LLDP is governed primarily by IEEE 802.1AB rather than an IETF RFC.

Identify applicable IETF RFCs for:

- IPv4 and IPv6 management address representation.
- Network interface identification.
- Network management data models.
- SNMP integration, if implemented.

Do not incorrectly characterize IEEE requirements as RFC requirements.

### 2.4 Standards Compliance Matrix

Produce a compliance matrix containing:

| Standard | Clause | Requirement | Implementation | Test Case | Status |
| --- | --- | --- | --- | --- | --- |
| IEEE 802.1AB | TBD | Chassis ID | lldp-core | TBD | Planned |
| IEEE 802.1AB | TBD | Port ID | lldp-core | TBD | Planned |
| IEEE 802.1AB | TBD | TTL | lldp-core | TBD | Planned |

Populate the matrix using verified standard references.

Do not invent clause numbers.

---

## 3. Ethernet Frame Handling

LLDP operates directly over Ethernet.

It does not use TCP or UDP.

### 3.1 Standard Ethernet Frame

| Field | Value |
| --- | --- |
| Destination MAC | 01:80:C2:00:00:0E |
| Source MAC | Local interface MAC |
| EtherType | 0x88CC |
| Payload | LLDPDU |

Support the standard nearest-bridge multicast address.

Evaluate additional IEEE-defined LLDP multicast addresses where applicable.

### 3.2 Receive Functionality

The LLDP receiver must:

1. Identify eligible network interfaces.
2. Receive Ethernet LLDP frames.
3. Filter EtherType 0x88CC.
4. Validate Ethernet and LLDPDU structure.
5. Decode mandatory TLVs.
6. Decode supported optional TLVs.
7. Decode organizationally specific TLVs.
8. Preserve unknown optional TLVs.
9. Update the neighbor database.
10. Track neighbor expiration.
11. Generate neighbor change events.

### 3.3 Transmit Functionality

The transmitter must:

1. Generate valid LLDPDUs.
2. Use the correct interface source MAC.
3. Use the appropriate LLDP destination MAC.
4. Transmit mandatory TLVs.
5. Transmit enabled optional TLVs.
6. Implement configurable transmission intervals.
7. Implement standards-compliant fast-start behavior.
8. Calculate TTL correctly.
9. Generate shutdown advertisements when required.
10. Prevent excessive transmission.

### 3.4 Input Validation

Validate:

- Incorrect EtherType.
- Invalid mandatory TLVs.
- Incorrect mandatory TLV order.
- Missing mandatory TLVs.
- Duplicate mandatory TLVs.
- Invalid TLV lengths.
- Truncated Ethernet frames.
- Truncated LLDPDUs.
- Invalid chassis identifiers.
- Invalid port identifiers.
- Malformed organizational TLVs.
- Invalid End of LLDPDU TLVs.
- Excessively large LLDPDUs.

Unknown optional TLVs must not automatically invalidate otherwise
valid packets.

Follow IEEE-defined malformed packet handling behavior.

---

## 4. LLDP TLV Support

### 4.1 Mandatory TLVs

Implement the following mandatory TLVs.

### Type 1: Chassis ID

Support appropriate subtypes:

- MAC address.
- Network address.
- Locally assigned identifier.

The Chassis ID must consistently identify the Windows workstation.

Evaluate stable identifiers that survive:

- Network adapter replacement.
- USB Ethernet adapter changes.
- Docking station changes.
- Interface renaming.

### Type 2: Port ID

Support appropriate subtypes:

- MAC address.
- Interface name.
- Locally assigned identifier.

The Port ID must uniquely identify the relevant interface
within the workstation chassis.

### Type 3: Time To Live

Implement:

- Configurable transmit interval.
- Hold multiplier.
- TTL calculation.
- Neighbor expiration.
- Shutdown TTL behavior.
- Reinitialization timing.

Validate allowable ranges against IEEE 802.1AB.

### Type 0: End of LLDPDU

Implement correct LLDPDU termination.

Enforce correct TLV encoding and ordering.

### 4.2 Optional TLVs

### Type 4: Port Description

Advertise a descriptive adapter name.

Example:

Intel Ethernet Controller I225-LM

Support:

- Windows interface alias.
- Adapter description.
- Administrator-defined description.

### Type 5: System Name

Advertise the workstation hostname.

Example:

WS-12345.example.mil

Support:

- Short hostname.
- Fully qualified domain name.
- Administrator-defined name.

### Type 6: System Description

Advertise configurable operating system information.

Example:

Microsoft Windows 11 Enterprise x64

Potential information:

- Operating system.
- Operating system version.
- Device manufacturer.
- Device model.

Sensitive information must be configurable and disabled when appropriate.

### Type 7: System Capabilities

Advertise appropriate workstation capabilities.

Do not advertise bridging or routing capabilities unless supported
and enabled.

Determine the appropriate capabilities for Windows workstation endpoints.

### Type 8: Management Address

Support:

- IPv4.
- IPv6.
- Multiple management addresses where permitted.

Allow administrators to configure which addresses are advertised.

IPv6 must be fully supported.

Do not automatically advertise temporary IPv6 privacy addresses.

Management address selection must be predictable and configurable.

---

## 5. Organizationally Specific TLVs

Implement a generic Type 127 TLV parser.

Type 127 TLVs contain:

- Organizationally Unique Identifier (OUI).
- Organizational subtype.
- Organizational data.

Requirements:

1. Support multiple organizational TLVs.
2. Preserve unknown organizational data.
3. Validate lengths.
4. Prevent malformed TLVs from causing crashes.
5. Provide decoded output for supported extensions.

Evaluate support for:

### IEEE 802.1

- Port VLAN ID.
- VLAN Name.
- Protocol Identity.

### IEEE 802.3

- MAC/PHY Configuration and Status.
- Link Aggregation.
- Maximum Frame Size.

### LLDP-MED

- LLDP-MED Capabilities.
- Network Policy.
- Location Identification.
- Inventory Information.

LLDP-MED must remain optional.

Do not advertise capabilities unsupported by the workstation.

---

## 6. Windows Networking Architecture

Investigate how to receive and transmit LLDP Ethernet frames
on supported Windows operating systems.

Evaluate the following architectures.

### 6.1 Npcap

Investigate:

- Ethernet frame capture.
- Ethernet frame injection.
- BPF filtering.
- Adapter enumeration.
- LLDP multicast reception.
- Windows Service integration.
- Driver dependencies.
- Licensing.
- Redistribution.
- ARM64 support.

### 6.2 NDIS Lightweight Filter Driver

Evaluate implementing a custom NDIS Lightweight Filter Driver.

Investigate:

- Receiving EtherType 0x88CC.
- Sending Ethernet frames.
- Interface binding.
- Kernel/user communication.
- Driver lifecycle.
- Windows driver signing.
- HVCI compatibility.
- Memory Integrity compatibility.
- Secure Boot requirements.
- Kernel crash risks.
- Driver deployment.

The Rust protocol engine should remain in user mode.

If a kernel driver is required, minimize kernel-mode functionality.

### 6.3 Native Windows LLDP

Investigate Microsoft LLDP Protocol Driver (MsLldp).

Determine:

1. Whether Windows already transmits LLDP advertisements.
2. Whether Windows exposes received LLDP neighbor data.
3. Whether a documented API exists for receiving LLDP.
4. Whether custom LLDP TLVs can be configured.
5. Whether Microsoft LLDP can coexist with this agent.
6. Whether duplicate advertisements can occur.
7. Whether native LLDP must be disabled when this agent transmits.

Do not assume MsLldp provides general-purpose LLDP APIs.

### 6.4 Windows Filtering Platform

Evaluate whether WFP can provide the required raw Ethernet
frame access.

Distinguish link-layer facilities from IP-layer filtering.

Do not assume WFP supports LLDP frame reception and injection.

### 6.5 Architecture Recommendation

Provide a comparison:

| Capability | Npcap | NDIS LWF | Native Windows |
| --- | --- | --- | --- |
| Receive LLDP | Research | Research | Research |
| Transmit LLDP | Research | Research | Research |
| Custom TLVs | Research | Research | Research |
| Driver required | Research | Research | Research |
| ARM64 | Research | Research | Research |
| Service integration | Research | Research | Research |
| Enterprise deployment | Research | Research | Research |
| Maintenance | Research | Research | Research |

Recommend the most appropriate architecture.

Prefer a user-mode implementation where technically feasible.

Design a packet I/O abstraction so the capture backend can be
changed without modifying the protocol engine.

---

## 7. Windows Network Interface Management

Use documented Windows APIs to discover network adapters.

Collect:

- Interface GUID.
- Interface LUID.
- Interface index.
- Friendly name.
- Adapter description.
- MAC address.
- Operational state.
- Link speed.
- IPv4 addresses.
- IPv6 addresses.
- Adapter type.

Support physical Ethernet adapters initially.

Evaluate:

- USB Ethernet.
- Thunderbolt Ethernet.
- Docking stations.
- Wi-Fi adapters.
- Hyper-V virtual adapters.
- VPN adapters.
- Network bridges.
- Network adapter teams.

### Interface Events

Detect:

- Link up.
- Link down.
- Adapter insertion.
- Adapter removal.
- Address changes.
- Interface renaming.
- Docking and undocking.

The service must respond without restarting.

### Administrative Modes

Support:

- Disabled.
- Receive only.
- Transmit only.
- Receive and transmit.

Apply administrative modes per interface.

---

## 8. Neighbor Database

Maintain an in-memory LLDP neighbor database.

Store:

- Local interface.
- Remote chassis ID.
- Remote port ID.
- Remote system name.
- Remote system description.
- Remote port description.
- Remote capabilities.
- Remote management addresses.
- Organizational TLVs.
- Advertised TTL.
- Remaining TTL.
- First seen timestamp.
- Last seen timestamp.
- Expiration timestamp.

Follow IEEE-defined neighbor identity and destination-scope rules.

Support multiple LLDP neighbors on the same interface.

### Neighbor Events

Generate:

- NeighborAdded.
- NeighborUpdated.
- NeighborExpired.
- NeighborRemoved.
- InterfaceUp.
- InterfaceDown.

Expire neighbors according to advertised TTL values.

Do not treat previously persisted neighbors as currently active.

---

## 9. Windows Service

Create a native Windows Service.

Service name:

WinLLDP

Executable:

winlldp-service.exe

Requirements:

- Automatic startup.
- Graceful shutdown.
- Service recovery.
- Minimal privileges.
- Configuration reload.
- Event logging.
- Interface lifecycle management.
- Service health reporting.

Follow Windows Service Control Manager requirements.

Evaluate running under:

- LocalSystem.
- LocalService.
- A restricted virtual service account.

Use the least-privileged identity that supports the selected
packet I/O implementation.

Decision (2026-10-09): v1 runs as LocalSystem with
`SERVICE_SID_TYPE_RESTRICTED` and a `RequiredPrivileges` list that
removes every privilege except `SeChangeNotifyPrivilege`. This is
required because Npcap's Admin-only mode limits device access to
SYSTEM and built-in Administrators.

---

## 10. Command-Line Interface

Create:

winlldp.exe

Use Rust Clap.

### Display Neighbors

```powershell
winlldp neighbors
```

Example:

```text
Local Interface : Ethernet
System Name     : SW-ACCESS-01
Chassis ID      : aa:bb:cc:dd:ee:ff
Port ID         : GigabitEthernet1/0/24
Port Description: Workstation Access Port
Management IPv4 : 10.10.10.1
Management IPv6 : 2001:db8:10::1
Capabilities    : Bridge
TTL Remaining   : 104 seconds
```

### Detailed Neighbor Information

```powershell
winlldp neighbors --detail
```

### JSON Output

```powershell
winlldp neighbors --json
```

### Filter by Interface

```powershell
winlldp neighbors --interface "Ethernet"
```

### List Interfaces

```powershell
winlldp interfaces
```

### Display Local Advertisement

```powershell
winlldp local
```

### Service Status

```powershell
winlldp status
```

### Enable Interface

```powershell
winlldp interface enable "Ethernet"
```

### Configure Mode

```powershell
winlldp interface mode "Ethernet" rx_tx
```

### Disable Interface

```powershell
winlldp interface disable "Ethernet"
```

### Diagnostics

```powershell
winlldp diagnostics
```

### Validate Configuration

```powershell
winlldp config validate
```

### Debugging

```powershell
winlldp debug --interface "Ethernet"
```

Diagnostic mode should display decoded LLDP TLVs.

Do not expose sensitive information unnecessarily.

---

## 11. PowerShell Module

Create a PowerShell module named:

WinLldp

The module is the primary administrative interface for scripted and
remote (PowerShell Remoting) retrieval of LLDP information.

### Requirements

- Support Windows PowerShell 5.1 and PowerShell 7.x.
- Ship as a script module (`.psm1` + `.psd1`) so no separate
  compiled binary is required.
- Communicate with the service through the same local IPC used by
  `winlldp.exe`. Do not scrape CLI text output.
- Emit typed objects (`PSTypeName`) with `format.ps1xml` views, not
  pre-formatted strings.
- Work over PowerShell Remoting and `Invoke-Command`.
- Use the noun prefix `WinLldp` to avoid collision with Microsoft's
  built-in `NetLldpAgent` module (`Get-NetLldpAgent`,
  `Enable-NetLldpAgent`, `Disable-NetLldpAgent`).
- Include comment-based or MAML help for every cmdlet.
- Include Pester tests.
- Install to `%ProgramFiles%\WindowsPowerShell\Modules\WinLldp`
  via the installer so both PowerShell 5.1 and 7 discover it.
- Evaluate publishing to an internal PowerShell repository.

### Cmdlets

```powershell
Get-WinLldpNeighbor [-InterfaceAlias <string>] [-Detailed]
Get-WinLldpInterface [-InterfaceAlias <string>]
Get-WinLldpLocalAdvertisement [-InterfaceAlias <string>]
Get-WinLldpServiceStatus
Get-WinLldpStatistic [-InterfaceAlias <string>]
Enable-WinLldpInterface -InterfaceAlias <string>
Disable-WinLldpInterface -InterfaceAlias <string>
Set-WinLldpInterface -InterfaceAlias <string> -Mode <Disabled|Rx|Tx|RxTx>
Test-WinLldpConfiguration [-Path <string>]
Update-WinLldpConfiguration    # reload the running service configuration
```

Example:

```powershell
Get-WinLldpNeighbor | Select-Object InterfaceAlias, SystemName, PortId, ManagementIPv4
Invoke-Command -ComputerName WS-12345 -ScriptBlock { Get-WinLldpNeighbor }
```

Read cmdlets must work for non-administrative users if the local IPC
read-only access control permits it.

Mutating cmdlets (`Enable-`, `Disable-`, `Set-`, `Update-`) require
administrative access and must support `-WhatIf` and `-Confirm`.

---

## 12. Configuration

Use YAML configuration.

Example:

```yaml
agent:
  enabled: true
  service_name: WinLLDP

lldp:
  transmit_interval: 30
  hold_multiplier: 4
  fast_start: true

  advertise:
    chassis_id: true
    port_id: true
    ttl: true
    system_name: true
    system_description: true
    port_description: true
    system_capabilities: true
    management_address: true

  management_addresses:
    ipv4: true
    ipv6: true
    allow_temporary_ipv6: false

interfaces:
  default:
    enabled: false

  ethernet:
    enabled: true
    mode: rx_tx

  wifi:
    enabled: false

  virtual:
    enabled: false

  exclusions:
    - "vEthernet*"
    - "VPN*"

logging:
  level: info
  windows_event_log: true

ipc:
  enabled: true
  transport: named_pipe
```

Treat this schema as a proposed design.

Validate all LLDP timer and state-machine parameters against IEEE 802.1AB.

Provide a versioned configuration schema.

Reject invalid configurations with actionable error messages.

---

## 13. Local IPC

Provide a secure local inter-process communication (IPC) channel
between the service and its administrative clients (`winlldp.exe`
and the WinLldp PowerShell module).

This is a local control channel, not a general-purpose API.

Transport: Windows Named Pipes.

Protocol: a versioned JSON request/response protocol.

- One JSON request per message, one JSON response per message.
- Every request carries a protocol version. The service rejects
  unsupported versions with an explicit error.
- Responses carry a status, a result object, or a structured error
  with a machine-readable code and a human-readable message.
- Messages are length-prefixed or newline-delimited; choose one and
  document it.
- Do not use gRPC.

Required operations:

- GetServiceStatus.
- ListInterfaces.
- GetInterfaceStatus.
- ListNeighbors.
- GetNeighborDetails.
- GetLocalAdvertisement.
- GetStatistics.
- SetInterfaceMode.
- ReloadConfiguration.

Deferred to a later phase:

- Subscriptions for neighbor and interface events.

Requirements:

- Windows ACLs on the pipe (security descriptor set at creation).
- Authenticated local access using the caller's Windows identity.
- Read-only operations available to a configurable local group.
- Mutating operations restricted to administrators.
- Versioned protocol contract documented in `docs/ipc.md`.
- Strict input validation and bounded message sizes.
- No network listener. The pipe must not be exposed remotely.

---

## 14. Logging and Statistics

Integrate Windows Event Log.

Log:

- Service startup.
- Service shutdown.
- Interface changes.
- LLDP transmission failures.
- LLDP reception failures.
- Neighbor discovery.
- Neighbor expiration.
- Configuration errors.
- Packet parser errors.

Track:

- Frames received.
- Frames transmitted.
- Frames discarded.
- TLV errors.
- Neighbor insertions.
- Neighbor deletions.
- Neighbor ageouts.

Expose statistics per interface.

Use IEEE-defined statistics where applicable.

---

## 15. Security Requirements

LLDP is an unauthenticated Layer 2 discovery protocol.

Treat all received LLDP frames as untrusted.

Implement:

- Memory-safe parsing.
- Strict bounds checking.
- TLV length validation.
- Integer overflow protection.
- Resource consumption limits.
- Neighbor database limits.
- Log rate limiting.
- Least-privilege execution.
- Secure configuration storage.
- Restricted IPC.
- No unnecessary network listeners.

Avoid unsafe Rust except where required for documented
Windows FFI integration.

### Security Restrictions

Received LLDP information must not automatically modify:

- Routing.
- DNS settings.
- IP addresses.
- VLAN configuration.
- Firewall rules.
- Network authentication.

LLDP information must never be treated as authenticated
proof of switch identity.

### Privacy

Allow administrators to disable advertisement of:

- FQDN.
- Operating system version.
- Device model.
- Hardware manufacturer.
- Management addresses.
- Custom inventory identifiers.

---

## 16. Performance

The agent must have minimal resource consumption.

Requirements:

- Low idle CPU usage.
- Small memory footprint.
- Efficient packet buffers.
- Bounded queues.
- Bounded neighbor database.
- Efficient timers.
- Event-driven interface management.
- No unnecessary polling.
- No unnecessary thread-per-interface model.

Use Tokio where asynchronous processing provides a benefit.

Avoid unnecessary abstractions in the packet processing path.

---

## 17. Testing

### Unit Tests

Test:

- Ethernet parsing.
- LLDPDU parsing.
- Mandatory TLV validation.
- Optional TLV parsing.
- Organizational TLV handling.
- TTL calculations.
- Neighbor expiration.
- Configuration validation.

### Negative Tests

Include:

- Missing mandatory TLVs.
- Duplicate mandatory TLVs.
- Invalid mandatory TLV order.
- Truncated frames.
- Invalid TLV lengths.
- Invalid organizational TLVs.
- Unknown TLVs.
- Zero TTL.
- Excessive payload lengths.
- Multiple neighbors.
- Rapid neighbor changes.

### Fuzz Testing

Use cargo-fuzz.

Fuzz:

- LLDPDU decoder.
- TLV parser.
- Organizational TLV parser.
- Configuration parser.

Malformed network traffic must never cause memory corruption
or uncontrolled application panics.

### Interoperability Testing

Test against:

- Cisco IOS-XE (available lab hardware).
- Linux lldpd (software, any Linux VM on the same L2 segment).

Deferred until hardware is available:

- Cisco NX-OS.
- Juniper Junos.
- Arista EOS.
- HPE Aruba.

Verify:

### Windows to Switch

The switch correctly identifies the Windows workstation
as an LLDP neighbor.

### Switch to Windows

The Windows agent correctly discovers the switch hostname,
physical switchport, management addresses, and capabilities.

### Wireshark Validation

Verify:

- Destination MAC.
- Source MAC.
- EtherType.
- TLV order.
- TLV lengths.
- TLV values.
- TTL.
- Capabilities.

Provide example Wireshark filters.

---

## 18. Enterprise Deployment

Create an MSI installer using WiX Toolset v7.

The deliverable format is MSI. Do not substitute MSIX or an
EXE-only installer.

WiX notes:

- Use WiX v7 (`wix` .NET tool and the WixToolset MSBuild SDK).
  Do not use WiX v3 syntax or `cargo-wix` defaults that target v3.
- WiX is subject to the Open Source Maintenance Fee for
  organizations that generate revenue. This project does not
  generate revenue and is not subject to the fee. Record this
  determination in `docs/licensing.md`.
- Run WiX in GitHub Actions on `windows-latest`.

Include:

- winlldp-service.exe
- winlldp.exe
- config.yaml
- WinLldp PowerShell module

Requirements:

- Silent installation.
- Silent uninstall.
- Service registration.
- Service removal.
- Configuration migration.
- Upgrade support.
- Rollback support.
- Installation logging.

Support deployment through:

- Microsoft Intune.
- Microsoft Configuration Manager.
- PowerShell.

Evaluate:

- Executable signing.
- Driver signing.
- Secure Boot.
- HVCI.
- Windows Defender Application Control.
- Enterprise application control policies.

Verify third-party driver licensing before distributing
any packet capture dependencies.

Decision (2026-10-09): Npcap is a separately deployed prerequisite.
The MSI does not bundle or chain Npcap. The installer checks that
Npcap is present and meets the minimum version, and the service
reports a clear Event Log error if Npcap is missing at runtime.
Deployment documentation must describe deploying Npcap through
Intune or MECM before this package.

Code signing: use Azure Trusted Signing for the executables, the MSI,
and the PowerShell module files.

---

## 19. Proposed Project Structure

Use a Rust workspace.

```text
winlldp/
├── Cargo.toml
├── crates/
│   ├── lldp-core/
│   ├── lldp-codec/
│   ├── lldp-agent/
│   ├── lldp-neighbors/
│   ├── lldp-windows/
│   ├── lldp-service/
│   ├── lldp-ipc/
│   └── lldp-config/
├── apps/
│   ├── winlldp-service/
│   └── winlldp-cli/
├── powershell/
│   └── WinLldp/
│       ├── WinLldp.psd1
│       ├── WinLldp.psm1
│       ├── WinLldp.format.ps1xml
│       └── tests/
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── interoperability/
│   └── fuzz/
├── packaging/
│   └── wix/
├── docs/
│   ├── architecture.md
│   ├── standards-compliance.md
│   ├── windows-networking.md
│   ├── configuration.md
│   ├── security.md
│   ├── ipc.md
│   ├── licensing.md
│   └── testing.md
└── examples/
    └── config.yaml
```

This is an initial structure.

Refine it if a simpler architecture is more appropriate.

Avoid excessive crate fragmentation.

---

## 20. Clarification Questions

Before implementation, interview me about the following decisions.

For every question:

1. Explain the available options.
2. Recommend an option.
3. Explain the technical tradeoffs.
4. Identify relevant IEEE or Windows requirements.

### A. Packet Access

1. Should we use Npcap or a native NDIS Lightweight Filter Driver?
2. Must the application work without third-party packet capture drivers?
3. Are administrator privileges during installation acceptable?
4. Must the solution support HVCI and Windows Credential Guard?

### B. Windows LLDP Integration

1. Should the application replace native Microsoft LLDP transmission?
2. Should it coexist with Microsoft's LLDP implementation?
3. How should duplicate LLDP advertisements be prevented?

### C. Workstation Identity

1. Should Chassis ID use a MAC address or stable custom identifier?
2. Should the workstation advertise its FQDN?
3. Should operating system and hardware inventory be advertised?
4. Should Port ID use the physical MAC or Windows interface alias?

### D. Network Interfaces

 1. Should Wi-Fi interfaces be supported?
 2. Should Hyper-V virtual interfaces be supported?
 3. Should all physical Ethernet interfaces be enabled automatically?
 4. How should USB Ethernet adapters and docking stations be handled?

### E. LLDP Extensions

 1. Is standard IEEE 802.1AB sufficient initially?
 2. Is LLDP-MED required?
 3. Are IEEE 802.1 VLAN TLVs required?
 4. Should vendor-specific TLVs be decoded?

### F. Management

 1. Which local group should be granted read-only IPC access?
 2. Should nonadministrative users be able to query neighbors?
 3. Is centralized configuration required?
 4. Must the PowerShell module support Windows PowerShell 5.1, or is PowerShell 7 sufficient?
 5. Should the PowerShell module be published to an internal repository or only shipped in the MSI?

### G. Deployment

 1. Will deployment use Intune, MECM, or another platform?
 2. Must installation and upgrades be silent?
 3. Are signed binaries and drivers required?

### H. Operational Requirements

 1. Must the agent work on IPv6-only networks?
 2. Should advertisement settings be configurable per interface?
 3. Should historical neighbors be stored?
 4. Are DoD STIG or additional hardening requirements applicable?
 5. Is a future Linux implementation planned?

Ask additional questions if necessary.

Do not begin coding until these architectural decisions have
been resolved.

---

## 21. Implementation Phases

### Phase 1: Requirements and Architecture

- Ask clarification questions.
- Verify applicable IEEE standards.
- Research Windows packet I/O capabilities.
- Evaluate native Windows LLDP integration.
- Recommend the architecture.
- Produce the standards compliance matrix.
- Document known limitations.

### Phase 2: Protocol Engine

Implement:

- LLDPDU encoder.
- LLDPDU decoder.
- TLV framework.
- Protocol validation.
- Neighbor model.
- Protocol timers and state machines.
- Unit tests.
- Fuzz testing.

Keep this component platform-independent.

### Phase 3: Windows Integration

Implement:

- Interface discovery.
- LLDP frame reception.
- LLDP frame transmission.
- Interface monitoring.
- Packet I/O backend.

### Phase 4: Windows Agent

Implement:

- Background service.
- LLDP state machines.
- Neighbor database.
- Configuration management.
- Logging.
- Statistics.

### Phase 5: Administration

Implement:

- CLI.
- JSON output.
- Local IPC.
- PowerShell module.
- Neighbor events.
- Diagnostic commands.

### Phase 6: Validation

Perform:

- IEEE compliance testing.
- Wireshark validation.
- Switch interoperability testing.
- Windows compatibility testing.
- Security testing.
- Fuzzing.
- Performance testing.

### Phase 7: Packaging

Produce:

- MSI installer.
- Silent deployment instructions.
- Upgrade instructions.
- Configuration documentation.
- Troubleshooting documentation.

---

## 22. Definition of Done

The project is complete when:

1. The agent runs as a native Windows Service.
2. Physical Ethernet adapters are automatically discovered.
3. LLDP advertisements are successfully received.
4. The upstream switch and switchport are correctly identified.
5. Workstation LLDP advertisements are successfully transmitted.
6. Cisco IOS-XE can identify the workstation. Juniper Junos is deferred until hardware is available.
7. Neighbor information is accessible through the CLI and the PowerShell module.
8. IPv4 and IPv6 management addresses are supported.
9. Configuration changes can be applied without restarting Windows.
10. Network interface changes are automatically handled.
11. Applicable IEEE 802.1AB requirements are implemented.
12. The packet parser passes malformed-input and fuzz testing.
13. The service operates with minimum required privileges.
14. The application is compatible with enterprise security controls.
15. The application can be silently deployed using an MSI.
16. Standards compliance and interoperability results are documented.

Do not claim production readiness without supporting test evidence.

---

## 23. Initial Response Instructions

Your first response must not contain implementation code.

Instead:

1. Identify the applicable IEEE standards and relevant RFCs.
2. Summarize Windows implementation challenges.
3. Explain packet reception and transmission options.
4. Identify potential conflicts with Microsoft LLDP.
5. Present a preliminary architecture recommendation.
6. Ask the clarification questions from Section 20.
7. Include your recommended answers and reasoning.
8. Identify important requirements not covered in this prompt.

After I answer, produce:

- Architecture design.
- Component design.
- Windows packet I/O decision.
- Standards compliance matrix.
- Security model.
- Implementation plan.
- Testing strategy.

Then begin implementation in small, testable increments.

Prioritize:

1. Protocol correctness.
2. IEEE standards compliance.
3. Windows compatibility.
4. Security.
5. Enterprise deployability.
6. Maintainability.
7. Performance.

Do not sacrifice correctness for development speed.
