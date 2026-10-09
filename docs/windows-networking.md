# Windows Networking Research (Phase 1)

Status: research findings and recommendation. Items marked **lab** must be
confirmed on real hardware before being treated as fact.

## 1. The core problem

Windows has no user-mode API for sending or receiving arbitrary Ethernet
frames. Winsock raw sockets operate at the IP layer and cannot bind to an
EtherType. Receiving and transmitting EtherType 0x88CC therefore requires a
kernel component. The only questions are whose kernel component, and how
much of it we own.

## 2. Options evaluated

### 2.1 Npcap (NDIS 6 lightweight filter, third party)

- Receive: yes. Npcap is an NDIS LWF; it sees inbound frames including
  01-80-C2-00-00-0E multicast. A BPF filter `ether proto 0x88cc` keeps the
  user-mode copy cost to LLDP frames only.
- Transmit: yes, `pcap_sendpacket` sends the buffer unmodified.
- Adapter enumeration: via `pcap_findalldevs`; correlate to Windows
  interfaces by the `\Device\NPF_{GUID}` name, which embeds the adapter GUID.
- Signed, HVCI-compatible, ARM64 support since Npcap 1.50 (2021).
- Service integration: works from a Windows Service. Npcap's optional
  "Admin-only" install mode restricts its device objects to SYSTEM and
  built-in Administrators, which constrains the service identity (see 5).
- Licensing: the free edition does **not** permit redistribution. Bundling
  or silently installing Npcap in our MSI requires the Npcap OEM
  Redistribution License (perpetual or term). Alternative: require Npcap as a
  separately deployed prerequisite, which avoids the license but adds an
  Intune/MECM dependency and version-drift risk. The `/require_version` and
  `/require_features` installer switches (Npcap 1.55+) help here.
- Maintenance: external, actively maintained, used by Wireshark and Nmap.

Sources: [Npcap OEM](https://npcap.com/oem/),
[OEM Redistribution License](https://npcap.com/oem/redist),
[Npcap changelog](https://npcap.com/changelog),
[Npcap Users' Guide](https://npcap.com/guide/npcap-users-guide.html).

### 2.2 Custom NDIS Lightweight Filter driver

- Technically ideal: a minimal LWF that only passes EtherType 0x88CC
  up/down through a control device, with the entire protocol engine in Rust
  user mode.
- Costs: Windows kernel driver development (C or Rust via `windows-drivers-rs`),
  an EV code-signing certificate, Partner Center attestation signing for
  Windows 10/11, HLK testing for Windows Server, HVCI/Memory Integrity
  compliant code, Smart App Control/WDAC policy entries, and an ongoing
  obligation to re-test on every Windows feature update.
- Risk: a kernel bug is a BSOD on every managed workstation.
- Deployment: driver packages can be delivered by Intune, but the signing
  and policy burden is on us.
- Recommendation: do not build this in v1. Keep the packet I/O trait narrow
  enough that an LWF backend can be added later if Npcap licensing or
  policy becomes unacceptable.

Sources: Microsoft Learn
[Roadmap for Developing NDIS Filter Drivers](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/roadmap-for-developing-ndis-filter-drivers)
and the Q&A on
[LWF blocked by Smart App Control](https://learn.microsoft.com/en-us/answers/questions/5563902/ndis-lightweight-filter-driver-is-blocked-by-smart).

### 2.3 Windows Filtering Platform (WFP)

- WFP has MAC-frame layers (`FWPM_LAYER_INBOUND/OUTBOUND_MAC_FRAME_ETHERNET`,
  Windows 8+). A user-mode program can add *filters* at these layers, but
  frame *inspection* and *injection* (`FwpsInjectMacReceiveAsync0`,
  `FwpsInjectMacSendAsync0`) are callout-driver APIs, i.e. kernel mode.
- Conclusion: WFP does not give user mode raw Ethernet receive or transmit.
  Using WFP would mean writing a kernel callout driver, which has all the
  costs of 2.2 with a less suitable API. Rejected.

Sources: Microsoft Learn
[Using Layer 2 Filtering](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-layer-2-filtering),
[Management filtering layer identifiers](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/management-filtering-layer-identifiers).

### 2.4 Native Microsoft LLDP (MsLldp)

What is documented:

- `mslldp.sys` is a kernel-mode NDIS protocol driver, service name `MsLldp`,
  startup Automatic, bound to Ethernet adapters as component `ms_lldp`
  ("Microsoft LLDP Protocol Driver" in adapter bindings).
- The only documented management surface is the `NetLldpAgent` PowerShell
  module with three cmdlets: `Get-NetLldpAgent`, `Enable-NetLldpAgent`,
  `Disable-NetLldpAgent`. They enable/disable the agent per adapter and per
  address scope (nearest bridge, nearest non-TPMR bridge, nearest customer
  bridge). Microsoft states the module requires the DataCenterBridging
  feature.
- There is **no documented API** to read received neighbors, add custom
  TLVs, or change transmitted content. A community finding suggests a
  `ChassisId` registry value under the service's Parameters key, but it is
  unofficial and reportedly ineffective.

What is widely reported but undocumented (**lab**):

- Windows 10 1809+ and Windows 11 transmit LLDP on Ethernet adapters by
  default, with Chassis ID = adapter MAC. Switch neighbor tables commonly
  show Windows hosts without any configuration.
- The agent does not expose received neighbor data anywhere; Microsoft's
  own use is Datacenter Bridging / DCBX negotiation.

Answers to the Section 6.3 questions:

1. Does Windows already transmit LLDP? Reportedly yes by default; confirm
   in lab with Wireshark on a clean Windows 11 image.
2. Does Windows expose received neighbor data? No documented interface.
3. Is there a documented receive API? No.
4. Can custom TLVs be configured? No.
5. Can MsLldp coexist with this agent? Yes at the NDIS level: MsLldp is a
   protocol driver, Npcap is a filter below it, both see inbound frames.
6. Can duplicate advertisements occur? Yes. Two agents on one port produce
   two distinct neighbors (different Chassis IDs) on the switch, which
   confuses inventory and can trip per-port neighbor limits.
7. Must native LLDP be disabled when this agent transmits? Yes, on
   adapters where this agent is in `tx` or `rx_tx` mode. Mechanism:
   `Disable-NetAdapterBinding -ComponentID ms_lldp` per adapter (the
   service can do this itself with the same NetAdapter CIM class, or the
   installer can do it policy-wide). Do not stop the `MsLldp` service
   globally; it is a boot-start kernel driver and other features may bind
   to it. Record the original binding state so uninstall can restore it.

Sources: Microsoft Learn
[NetLldpAgent module](https://learn.microsoft.com/en-us/powershell/module/netlldpagent/?view=windowsserver2025-ps),
[Enable-NetLldpAgent](https://learn.microsoft.com/en-us/powershell/module/netlldpagent/enable-netlldpagent?view=windowsserver2025-ps),
Microsoft Q&A
[How to Configure Microsoft LLDP Protocol Driver](https://learn.microsoft.com/en-au/answers/questions/378477/how-to-configure-microsoft-lldp-protocol-driver?page=0).

## 3. Comparison

| Capability | Npcap | Custom NDIS LWF | Native Windows (MsLldp) | WFP |
| --- | --- | --- | --- | --- |
| Receive LLDP | Yes | Yes | No exposed data | Kernel callout only |
| Transmit LLDP | Yes | Yes | Yes, fixed content | Kernel callout only |
| Custom TLVs | Yes | Yes | No | n/a |
| Driver required | Third-party, signed | Our own, must sign | Built in | Our own callout |
| ARM64 | Yes (1.50+) | Must build and sign | Yes | Must build and sign |
| Service integration | Yes; identity constrained by Admin-only mode | Yes | n/a | Yes |
| Enterprise deployment | OEM license or prerequisite package; WDAC allow entry for Npcap | EV cert, attestation, HLK, WDAC | Nothing | Same as LWF |
| Maintenance | External | Ours, per Windows release | None | Ours |

## 4. Recommendation

Use **Npcap** as the v1 packet I/O backend, behind a `PacketIo` trait in
the `lldp-windows` crate with roughly this surface:

- `enumerate() -> Vec<AdapterHandle>` correlated to Windows interface
  GUID/LUID/IfIndex.
- `open(adapter, filter: EtherType) -> Channel` with bounded receive
  queue.
- `Channel::recv() -> Frame` (async), `Channel::send(&[u8])`.
- Hot-plug notification is *not* the backend's job; interface lifecycle
  comes from `NotifyIpInterfaceChange` / `NotifyUnicastIpAddressChange` and
  the backend is asked to re-open channels.

Keep a `mock` backend for tests and a reserved `lwf` backend for a future
first-party driver.

## 5. Service identity

- Npcap in default mode: device ACL permits authenticated users; a virtual
  service account (`NT SERVICE\WinLLDP`) or `LocalService` should work
  (**lab**).
- Npcap in Admin-only mode (common in hardened enterprises): only SYSTEM and
  built-in Administrators. The service then needs `LocalSystem`, mitigated by
  `SERVICE_SID_TYPE_RESTRICTED`, a `RequiredPrivileges` list that strips
  everything but `SeChangeNotifyPrivilege`, and no network listeners.
- Recommendation: support both. Default install uses `LocalSystem` with
  restricted privileges, because it works in every Npcap mode. Document a
  hardening path to a virtual service account when Admin-only mode is off.

## 6. Interface discovery and events

Documented APIs, all user mode, all in `windows-rs`:

- `GetAdaptersAddresses` (IP Helper): GUID, LUID, IfIndex, friendly name,
  description, MAC, operational status, link speed, IPv4/IPv6 unicast
  addresses with `PrefixOrigin`/`SuffixOrigin` (identifies temporary IPv6
  addresses), `IfType`, `TunnelType`.
- `NotifyIpInterfaceChange`, `NotifyUnicastIpAddressChange`,
  `NotifyNetworkConnectivityHint`: event-driven, no polling.
- `GetIfEntry2` / `GetIfTable2`: `MediaConnectState`, `PhysicalMediumType`,
  `ConnectorPresent`, `InterfaceAndOperStatusFlags.HardwareInterface`.
  These distinguish physical Ethernet from Hyper-V vEthernet, VPN, loopback.
- Docking/USB: appears as adapter arrival; no special API needed.
- Renames: friendly name is not stable; key everything on LUID/GUID.

## 7. Known limitations and gotchas

- **NIC firmware LLDP agents.** Intel X710/E810 and similar adapters can
  run LLDP in firmware ("FW-LLDP"). When enabled, the firmware consumes
  inbound LLDP frames and the OS never sees them. Detect by "transmit works,
  receive never does" and document the UEFI/driver setting to disable it.
- **Hyper-V external vSwitch.** When a physical NIC is bound to a vSwitch,
  the host talks through a `vEthernet` adapter. Whether LLDP multicast
  reaches the host vNIC is **lab**; the default config excludes `vEthernet*`.
- **Wi-Fi.** 802.11 adapters do not carry LLDP to an access point in any
  interoperable way. Default off.
- **802.1X.** Switches generally allow LLDP before authentication, but
  neighbor discovery timing on port auth is switch-dependent.
- **Sleep/resume.** Timers must be re-based on resume; treat resume as
  link-down/link-up for fast-start purposes.
- **MsLldp duplicate neighbor.** See 2.4 item 7.
- **WDAC / App Control.** Both our binaries and `npcap.sys`/`wpcap.dll`
  need allow entries in enforced policies.
