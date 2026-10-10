# Architecture Decisions (Phase 1 interview)

Each item: options, recommendation, tradeoffs, governing requirement.
"Decision:" lines record the owner's answer. Decided 2026-10-09.
Sections A-H: the owner accepted the recommendations as written.

## A. Packet access

### A1. Npcap or custom NDIS LWF?
- Options: Npcap OEM (bundled); Npcap as prerequisite; custom LWF.
- Recommendation: Npcap, behind a `PacketIo` trait. See docs/windows-networking.md section 4.
- Tradeoffs: Npcap costs a license or a prerequisite dependency and adds a third-party driver to the WDAC policy. A custom LWF costs EV signing, attestation, HLK, and kernel risk.
- Requirement: Windows has no user-mode raw Ethernet API; something kernel-side is unavoidable.
- Decision: accepted recommendation.

### A2. Must it work without third-party drivers?
- Options: yes (forces custom LWF); no.
- Recommendation: no for v1. Reserve the trait for a future LWF.
- Decision: accepted recommendation.

### A3. Admin during install acceptable?
- Recommendation: yes. Service registration and driver install require it; Intune/MECM run as SYSTEM.
- Decision: accepted recommendation.

### A4. HVCI / Credential Guard support required?
- Recommendation: yes, treat as mandatory. Npcap is HVCI-compatible. Any future LWF must be too.
- Decision: accepted recommendation.

## B. Windows LLDP integration

### B1. Replace MsLldp transmission?
- Recommendation: yes on adapters we transmit on. Unbind `ms_lldp` per adapter, record the prior state, restore on uninstall.
- Decision: accepted recommendation.

### B2. Coexist with MsLldp?
- Recommendation: coexist in `rx` mode (leave MsLldp bound, we only listen); replace in `tx`/`rx_tx` mode.
- Decision: accepted recommendation.

### B3. Preventing duplicate advertisements?
- Options: unbind `ms_lldp` per adapter; `Disable-NetLldpAgent` (needs DataCenterBridging feature, may not exist on client SKUs); stop the MsLldp service globally.
- Recommendation: per-adapter unbind. It is documented, scriptable, reversible, and does not touch a boot-start driver.
- Decision: accepted recommendation.

## C. Workstation identity

### C1. Chassis ID: MAC or stable custom identifier?
- Options: MAC of the transmitting adapter (subtype 4), locally assigned (subtype 7) using a stable machine identifier, network address (subtype 5).
- Recommendation: locally assigned, value = computer hostname by default, with a config option to use the SMBIOS system UUID or a custom string. A docked laptop that advertises its dock's MAC as Chassis ID is a different "chassis" every dock. Switches display locally assigned IDs as text, which is what network teams want to see.
- Requirement: 802.1AB Chassis ID must be constant for the lifetime of the agent and identical across all its ports.
- Decision: accepted recommendation.

### C2. Advertise FQDN?
- Recommendation: System Name = FQDN when domain-joined, short hostname otherwise, with a config override. Make it a privacy toggle.
- Decision: accepted recommendation.

### C3. Advertise OS and hardware inventory?
- Recommendation: System Description = "Microsoft Windows 11 Enterprise 24H2 (x64)" style string, with manufacturer/model off by default. LLDP-MED Inventory TLVs off by default.
- Decision: accepted recommendation.

### C4. Port ID: MAC or interface alias?
- Recommendation: MAC address (subtype 3). Aliases are user-renamable and non-unique across machines; a switch port shows exactly one neighbor anyway, and the MAC is what the switch's MAC table and 802.1X session already show. Offer interface name (subtype 5) as a config option. Port Description carries the alias and adapter description.
- Decision: accepted recommendation.

## D. Network interfaces

### D1. Wi-Fi?
- Recommendation: no. Decode-only if a frame arrives, never transmit. Excluded by default.
- Decision: accepted recommendation.

### D2. Hyper-V virtual interfaces?
- Recommendation: no by default. Allow opt-in for `vEthernet` adapters bound to an external vSwitch after lab validation.
- Decision: accepted recommendation.

### D3. Enable all physical Ethernet automatically?
- Recommendation: yes, `rx_tx` on adapters where `HardwareInterface` is true and medium is 802.3, subject to the exclusion list.
- Decision: accepted recommendation.

### D4. USB Ethernet and docks?
- Recommendation: treat as ordinary physical Ethernet. Because Chassis ID is not MAC-based (C1), the dock's MAC only affects Port ID, which is correct behavior.
- Decision: accepted recommendation.

## E. LLDP extensions

### E1. Base 802.1AB sufficient initially?
- Recommendation: yes for transmit. Decode 802.1, 802.3, and LLDP-MED on receive from day one because that is where the useful switch-side data lives (PVID, link speed, PoE, voice VLAN).
- Decision: accepted recommendation.

### E2. LLDP-MED required?
- Recommendation: decode yes, transmit no (off by default). Only enable if the network team wants workstations in the MED inventory.
- Decision: accepted recommendation.

### E3. 802.1 VLAN TLVs required?
- Recommendation: decode only. A workstation has nothing meaningful to advertise.
- Decision: accepted recommendation.

### E4. Decode vendor-specific TLVs?
- Recommendation: generic decode (OUI, subtype, hex) for all; named decoders for Cisco (00-00-0C) and Juniper (00-90-69) if lab captures show value. Unknown TLVs are preserved and displayed as hex.
- Decision: accepted recommendation.

## F. Management

### F1. Which local group gets read-only IPC access?
- Options: Everyone/Authenticated Users; BUILTIN\Users; a dedicated local group created by the installer; Administrators only.
- Recommendation: Authenticated Users for read operations, Administrators for mutating operations. Neighbor data is already visible to anyone with Wireshark on the box.
- Decision: accepted recommendation.

### F2. Non-admin users query neighbors?
- Recommendation: yes (follows from F1).
- Decision: accepted recommendation.

### F3. Centralized configuration required?
- Options: YAML file only, deployed by Intune/MECM; registry overrides (ADMX/Intune OMA-URI); both.
- Recommendation: YAML as the source of truth, plus a small set of registry overrides under `HKLM\SOFTWARE\Policies\WinLLDP` for the handful of settings an Intune admin would want to flip without redeploying a file (enabled, mode, privacy toggles). Policy wins over file.
- Decision: accepted recommendation.

### F4. PowerShell 5.1 support?
- Recommendation: yes. Windows PowerShell 5.1 is still the default shell on every supported SKU and what MECM/Intune scripts run under.
- Decision: accepted recommendation.

### F5. Publish the module to an internal repository?
- Recommendation: ship in MSI; additionally publish to an internal PSResource repository if one exists. Not required for v1.
- Decision: accepted recommendation.

## G. Deployment

### G1. Intune, MECM, or other?
- Recommendation: build for both. MSI as Intune LOB app or Win32 app (.intunewin) and as an MECM application with MSI detection.
- Decision: accepted recommendation.

### G2. Silent install/upgrade required?
- Recommendation: yes, `msiexec /i WinLLDP.msi /qn`, major-upgrade semantics, config preserved.
- Decision: accepted recommendation.

### G3. Signed binaries and drivers required?
- Recommendation: yes. Sign `winlldp-service.exe`, `winlldp.exe`, the MSI, and the PowerShell module files (Authenticode on .psm1/.psd1 for AllSigned policies). Npcap is already signed. Decide on certificate source: organizational EV cert or Azure Trusted Signing.
- Decision: accepted recommendation.

## H. Operational requirements

### H1. IPv6-only networks?
- Recommendation: yes. LLDP itself is L2; IPv6-only only affects Management Address selection, which must prefer GUA, then ULA, and never advertise link-local by default.
- Decision: accepted recommendation.

### H2. Per-interface advertisement settings?
- Recommendation: yes. Global defaults with per-interface overrides keyed by alias glob or GUID.
- Decision: accepted recommendation.

### H3. Store historical neighbors?
- Recommendation: no persistence in v1. Keep a "last known neighbor" per interface in memory after expiry, clearly marked stale, for troubleshooting. Persistence to disk is a later feature.
- Decision: accepted recommendation.

### H4. DoD STIG / hardening?
- Recommendation: assume yes given the `.mil` example. Implications: WDAC allow-listing, no inbound network listeners, FIPS-irrelevant (no crypto), Event Log integration, signed everything, documented service privileges.
- Decision: accepted recommendation.

### H5. Future Linux implementation?
- Recommendation: plan for it structurally (core/codec crates are OS-free) but do not build it. Note that lldpd already serves Linux well.
- Decision: accepted recommendation.

## I. Additional questions not in the original plan

### I1. Npcap licensing path
- Options: buy Npcap OEM Redistribution and bundle; require Npcap as a prerequisite deployed separately; use the free edition only for development and defer.
- Recommendation: decide before Phase 3. Bundling via OEM gives one package and version control.
- Decision: **Npcap is a separately deployed prerequisite.** The MSI does not bundle Npcap. The installer and the service check for Npcap at runtime and report a clear error if it is missing or too old.

### I2. Service identity
- Options: LocalSystem with restricted privileges; virtual service account.
- Recommendation: LocalSystem + restricted service SID + minimal privilege list in v1, because it works under Npcap Admin-only mode. Revisit after lab test.
- Decision: **LocalSystem with restricted SID and minimal privileges in v1.**
- Lab result 2026-10-09: the restricted SID type does not work. Its
  write-restricted token is not an administrator to Npcap's Admin-only mode
  (the adapter open fails asking for the elevation helper), and the service
  is denied further instances of its own pipe. The service now uses the
  unrestricted service SID type; LocalSystem and the single
  `SeChangeNotifyPrivilege` are unchanged and were confirmed in the token.

### I3. Code-signing certificate source
- Options: organizational EV certificate; Azure Trusted Signing.
- Decision: **Azure Trusted Signing.**

### I4. Fast-start on link up
- Recommendation: implement 802.1AB fast transmission (txFastInit = 4 frames at msgFastTx = 1 s) on link up, resume from sleep, and admin enable. Standard behavior, no decision needed unless objected to.
- Decision: no objection; implement.

### I5. Lab hardware for interoperability
- Need: at least one Cisco IOS-XE and one Juniper Junos switch, a Windows 11 x64 machine, a Windows on ARM device, a Server 2022/2025 VM, an Intel NIC with FW-LLDP capability if available.
- Decision: **One Cisco switch and one Windows 11 workstation.** Juniper, ARM64, and Server interoperability are deferred until hardware is available and are marked as untested in the compliance matrix.
