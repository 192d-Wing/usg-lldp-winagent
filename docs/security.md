# Security Model

## Threat model

LLDP is unauthenticated Layer 2 multicast. Anyone on the same segment can
send arbitrary LLDPDUs to the workstation. Threats considered:

1. Malformed frames aimed at the parser (memory safety, panics, resource
   exhaustion).
2. Neighbor table flooding (thousands of fake MSAPs).
3. Log flooding (rapid neighbor churn to fill the Event Log).
4. Information disclosure in our own advertisements (FQDN, OS version,
   hardware, management addresses).
5. Local privilege escalation through the service (IPC, config file,
   Npcap device access, service binary path).
6. Supply chain (Npcap, crates, build pipeline).

Out of scope: LLDP spoofing of the switch identity. LLDP data is displayed
as received and is never used to change system configuration. The CLI and
docs state that LLDP is not proof of switch identity.

## Controls

### Parser
- `lldp-codec` is `#![forbid(unsafe_code)]`, uses only slice indexing with
  explicit bounds checks, and never allocates proportional to attacker
  controlled length fields beyond the frame size (max 1500-octet LLDPDU
  from a standard frame; jumbo frames capped at 9216 octets at the backend).
- All integer arithmetic on lengths uses checked or saturating operations.
- Fuzzed with `cargo-fuzz` (libFuzzer) on the LLDPDU decoder, TLV parser,
  org-TLV parser, and YAML config parser. CI runs each target for a fixed
  budget on every PR; a corpus is committed.
- Decoder returns structured errors; the port task counts them and never
  panics on input. `panic = "abort"` in release so any surviving panic is
  a crash with a dump, not silent corruption.

### Resource limits
- Per-port receive queue bounded (64 frames). Overflow is counted and
  dropped.
- Neighbor table bounded per port (default 8, max 64) and globally
  (default 256). Overflow follows 802.1AB "too many neighbors": new MSAPs
  are discarded and `lldpStatsRxPortFramesDiscardedTotal` increments.
- Unknown/organizational TLVs retained per neighbor are capped (default 32
  TLVs, 2 KiB total) to bound memory per neighbor.
- Event Log sink is token-bucket rate limited (default 60 events/minute)
  with a summary event when suppression occurs.

### Service hardening
- LocalSystem with `SERVICE_SID_TYPE_RESTRICTED`.
- `RequiredPrivileges` = `SeChangeNotifyPrivilege` only. Verified at
  startup: the service logs and refuses to run if it finds itself with
  unexpected privileges enabled (defense against misconfiguration).
- Binary and config directories under `%ProgramFiles%\WinLLDP` and
  `%ProgramData%\WinLLDP` with explicit ACLs set by the installer; the
  service verifies the config file is not writable by non-administrators
  and refuses to load it otherwise.
- No network sockets of any kind. The only listener is the named pipe.
- No dynamic loading except `wpcap.dll` from the Npcap system directory by
  absolute path (prevents DLL search-order hijacking).
- Npcap device access is not escalated: the service uses whatever Npcap
  mode the organization installed.

### IPC
- Named pipe with explicit security descriptor; `PIPE_REJECT_REMOTE_CLIENTS`.
- Read operations: Authenticated Users. Mutating operations: client token
  checked for Administrators membership per request.
- Strict JSON schema validation; unknown fields rejected; 1 MiB max message.
- Protocol version negotiated; unknown versions rejected.

### Privacy
Config toggles, all honored by the encoder:
`advertise.system_name.fqdn`, `advertise.system_description.os_version`,
`advertise.system_description.hardware`, `advertise.management_address`,
`advertise.port_description.adapter_description`, LLDP-MED inventory
(default off). Registry policy can force any of them off.

### Supply chain
- `cargo deny` for license and advisory checks, `cargo audit` in CI,
  `Cargo.lock` committed, dependencies pinned.
- Release builds are reproducible from a tagged commit in GitHub Actions
  on `windows-latest`; artifacts signed with Azure Trusted Signing.
- SBOM (CycloneDX via `cargo-cyclonedx`) attached to each release.
- Npcap is not redistributed; its integrity is the organization's
  deployment pipeline's responsibility. The service logs the Npcap
  version and `npcap.sys` signer at startup for audit.

### What LLDP data is never used for
Routing, DNS, IP configuration, VLAN assignment, firewall rules, 802.1X
or any authentication decision. The agent has no code path that writes
network configuration from received data.
