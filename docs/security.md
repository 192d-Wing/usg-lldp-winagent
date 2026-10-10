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

Each control below is implemented in the code named in parentheses. The
audit of 2026-10-10 (docs/security-audit-2026-10-10.md) found several
controls this document described that did not exist; they are implemented
now, and this section was rewritten to match the code.

### Parser
- `lldp-codec` is `#![forbid(unsafe_code)]`, reads every octet through a
  bounds-checked slice access, and never allocates in proportion to an
  attacker-controlled length field beyond the frame itself. The LLDPDU is
  capped at 9216 octets (`MAX_LLDPDU_LEN`); the Npcap snaplen is 9300.
- All integer arithmetic on lengths uses checked or saturating operations;
  `arithmetic_side_effects`, `indexing_slicing`, `unwrap_used`,
  `expect_used`, and `panic` are denied workspace-wide.
- Fuzzed with `cargo-fuzz` (libFuzzer) on the LLDPDU decoder, TLV parser,
  org-TLV parser, Ethernet frame parser, and YAML config parser (`fuzz/`).
  CI runs each target for 120 s on every PR from committed seeds.
- The decoder returns structured errors; the port task counts them and
  never panics on input. `panic = "abort"` in release so any surviving
  panic is a crash with a dump, not silent corruption.
- Neighbor text (system name, port description, IDs) is rendered through
  `lossy_text`, which falls back to hex when the value is not UTF-8 or
  contains a control character, so a hostile neighbor cannot inject
  terminal escape sequences through the CLI.

### Resource limits
- Per-port receive queue bounded (64 frames, `lldp-windows::npcap`).
  Overflow is counted and dropped.
- Neighbor table bounded per port (`lldp.max_neighbors_per_interface`,
  default 8, max 64). Overflow follows 802.1AB "too many neighbors": new
  MSAPs are discarded and `lldpStatsRxPortFramesDiscardedTotal` increments.
  There is no separate global cap; the global bound is ports times the
  per-port limit.
- Each stored neighbor keeps at most 64 optional TLVs and 4 KiB of
  organizationally specific and unknown TLV data
  (`lldp-core::neighbor::bound_retained`). This bounds the heap per neighbor
  and the size of IPC responses that list neighbors.
- Event Log sink is token-bucket rate limited (default 60 events/minute,
  `logging.event_rate_limit_per_minute`) with a summary event when
  suppression occurs.

### Service hardening
- LocalSystem with the unrestricted service SID type and
  `RequiredPrivileges` = `SeChangeNotifyPrivilege` only, applied by the MSI
  and by `winlldp-service.exe harden`. The restricted SID type was tried
  and does not work with Npcap's Admin-only mode (decision I2).
- At start, under the SCM, the service lists the privileges in its token
  and refuses to run if any beyond `SeChangeNotifyPrivilege` is present
  (Event ID 1006, `lldp-windows::secinfo`). In console mode the surplus is
  only reported, since an elevated administrator's token has many.
- The configuration file is loaded only if no principal other than
  SYSTEM, Administrators, and TrustedInstaller can modify it: the owner
  must be one of those and no allow ACE may grant write, append, delete,
  `WRITE_DAC`, or `WRITE_OWNER` to anyone else. Otherwise the file is
  treated like an invalid one: every interface stays disabled and Event ID
  1005 names the SID and access mask. The same check on the service
  executable is reported (Event ID 1007) but not fatal.
- The MSI sets a protected DACL on `%ProgramData%\WinLLDP` (SYSTEM and
  Administrators full control, Users read and execute, inherited) so the
  default `%ProgramData%` ACL, which lets Users create files there, does
  not apply. Binaries live under `%ProgramFiles%\WinLLDP`.
- No network sockets of any kind. The only listener is the named pipe.
- `wpcap.dll` is loaded from `%SystemRoot%\System32\Npcap` by absolute
  path, never by search order, with `LOAD_WITH_ALTERED_SEARCH_PATH` and
  `SetDllDirectoryW` pointed at that directory so `Packet.dll` resolves
  from there too.
- Npcap device access is not escalated: the service uses whatever Npcap
  mode the organization installed.
- MsLldp binding control runs Windows PowerShell 5.1 by absolute path with
  `-NoProfile -NonInteractive` and a fixed command line into which only an
  adapter GUID is interpolated, after it has been checked to be 36
  hexadecimal digits and hyphens (`lldp-windows::mslldp`).
- Release binaries are built with Control Flow Guard (`.cargo/config.toml`)
  on top of the DEP, ASLR, and high-entropy VA that Rust's MSVC targets
  enable by default. CI reads the PE header and fails if any of the four
  flags is missing.

### IPC
- Named pipe with an explicit security descriptor and
  `PIPE_REJECT_REMOTE_CLIENTS`. SYSTEM and Administrators have full
  control; the read group (`ipc.read_group`, default Authenticated Users)
  has `0x12019B`: generic read plus write data, attributes, and EA. That
  excludes `FILE_CREATE_PIPE_INSTANCE`, so a member of the read group
  cannot create instances of the pipe and impersonate the service to other
  clients. The first instance uses `FILE_FLAG_FIRST_PIPE_INSTANCE`.
- `ipc.read_group` must be a SID string or a two-letter SDDL alias; the
  configuration validator rejects anything else before it reaches the
  security descriptor.
- Read operations: the read group. Mutating operations: the client's token
  is impersonated at identification level and checked for an enabled
  Administrators group (elevated), once per connection.
- The CLI opens the pipe with `SECURITY_IDENTIFICATION`, so a process that
  squats the name cannot obtain an impersonation-level token for the
  administrator running the CLI.
- Strict JSON schema validation; unknown fields rejected; requests at most
  64 KiB, responses at most 8 MiB; at most 32 concurrent clients; idle
  connections closed after 30 s.
- Protocol version negotiated; unknown versions rejected.

### Privacy
Config toggles, all honored by the encoder: `lldp.advertise.system_name`
and `system_name_fqdn`, `system_description`, `os_version`, `hardware`
(default off), `port_description` and `adapter_description`,
`management_address` with the `management_addresses` selection rules
(temporary and link-local addresses excluded by default). LLDP-MED
inventory is not transmitted. Registry policy under
`HKLM\SOFTWARE\Policies\WinLLDP` can force the main toggles off.

### Supply chain
- `cargo deny` (licenses, advisories, yanked crates, unknown registries and
  git sources) runs in CI; `Cargo.lock` is committed and release builds use
  `--locked`.
- Every GitHub Action is pinned to a commit SHA, including the toolchain
  installer; `cargo install` of build tools (cargo-fuzz, cargo-cyclonedx)
  and PowerShell modules name exact versions. Workflow permissions are the
  minimum per job.
- Release builds run from a tagged commit in GitHub Actions on
  `windows-latest`; executables, PowerShell module files, and the MSI are
  signed with Azure Trusted Signing, and a SLSA build provenance
  attestation is published for the MSI and SBOM
  (`gh attestation verify`).
- SBOM (CycloneDX via `cargo-cyclonedx`) attached to each release.
- Npcap is not redistributed; its integrity is the organization's
  deployment pipeline's responsibility. The service logs the Npcap version
  string at startup (Event ID 1101).

### What LLDP data is never used for
Routing, DNS, IP configuration, VLAN assignment, firewall rules, 802.1X
or any authentication decision. The agent has no code path that writes
network configuration from received data.
