# Security Audit, 2026-10-10

Scope: every crate in the workspace, both executables, the MSI, the
PowerShell module, the CI and release workflows, and `docs/security.md`.
Method: manual review of the whole source against the threat model in
docs/security.md, with `cargo audit` and `cargo deny` for dependencies.
The reviewer had no lab access; everything below was verified by reading
code and by the unit and integration tests, not against a switch.

Baseline before changes: clippy clean under `-D warnings`, all tests
passing, `cargo audit` reporting no advisories for the 65 locked crates.

## Findings

Severity is relative to this agent's threat model: an unauthenticated
sender on the same segment, and a standard (non-administrator) local user.

| # | Severity | Finding | Status |
| --- | --- | --- | --- |
| 1 | High | Documented controls did not exist: the service did not verify its token privileges, did not check the configuration file ACL, and the installer did not set an ACL on `%ProgramData%\WinLLDP`. docs/security.md also described a restricted service SID (changed to unrestricted in decision I2), a global neighbor cap, a per-neighbor TLV cap, `cargo audit` in CI, and logging of the `npcap.sys` signer, none of which were implemented. | Fixed: privilege check (Event 1006, fatal under the SCM), config ACL check (Event 1005, file not loaded), binary ACL check (Event 1007), MSI DACL on the configuration directory, TLV retention cap. docs/security.md rewritten to match the code. |
| 2 | High | Named pipe DACL granted the read group `GENERIC_WRITE`, which on a pipe includes `FILE_CREATE_PIPE_INSTANCE` (same bit as `FILE_APPEND_DATA`). Any authenticated local user could create further instances of `\\.\pipe\WinLLDP` and answer administrators' CLI requests with fabricated data, or hold instances open to starve real clients. Impersonation of the administrator was already prevented by tokio's default `SECURITY_IDENTIFICATION`. | Fixed: the read group gets `0x12019B` (generic read plus write data, attributes, EA); a test asserts the mask excludes instance creation. `SECURITY_IDENTIFICATION` is now explicit in the client. |
| 3 | Medium | Configuration file writable by a standard user was loaded without complaint. With the default `%ProgramData%` ACL a user cannot modify the installed file, but can on any machine where the directory ACL was loosened or the file was placed by hand, and the service then advertises and listens as that user chooses. | Fixed by finding 1: ACL check in the service and in the MSI. |
| 4 | Medium | IPC server allocated up to 1 MiB per request for any authenticated user, served unlimited concurrent connections, and never timed out an idle connection. A local user could hold hundreds of megabytes of service memory and tasks. | Fixed: requests capped at 64 KiB before allocation, 32 concurrent clients, 30 s idle timeout. |
| 5 | Medium | A neighbor's whole LLDPDU was retained verbatim. A 9216-octet frame of two-octet TLVs becomes thousands of heap allocations per neighbor, and the JSON for `ListNeighbors` could exceed the 1 MiB message limit, at which point the CLI and PowerShell module failed for every user until the hostile neighbor aged out. | Fixed: 64 optional TLVs and 4 KiB of organizational and unknown TLV data retained per neighbor; response limit raised to 8 MiB while requests are capped separately. |
| 6 | Medium | Supply chain: all GitHub Actions were referenced by moving tags, the toolchain installer by a branch (`dtolnay/rust-toolchain@master`), and `cargo install` of cargo-fuzz and cargo-cyclonedx, and `Install-Module` of Pester and PSScriptAnalyzer, took whatever was latest at build time. The release workflow granted `contents: write` to the build job as well as the release job. | Fixed: every action pinned to a commit SHA with the version in a comment; tool and module versions pinned; permissions scoped per job; SLSA build provenance attested for the MSI and SBOM. |
| 7 | Low | `ipc.read_group` was interpolated into the pipe SDDL unvalidated. The value is administrator-controlled, so this is a robustness issue (a group name silently disabled IPC at start) rather than an injection. | Fixed: validator accepts a SID string or a two-letter SDDL alias only. |
| 8 | Low | `lldp.management_addresses.pinned` entries that did not parse were silently dropped, so a typo removed the management address without any error. | Fixed: validation error naming the entry. |
| 9 | Low | Release binaries were built without Control Flow Guard. DEP, ASLR, and high-entropy VA were already on by default. | Fixed: `-C control-flow-guard` for both MSVC targets in `.cargo/config.toml`; CI reads the PE header and fails if any mitigation flag is missing. |
| 10 | Info | `mslldp.rs` runs Windows PowerShell with `-ExecutionPolicy Bypass`. Execution policy does not apply to `-Command` strings, so the flag is inert, but it stands out in an audit. The GUID is validated before interpolation and the rest of the command line is fixed, so there is no injection. | Left as is; documented. |
| 11 | Info | `lossy_text` falls back to hex for control characters, which blocks terminal escape injection. Unicode format characters (bidirectional overrides, zero-width joiners) are not control characters and pass through; they can reorder display but cannot execute anything. | Left as is. |
| 12 | Info | Event source registration points `EventMessageFile` at the .NET Framework `EventLogMessages.dll`, a Microsoft file under `%SystemRoot%`. Not a hijack path. | No change. |

## Verified as sound

- `lldp-codec`: every read is bounds-checked, every length computation is
  checked or saturating, no `unsafe`, decoder stops at the first framing
  error and preserves earlier TLVs as the standard requires. Fuzz targets
  cover the decoder, TLV iterator, organizational TLVs, frame parser, and
  the YAML config.
- `lldp-windows::npcap`: `wpcap.dll` loaded by absolute path from the
  System32 Npcap directory; capture handle filtered to EtherType 0x88CC,
  inbound only, non-promiscuous; frames copied out of pcap's buffer within
  the snaplen; bounded queue to the port task.
- Pipe server: `PIPE_REJECT_REMOTE_CLIENTS`; first instance created with
  `FILE_FLAG_FIRST_PIPE_INSTANCE` so a squatted name fails the service
  rather than the clients; administrator check uses an identification
  token and `CheckTokenMembership`, so a filtered (non-elevated)
  administrator token is refused.
- Configuration failure is fail-closed: a missing, invalid, or (now)
  untrusted file leaves the service running with every interface disabled
  rather than falling back to defaults.
- No network sockets; no persistence of neighbor data; no code path that
  changes network configuration from received data.
- Registry policy is read from `HKLM\SOFTWARE\Policies\WinLLDP` only,
  which standard users cannot write.

## Not covered

- The signed release MSI, and the release workflow's provenance
  attestation, which run only on a tag. The `PermissionEx` SDDL on the
  configuration directory was checked later with the unsigned CI MSI (lab
  verification below).
- If a future deployment changes the service account,
  `REQUIRED_PRIVILEGES` in `apps/winlldp-service/src/main.rs` is the single
  list to update.
- Npcap itself, its driver, and its installer are out of scope.

## Lab verification, 2026-10-10

Run after the review on the lab workstation (Windows 11 x64, Cisco
C9200CX), with a build of this change, in the console and as the installed
service (the build copied over the installed executables, then restored).

| Check | Result |
| --- | --- |
| Privilege check under the SCM | pass: registration `SeChangeNotifyPrivilege`, unrestricted SID; the service started, no event 1006, 1005, or 1007, neighbor discovered |
| Configuration ACL | pass: the MSI-installed file loads; after granting Users modify, a reload logged event 1005 naming `S-1-5-32-545` and kept the previous configuration; a file in a user's checkout is refused at start and every interface stays disabled |
| Pipe access for a non-elevated client | pass with a filtered token (Administrators deny-only): `winlldp neighbors` and the PowerShell module both read; `config reload` answered `Forbidden`; creating another instance of `\\.\pipe\WinLLDP` was refused with access denied |
| IPC limits | pass: with 40 idle connections open a further client was closed without a response; all 40 were closed after 30 s and the CLI worked again. A 70000-octet length prefix closed the connection |

Observed and left as is:

- A member of the read group who holds 32 idle connections and reopens
  them every 30 s keeps other clients out of the IPC. LLDP operation is not
  affected. Before this change the same user could exhaust memory instead.
- The `BadRequest` response to an oversized request did not reach the
  client; it saw the connection close. The request is refused either way.
- `--console` applies the same configuration ACL check as the service, so
  a development run needs the file in a directory only administrators can
  write (CLAUDE.md, lab workflow).

After the merge, the unsigned MSI built by CI from `main` (42588c9) was
installed over the existing installation on the same workstation:

| Check | Result |
| --- | --- |
| `PermissionEx` DACL on `%ProgramData%\WinLLDP` | pass: protected, SYSTEM and Administrators full control, Users read and execute, inherited by `config.yaml`; the inherited Users create-files entry from `%ProgramData%` is gone, and a non-elevated process could not create a file in the directory |
| Service after the upgrade | pass: running, unrestricted SID, `SeChangeNotifyPrivilege` only, configuration loaded, neighbor discovered, no event 1005, 1006, or 1007 |
| Control Flow Guard in the installed executables | pass: `DllCharacteristics` 0xC160 on both |
| Non-elevated client against the installed service | pass: `winlldp neighbors` read the neighbor |
