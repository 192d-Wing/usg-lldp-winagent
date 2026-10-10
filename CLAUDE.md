# WinLLDP: notes for Claude Code sessions

Read PLAN.MD for the full specification and docs/decisions.md for the
architectural decisions already made (do not reopen them).

## State of the project
- Phases 1 through 5 and Phase 7 packaging are implemented and pass CI.
- Phase 6 (lab validation): every row of the checklist in
  docs/standards-compliance.md section 5 has passed on one Windows 11 x64
  workstation against a Cisco C9200CX. That section also lists the open
  findings. Not covered: the signed release MSI, ARM64, Server, Juniper.
- The 802.1AB requirements were checked against IEEE Std 802.1AB-2016
  (docs/standards-compliance.md section 4.1, which also lists the deliberate
  differences), and the 802.1 and 802.3 TLV decoders against 802.1Q-2022
  Annex D and 802.3 Clause 79 (section 4.2). Still `verify`: the 802.1AX
  Link Aggregation TLV and LLDP-MED (TIA-1057); see ROADMAP.MD.
- The service SID type is unrestricted, not restricted; see the lab result
  under decision I2 in docs/decisions.md before changing it.
- Security audit 2026-10-10 (docs/security-audit-2026-10-10.md): the
  service now refuses to run under the SCM with privileges beyond
  REQUIRED_PRIVILEGES, refuses a config file non-administrators can
  modify, and the pipe DACL denies FILE_CREATE_PIPE_INSTANCE to the read
  group. docs/security.md describes only controls that exist in code;
  keep it that way.

## Conventions
- Rust 1.99, edition 2024, MSRV pinned in rust-toolchain.toml.
- Workspace lints: unsafe denied (allowed only in crates/lldp-windows FFI
  modules with a SAFETY comment), indexing/unwrap/panic/unchecked arithmetic
  denied, clippy pedantic. CI runs with RUSTFLAGS=-D warnings.
- Conventional commits (feat, fix, docs, build, ci, test, refactor).
- Before committing: cargo fmt --all --check, cargo clippy --workspace
  --all-targets, cargo test --workspace; on non-Windows also
  cargo clippy --workspace --all-targets --target x86_64-pc-windows-msvc.
- Anything marked `verify` must be checked against the published standard
  before being treated as confirmed. Where clause 9 of 802.1AB-2016 and its
  MIB disagree, clause 9 takes precedence (11.5.2).
- examples/config.yaml must equal Config::default(); a test enforces it.

## Lab workflow on Windows
1. Install Npcap 1.50+, Rust 1.99 with the MSVC toolchain, and Wireshark.
2. cargo build --release -p winlldp-service -p winlldp-cli
3. Foreground run (elevated): target\release\winlldp-service.exe --console
   --config C:\ProgramData\WinLLDP\config.yaml (copy examples\config.yaml
   there from an elevated prompt first). A file in the checkout is owned by
   the user, so the service refuses it with event 1005 and manages nothing.
   Event 1007 about the executable under target\ is expected in this mode.
4. In another elevated prompt: target\release\winlldp.exe diagnostics,
   interfaces, neighbors --detail, local, statistics.
5. Service install for real: winlldp-service.exe install --config
   C:\ProgramData\WinLLDP\config.yaml (copy examples\config.yaml there first),
   or install the CI MSI artifact.
6. Capture with Wireshark filter `lldp` and compare against
   docs/troubleshooting.md "Expected from WinLLDP".
7. On the Cisco switch: show lldp neighbors detail.
