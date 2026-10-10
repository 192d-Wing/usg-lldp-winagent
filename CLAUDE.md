# WinLLDP: notes for Claude Code sessions

Read PLAN.MD for the full specification and docs/decisions.md for the
architectural decisions already made (do not reopen them).

## State of the project
- Phases 1 through 5 and Phase 7 packaging are implemented and pass CI.
- Phase 6 (lab validation) is in progress. The checklist is
  docs/standards-compliance.md section 5; record results there. Console
  mode, the installed service, cable pull, USB NIC, and Modern Standby
  have run against the Cisco switch. Still to do: the MSI.
- The service SID type is unrestricted, not restricted; see the lab result
  under decision I2 in docs/decisions.md before changing it.

## Conventions
- Rust 1.99, edition 2024, MSRV pinned in rust-toolchain.toml.
- Workspace lints: unsafe denied (allowed only in crates/lldp-windows FFI
  modules with a SAFETY comment), indexing/unwrap/panic/unchecked arithmetic
  denied, clippy pedantic. CI runs with RUSTFLAGS=-D warnings.
- Conventional commits (feat, fix, docs, build, ci, test, refactor).
- Before committing: cargo fmt --all --check, cargo clippy --workspace
  --all-targets, cargo test --workspace; on non-Windows also
  cargo clippy --workspace --all-targets --target x86_64-pc-windows-msvc.
- Clause numbers and receive rules marked `verify` must be checked against
  IEEE 802.1AB-2016 before being treated as confirmed.
- examples/config.yaml must equal Config::default(); a test enforces it.

## Lab workflow on Windows
1. Install Npcap 1.50+, Rust 1.99 with the MSVC toolchain, and Wireshark.
2. cargo build --release -p winlldp-service -p winlldp-cli
3. Foreground run (elevated): target\release\winlldp-service.exe --console
   --config examples\config.yaml
4. In another elevated prompt: target\release\winlldp.exe diagnostics,
   interfaces, neighbors --detail, local, statistics.
5. Service install for real: winlldp-service.exe install --config
   C:\ProgramData\WinLLDP\config.yaml (copy examples\config.yaml there first),
   or install the CI MSI artifact.
6. Capture with Wireshark filter `lldp` and compare against
   docs/troubleshooting.md "Expected from WinLLDP".
7. On the Cisco switch: show lldp neighbors detail.
