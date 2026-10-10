# Configuration

File: `%ProgramData%\WinLLDP\config.yaml`. Schema version 1. Every setting
is optional except `version`; `examples/config.yaml` documents the
defaults and a test keeps that file equal to them. Unknown keys are
rejected with the key name. Validate with `winlldp config validate` or
`Test-WinLldpConfiguration`; reload with `winlldp config reload`.

Registry policy (`HKLM\SOFTWARE\Policies\WinLLDP`, see docs/deployment.md)
overrides the file.

## `agent`

| Key | Default | Meaning |
| --- | --- | --- |
| `enabled` | `true` | Master switch. `false` keeps the service running with every interface disabled. |

## `lldp`

| Key | Default | IEEE name and range |
| --- | --- | --- |
| `transmit_interval` | 30 | `msgTxInterval`, 5 to 32768 s |
| `hold_multiplier` | 4 | `msgTxHold`, 2 to 10. TTL = interval x hold + 1 (121 by default). |
| `fast_tx_interval` | 1 | `msgFastTx`, 1 to 3600 s |
| `fast_tx_count` | 4 | `txFastInit`, 1 to 8 |
| `tx_credit_max` | 5 | `txCreditMax`, 1 to 100 |
| `reinit_delay` | 2 | `reinitDelay`, 1 to 10 s |
| `max_neighbors_per_interface` | 8 | 1 to 64 |
| `chassis_id.source` | `hostname` | `hostname`, `smbios_uuid`, `custom` (locally assigned subtype); `mac` (MAC subtype; changes when docking) |
| `chassis_id.value` | | Required with `custom`, 1 to 255 bytes |
| `port_id` | `mac` | `mac` (MAC subtype) or `interface_name` (alias) |
| `system_name_override` | | Replaces the computed System Name |
| `system_description_override` | | Replaces the computed System Description |

### `lldp.advertise`

| Key | Default | TLV effect |
| --- | --- | --- |
| `port_description` | `true` | Port Description TLV |
| `adapter_description` | `true` | Port Description is `Alias (Adapter description)`; `false` sends the alias only |
| `system_name` | `true` | System Name TLV |
| `system_name_fqdn` | `true` | Use the DNS FQDN when domain-joined; `false` sends the short name |
| `system_description` | `true` | System Description TLV |
| `os_version` | `true` | Append version, build, and architecture |
| `hardware` | `false` | Append manufacturer and model from SMBIOS |
| `system_capabilities` | `true` | System Capabilities TLV with Station Only |
| `bridge_capability` | `false` | Also set Bridge when a Hyper-V vSwitch or network bridge exists |
| `management_address` | `true` | Management Address TLVs |

### `lldp.management_addresses`

Selection order: pinned addresses if any; otherwise IPv6 global, IPv6
unique local, IPv4, then link-local if allowed. Temporary (RFC 8981) and
tentative addresses are skipped unless allowed. When `max_per_interface` is
2 or more, IPv4 and IPv6 each keep at least one slot if they have a usable
address, so a host with several IPv6 addresses still advertises its IPv4
address.

| Key | Default |
| --- | --- |
| `ipv4` | `true` |
| `ipv6` | `true` |
| `allow_temporary_ipv6` | `false` |
| `allow_link_local` | `false` |
| `max_per_interface` | 2 (0 to 8; 0 disables) |
| `pinned` | `[]` list of address strings |

## `interfaces`

| Key | Default | Meaning |
| --- | --- | --- |
| `default_mode` | `rx_tx` | Physical Ethernet adapters (including USB and docks) |
| `wifi` | `disabled` | 802.11 adapters |
| `virtual` | `disabled` | Hyper-V, bridges, teams |
| `exclude` | `["vEthernet*", "VPN*", "Loopback*"]` | Alias globs (`*`, `?`, case-insensitive) always disabled |
| `overrides` | `[]` | List of `{match, mode?, port_description?}`; first match wins. `match` is an alias glob or `guid:{...}`. |

Modes: `disabled`, `rx_only`, `tx_only`, `rx_tx`.

## `logging`

| Key | Default |
| --- | --- |
| `level` | `info` |
| `windows_event_log` | `true` |
| `event_rate_limit_per_minute` | 60 (1 to 10000) |

## `ipc`

| Key | Default | Meaning |
| --- | --- | --- |
| `enabled` | `true` | Serve `\\.\pipe\WinLLDP` |
| `read_group` | `S-1-5-11` (Authenticated Users) | SID or SDDL alias granted read access. Mutating operations always require Administrators. |

## `windows`

| Key | Default | Meaning |
| --- | --- | --- |
| `manage_mslldp_binding` | `true` | Unbind the Microsoft LLDP driver on adapters where WinLLDP transmits; restore when it stops |
