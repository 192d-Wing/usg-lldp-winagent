# Troubleshooting

Start with `winlldp diagnostics` (exit code 1 if any check fails). It checks the configuration file, Npcap,
service reachability, the packet backend, managed interfaces, neighbor
count, and per-interface error counters.

## Event Log

Source `WinLLDP` in the Application log.

| ID | Level | Meaning |
| --- | --- | --- |
| 1000 / 1001 | Info | Service started / stopped |
| 1002 | Info | Configuration loaded |
| 1003 | Error | Configuration missing or invalid; the message lists each bad value with its path. At start the service stays up with every interface disabled until the file is corrected and reloaded; on a reload the previous configuration is kept |
| 1004 | Info | Registry policy overrides applied |
| 1100 | Error | Npcap missing or older than 1.50; LLDP is disabled until fixed |
| 1101 | Info | Npcap version in use |
| 1200 / 1201 | Info | Interface managed / unmanaged (with mode) |
| 1202 | Error | Packet channel could not be opened (Npcap access denied, adapter busy) |
| 1203 | Error | Port task failed (adapter removed under it) |
| 1300 | Info | Neighbor discovered |
| 1301 | Info | Neighbor advertisement changed |
| 1302 | Warning | Neighbor expired (no LLDPDU within TTL) |
| 1303 | Info | Neighbor removed (TTL 0, link down, admin change, shutdown) |
| 1304 | Warning | Neighbor table full; new neighbor dropped |
| 1305 | Warning | Malformed LLDP frame discarded |
| 1306 | Error | Local LLDPDU could not be built |
| 1400 | Info | Microsoft LLDP driver binding disabled or restored on an adapter |
| 1401 | Warning | Microsoft LLDP driver binding change failed |
| 1500 / 1501 | Info / Error | IPC server started / failed |
| 1900 | Warning | Events suppressed by rate limiting |

## Common situations

**No neighbors on a link that is up.**
1. Confirm the switch sends LLDP toward the port (`show lldp interface`, `show lldp neighbors` on the switch; the workstation should appear there if transmit works).
2. **NIC firmware LLDP agents.** Intel X710 / E810 and some server adapters can run LLDP in firmware and consume inbound LLDPDUs before Windows sees them. Symptom: `winlldp statistics` shows frames out but never in. Disable FW-LLDP in the adapter's UEFI HII menu or driver settings.
3. Capture with Wireshark on the workstation using filter `eth.dst == 01:80:c2:00:00:0e`. If frames appear in Wireshark but not in WinLLDP, check Event ID 1202 (Npcap access) and 1305 (malformed frames).
4. Hyper-V external vSwitch: LLDP multicast may not reach the host vNIC. Virtual adapters are disabled by default.

**Switch entry flips between full and bare, or shows TTL 3601.** The Microsoft LLDP driver (`ms_lldp`) and WinLLDP both transmitted. On Windows 11, `ms_lldp` advertises the hostname as a locally assigned chassis ID and the adapter MAC as port ID, the same identity WinLLDP uses by default, so the switch keeps one entry that the two agents overwrite in turn (the `ms_lldp` one has TTL 3601 and no system name). WinLLDP disables the binding on adapters where it transmits when `windows.manage_mslldp_binding` is true (default); check Event IDs 1400 / 1401. Verify with `Get-NetAdapterBinding -ComponentID ms_lldp`. With a different chassis or port ID source configured, the switch shows two neighbors instead.

**Switch entry reappears after WinLLDP stops.** Expected: on stop WinLLDP sends TTL 0 and restores the `ms_lldp` binding, and `ms_lldp` then advertises again.

**`winlldp` says it cannot connect.** The service is not running (`Get-Service WinLLDP`), or `ipc.enabled` is false, or the caller is not in the configured read group.

**`forbidden` from a mode change or reload.** Run from an elevated prompt; mutating operations require the Administrators group to be enabled in the token.

**Service runs but Event ID 1100.** Install Npcap 1.50+ (any edition) and restart the service. The MSI blocks installation without Npcap unless `IGNORE_NPCAP=1` was passed.

**Advertised name or addresses are wrong.** `winlldp local` shows exactly what is sent, including the encoded LLDPDU in hex. Adjust `lldp.advertise.*`, `lldp.management_addresses`, or policy, then `winlldp config reload`.

## Wireshark

```text
lldp
eth.type == 0x88cc
eth.dst == 01:80:c2:00:00:0e
eth.src == <workstation MAC>          # our transmissions
lldp.chassis.id.subtype == 7          # locally assigned chassis IDs (WinLLDP default)
lldp.tlv.ttl == 0                     # shutdown advertisements
lldp.tlv.type == 127                  # organizationally specific TLVs
```

Expected from WinLLDP: destination `01:80:c2:00:00:0e`, source = adapter MAC, EtherType `0x88cc`, TLV order Chassis ID (subtype 7), Port ID (subtype 3), TTL 121, Port Description, System Name, System Description, System Capabilities (Station Only), Management Address(es), End of LLDPDU.

## Foreground debugging

```powershell
Stop-Service WinLLDP
& "$env:ProgramFiles\WinLLDP\winlldp-service.exe" --console --config "$env:ProgramData\WinLLDP\config.yaml"
```

Prints every event to the console in addition to the Event Log. Ctrl+C sends shutdown advertisements and exits.
