# Deployment

## Prerequisites

| Requirement | Notes |
| --- | --- |
| Windows 11 Enterprise / LTSC, Windows Server 2022 / 2025, x64 or ARM64 | The MSI refuses older or 32-bit Windows. |
| **Npcap 1.50 or later** | Not bundled. Deploy it before WinLLDP. The MSI checks for `%SystemRoot%\System32\Npcap\wpcap.dll` and refuses to install without it unless `IGNORE_NPCAP=1` is passed. Npcap's free edition permits internal use; silent deployment switches (`/S`) are documented by Npcap. Admin-only mode is supported because the service runs as LocalSystem. |
| .NET Framework 4.x | Present on all supported Windows; used only for Event Log message rendering. |

## Packages

Each release publishes `WinLLDP-<version>-x64.msi`, `WinLLDP-<version>-arm64.msi`, and a CycloneDX SBOM per architecture. Executables, the PowerShell module files, and the MSI are signed with Azure Trusted Signing.

The MSI installs:

- `%ProgramFiles%\WinLLDP\winlldp-service.exe`, `winlldp.exe`, `LICENSE.txt`, and adds the folder to the system `PATH`.
- `%ProgramData%\WinLLDP\config.yaml` (never overwritten on upgrade).
- `%ProgramFiles%\WindowsPowerShell\Modules\WinLldp\` (the PowerShell module, visible to both Windows PowerShell 5.1 and PowerShell 7).
- The `WinLLDP` service: automatic start, LocalSystem, service SID (unrestricted), `SeChangeNotifyPrivilege` only, restart on failure.
- The `WinLLDP` Event Log source.

## Silent install, upgrade, uninstall

```powershell
msiexec /i WinLLDP-0.1.0-x64.msi /qn /norestart /l*v "$env:TEMP\WinLLDP-install.log"
msiexec /i WinLLDP-0.2.0-x64.msi /qn /norestart /l*v "$env:TEMP\WinLLDP-upgrade.log"   # major upgrade, config kept
msiexec /x WinLLDP-0.2.0-x64.msi /qn /norestart /l*v "$env:TEMP\WinLLDP-uninstall.log"
```

Upgrades stop the service, replace the binaries, and restart it; the shutdown sends TTL 0 advertisements so switches drop the old entry immediately. Rollback is handled by Windows Installer if any step fails.

## Microsoft Intune

1. Deploy Npcap first as a Win32 app (wrap the Npcap installer with the Win32 Content Prep Tool; install command `npcap-<ver>.exe /S`; detection rule: file `%SystemRoot%\System32\Npcap\wpcap.dll` exists).
2. Add WinLLDP as a **Line-of-business app** (MSI) or as a Win32 app:
   - Install: `msiexec /i WinLLDP-0.1.0-x64.msi /qn /norestart`
   - Uninstall: `msiexec /x {ProductCode} /qn /norestart`
   - Detection: MSI product code (automatic for LOB apps).
   - Dependency: the Npcap app.
3. Optional policy via a custom OMA-URI or a PowerShell script that writes `HKLM\SOFTWARE\Policies\WinLLDP` (see Configuration).

## Microsoft Configuration Manager

Create an Application with the MSI deployment type (the wizard reads the product code). Set a dependency on the Npcap application. Use the silent commands above. Deploy to a device collection; the detection method is the MSI product code.

## PowerShell / manual

```powershell
Start-Process msiexec -ArgumentList '/i','WinLLDP-0.1.0-x64.msi','/qn','/norestart','/l*v','C:\Windows\Temp\WinLLDP.log' -Wait
Get-Service WinLLDP
winlldp status
Get-WinLldpNeighbor
```

## Application control (WDAC / App Control for Business, Smart App Control)

Allow the WinLLDP signer (Azure Trusted Signing certificate) and Npcap's signer. `wpcap.dll` and `Packet.dll` are loaded from `System32\Npcap` by absolute path; both must be allowed by policy. No other DLLs are loaded dynamically.

## Policy overrides

Values under `HKLM\SOFTWARE\Policies\WinLLDP` override `config.yaml` at every load:

| Value | Type | Meaning |
| --- | --- | --- |
| `Enabled` | DWORD | 0 disables every interface |
| `DefaultMode` | SZ | `disabled`, `rx_only`, `tx_only`, `rx_tx` |
| `AdvertiseFqdn` | DWORD | System Name uses FQDN (1) or short name (0) |
| `AdvertiseOsVersion` | DWORD | Include OS version in System Description |
| `AdvertiseHardware` | DWORD | Include manufacturer and model |
| `AdvertiseManagementAddress` | DWORD | Send Management Address TLVs |

Reload without restart: `winlldp config reload`, `Update-WinLldpConfiguration`, or `sc control WinLLDP 128`.
