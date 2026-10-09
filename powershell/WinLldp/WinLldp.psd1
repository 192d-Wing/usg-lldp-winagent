@{
    RootModule        = 'WinLldp.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = '7f3a2b1c-5d4e-4f60-9a8b-1c2d3e4f5a6b'
    Author            = 'John Edward Willman V'
    CompanyName       = 'JHICS'
    Copyright         = '(c) 2026. MIT License.'
    Description       = 'Query and manage the WinLLDP IEEE 802.1AB agent: LLDP neighbors, interfaces, local advertisements, statistics, and service status.'
    PowerShellVersion = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    FunctionsToExport = @(
        'Get-WinLldpNeighbor',
        'Get-WinLldpInterface',
        'Get-WinLldpLocalAdvertisement',
        'Get-WinLldpServiceStatus',
        'Get-WinLldpStatistic',
        'Enable-WinLldpInterface',
        'Disable-WinLldpInterface',
        'Set-WinLldpInterface',
        'Test-WinLldpConfiguration',
        'Update-WinLldpConfiguration'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    FormatsToProcess  = @('WinLldp.format.ps1xml')
    PrivateData       = @{
        PSData = @{
            Tags       = @('LLDP', 'Network', 'Windows', 'IEEE802.1AB')
            LicenseUri = 'https://opensource.org/licenses/MIT'
            ProjectUri = 'https://github.com/jhics/usg-lldp-winagent'
        }
    }
}
