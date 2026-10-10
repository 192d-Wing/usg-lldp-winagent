#Requires -Version 5.1
Set-StrictMode -Version Latest

$script:PipeName = 'WinLLDP'
$script:ProtocolVersion = 1
$script:MaxMessage = 8MB

function ConvertTo-WinLldpRequest {
    <#
    .SYNOPSIS
    Builds the JSON for one IPC request. Internal; exposed for tests.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Op,
        [hashtable] $Params
    )
    $body = [ordered]@{ v = $script:ProtocolVersion; op = $Op }
    # An operation whose parameters are all optional still needs a params
    # object, so an empty table is sent as {} rather than left out.
    if ($null -ne $Params) { $body.params = $Params }
    return ($body | ConvertTo-Json -Compress -Depth 5)
}

function ConvertFrom-WinLldpResponse {
    <#
    .SYNOPSIS
    Parses a response, throwing a terminating error on failure. Internal; exposed for tests.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Json)
    $resp = $Json | ConvertFrom-Json
    if ($resp.v -ne $script:ProtocolVersion) {
        throw "WinLLDP service speaks protocol version $($resp.v); this module speaks $($script:ProtocolVersion)"
    }
    if (-not $resp.ok) {
        $code = if ($resp.error) { $resp.error.code } else { 'internal' }
        $msg = if ($resp.error) { $resp.error.message } else { 'unknown error' }
        throw "WinLLDP ($code): $msg"
    }
    return $resp.result
}

function ConvertFrom-WinLldpUnixTime {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [uint64] $Seconds)
    return [DateTimeOffset]::FromUnixTimeSeconds([int64]$Seconds).LocalDateTime
}

function Invoke-WinLldpRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Op,
        [hashtable] $Params
    )
    $json = ConvertTo-WinLldpRequest -Op $Op -Params $Params
    $payload = [System.Text.Encoding]::UTF8.GetBytes($json)
    $pipe = New-Object System.IO.Pipes.NamedPipeClientStream('.', $script:PipeName, [System.IO.Pipes.PipeDirection]::InOut)
    try {
        try { $pipe.Connect(3000) }
        catch { throw "Cannot connect to the WinLLDP service pipe \\.\pipe\$($script:PipeName). Is the service running? ($($_.Exception.Message))" }
        $len = [BitConverter]::GetBytes([uint32]$payload.Length)
        if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($len) }
        $pipe.Write($len, 0, 4)
        $pipe.Write($payload, 0, $payload.Length)
        $pipe.Flush()

        $hdr = New-Object byte[] 4
        $got = 0
        while ($got -lt 4) {
            $n = $pipe.Read($hdr, $got, 4 - $got)
            if ($n -le 0) { throw 'WinLLDP service closed the connection before replying' }
            $got += $n
        }
        if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($hdr) }
        $size = [BitConverter]::ToUInt32($hdr, 0)
        if ($size -eq 0 -or $size -gt $script:MaxMessage) { throw "WinLLDP response length $size is out of range" }
        $buf = New-Object byte[] $size
        $got = 0
        while ($got -lt $size) {
            $n = $pipe.Read($buf, $got, $size - $got)
            if ($n -le 0) { throw 'WinLLDP service closed the connection mid-response' }
            $got += $n
        }
        return ConvertFrom-WinLldpResponse -Json ([System.Text.Encoding]::UTF8.GetString($buf))
    }
    finally {
        $pipe.Dispose()
    }
}

function Add-WinLldpType {
    param([Parameter(ValueFromPipeline)] $InputObject, [Parameter(Mandatory)] [string] $TypeName)
    process {
        if ($null -eq $InputObject) { return }
        $InputObject.PSObject.TypeNames.Insert(0, $TypeName)
        $InputObject
    }
}

function Get-WinLldpNeighbor {
    <#
    .SYNOPSIS
    Gets LLDP neighbors seen by this computer.
    .DESCRIPTION
    Returns one object per neighbor with the switch system name, chassis ID,
    port ID, port description, capabilities, management addresses, TTL, and
    the full decoded advertisement. Works over PowerShell Remoting.
    .PARAMETER InterfaceAlias
    Limit to one local interface by alias or GUID.
    .EXAMPLE
    Get-WinLldpNeighbor
    .EXAMPLE
    Get-WinLldpNeighbor -InterfaceAlias Ethernet | Select-Object SystemName, PortId, ManagementIPv4
    .EXAMPLE
    Invoke-Command -ComputerName WS-12345 -ScriptBlock { Get-WinLldpNeighbor }
    #>
    [CmdletBinding()]
    [OutputType('WinLldp.Neighbor')]
    param(
        [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('Name', 'Interface')]
        [string] $InterfaceAlias
    )
    process {
        $params = @{}
        if ($InterfaceAlias) { $params.interface = $InterfaceAlias }
        $result = Invoke-WinLldpRequest -Op 'ListNeighbors' -Params $params
        foreach ($n in @($result)) {
            $v4 = @($n.management_addresses | Where-Object family -eq 'ipv4' | ForEach-Object address)
            $v6 = @($n.management_addresses | Where-Object family -eq 'ipv6' | ForEach-Object address)
            $caps = if ($n.capabilities) { @($n.capabilities.enabled) } else { @() }
            [PSCustomObject]@{
                InterfaceAlias      = $n.interface_alias
                InterfaceGuid       = $n.interface_guid
                SystemName          = $n.system_name
                SystemDescription   = $n.system_description
                ChassisId           = $n.chassis_id.value
                ChassisIdSubtype    = $n.chassis_id.subtype_name
                PortId              = $n.port_id.value
                PortIdSubtype       = $n.port_id.subtype_name
                PortDescription     = $n.port_description
                Capabilities        = $caps
                ManagementIPv4      = $v4
                ManagementIPv6      = $v6
                ManagementAddresses = $n.management_addresses
                Ttl                 = [int]$n.ttl
                TtlRemaining        = [int]$n.ttl_remaining
                FirstSeen           = ConvertFrom-WinLldpUnixTime $n.first_seen_unix
                LastSeen            = ConvertFrom-WinLldpUnixTime $n.last_seen_unix
                Expires             = ConvertFrom-WinLldpUnixTime $n.expires_unix
                SourceMac           = $n.source_mac
                Scope               = $n.scope
                Frames              = [uint64]$n.frames
                OrgTlvs             = $n.org_tlvs
                UnknownTlvs         = $n.unknown_tlvs
                ComputerName        = $env:COMPUTERNAME
            } | Add-WinLldpType -TypeName 'WinLldp.Neighbor'
        }
    }
}

function Get-WinLldpInterface {
    <#
    .SYNOPSIS
    Lists network interfaces known to WinLLDP and their LLDP mode.
    .PARAMETER InterfaceAlias
    Limit to one interface by alias or GUID.
    .EXAMPLE
    Get-WinLldpInterface
    #>
    [CmdletBinding()]
    [OutputType('WinLldp.Interface')]
    param(
        [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('Name', 'Interface')]
        [string] $InterfaceAlias
    )
    process {
        $result = if ($InterfaceAlias) {
            Invoke-WinLldpRequest -Op 'GetInterfaceStatus' -Params @{ interface = $InterfaceAlias }
        } else {
            Invoke-WinLldpRequest -Op 'ListInterfaces'
        }
        foreach ($i in @($result)) {
            if ($null -eq $i) { continue }
            [PSCustomObject]@{
                InterfaceAlias = $i.alias
                InterfaceGuid  = $i.guid
                Description    = $i.description
                MacAddress     = $i.mac
                IfIndex        = [int]$i.if_index
                Kind           = $i.kind
                Connected      = [bool]$i.connected
                LinkSpeed      = [uint64]$i.link_speed
                Mode           = $i.mode
                Managed        = [bool]$i.managed
                Neighbors      = [int]$i.neighbors
                TooManyNeighbors = [bool]$i.too_many_neighbors
                Addresses      = @($i.addresses)
                ComputerName   = $env:COMPUTERNAME
            } | Add-WinLldpType -TypeName 'WinLldp.Interface'
        }
    }
}

function Get-WinLldpLocalAdvertisement {
    <#
    .SYNOPSIS
    Shows what this computer advertises on each managed interface.
    .PARAMETER InterfaceAlias
    Limit to one interface by alias or GUID.
    #>
    [CmdletBinding()]
    [OutputType('WinLldp.LocalAdvertisement')]
    param(
        [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('Name', 'Interface')]
        [string] $InterfaceAlias
    )
    process {
        $params = @{}
        if ($InterfaceAlias) { $params.interface = $InterfaceAlias }
        $result = Invoke-WinLldpRequest -Op 'GetLocalAdvertisement' -Params $params
        foreach ($a in @($result)) {
            [PSCustomObject]@{
                InterfaceAlias      = $a.interface_alias
                InterfaceGuid       = $a.interface_guid
                Mode                = $a.mode
                DestinationMac      = $a.destination_mac
                SourceMac           = $a.source_mac
                ChassisId           = $a.chassis_id.value
                ChassisIdSubtype    = $a.chassis_id.subtype_name
                PortId              = $a.port_id.value
                PortIdSubtype       = $a.port_id.subtype_name
                Ttl                 = [int]$a.ttl
                PortDescription     = $a.port_description
                SystemName          = $a.system_name
                SystemDescription   = $a.system_description
                Capabilities        = if ($a.capabilities) { @($a.capabilities.enabled) } else { @() }
                ManagementAddresses = @($a.management_addresses | ForEach-Object address)
                LldpduHex           = $a.lldpdu_hex
                ComputerName        = $env:COMPUTERNAME
            } | Add-WinLldpType -TypeName 'WinLldp.LocalAdvertisement'
        }
    }
}

function Get-WinLldpServiceStatus {
    <#
    .SYNOPSIS
    Gets WinLLDP service health.
    #>
    [CmdletBinding()]
    [OutputType('WinLldp.ServiceStatus')]
    param()
    $s = Invoke-WinLldpRequest -Op 'GetServiceStatus'
    [PSCustomObject]@{
        Version           = $s.version
        Uptime            = [TimeSpan]::FromSeconds([double]$s.uptime_secs)
        NpcapVersion      = $s.npcap_version
        BackendStatus     = $s.backend_status
        ConfigPath        = $s.config_path
        ConfigLoaded      = ConvertFrom-WinLldpUnixTime $s.config_loaded_unix
        PolicyApplied     = [bool]$s.policy_applied
        InterfacesKnown   = [int]$s.interfaces_known
        InterfacesManaged = [int]$s.interfaces_managed
        Neighbors         = [int]$s.neighbors_total
        SystemName        = $s.system_name
        ChassisId         = $s.chassis_id
        ComputerName      = $env:COMPUTERNAME
    } | Add-WinLldpType -TypeName 'WinLldp.ServiceStatus'
}

function Get-WinLldpStatistic {
    <#
    .SYNOPSIS
    Gets IEEE 802.1AB statistics counters per interface.
    .PARAMETER InterfaceAlias
    Limit to one interface by alias or GUID.
    #>
    [CmdletBinding()]
    [OutputType('WinLldp.Statistic')]
    param(
        [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('Name', 'Interface')]
        [string] $InterfaceAlias
    )
    process {
        $params = @{}
        if ($InterfaceAlias) { $params.interface = $InterfaceAlias }
        $result = Invoke-WinLldpRequest -Op 'GetStatistics' -Params $params
        foreach ($s in @($result)) {
            [PSCustomObject]@{
                InterfaceAlias        = $s.interface_alias
                InterfaceGuid         = $s.interface_guid
                RxFramesTotal         = [uint64]$s.rx_frames_total
                RxFramesDiscarded     = [uint64]$s.rx_frames_discarded_total
                RxFramesErrors        = [uint64]$s.rx_frames_errors
                RxTlvsDiscarded       = [uint64]$s.rx_tlvs_discarded_total
                RxTlvsUnrecognized    = [uint64]$s.rx_tlvs_unrecognized_total
                RxAgeouts             = [uint64]$s.rx_ageouts_total
                TxFramesTotal         = [uint64]$s.tx_frames_total
                TxLengthErrors        = [uint64]$s.tx_lldpdu_length_errors
                NeighborInserts       = [uint64]$s.rem_inserts
                NeighborDeletes       = [uint64]$s.rem_deletes
                NeighborDrops         = [uint64]$s.rem_drops
                RxQueueOverflow       = [uint64]$s.rx_queue_overflow
                ComputerName          = $env:COMPUTERNAME
            } | Add-WinLldpType -TypeName 'WinLldp.Statistic'
        }
    }
}

function Set-WinLldpInterface {
    <#
    .SYNOPSIS
    Sets the LLDP administrative mode of an interface at runtime (administrators only).
    .DESCRIPTION
    The change lasts until the service reloads its configuration or restarts.
    Edit config.yaml for a persistent change.
    .PARAMETER InterfaceAlias
    Interface alias or GUID.
    .PARAMETER Mode
    Disabled, RxOnly, TxOnly, or RxTx.
    .EXAMPLE
    Set-WinLldpInterface -InterfaceAlias Ethernet -Mode RxOnly
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('Name', 'Interface')]
        [string] $InterfaceAlias,
        [Parameter(Mandatory)]
        [ValidateSet('Disabled', 'RxOnly', 'TxOnly', 'RxTx')]
        [string] $Mode
    )
    process {
        $wire = @{ Disabled = 'disabled'; RxOnly = 'rx_only'; TxOnly = 'tx_only'; RxTx = 'rx_tx' }[$Mode]
        if ($PSCmdlet.ShouldProcess($InterfaceAlias, "Set LLDP mode to $Mode")) {
            $r = Invoke-WinLldpRequest -Op 'SetInterfaceMode' -Params @{ interface = $InterfaceAlias; mode = $wire }
            foreach ($changed in @($r.changed)) {
                Get-WinLldpInterface -InterfaceAlias $changed
            }
        }
    }
}

function Enable-WinLldpInterface {
    <#
    .SYNOPSIS
    Enables LLDP receive and transmit on an interface (administrators only).
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('Name', 'Interface')]
        [string] $InterfaceAlias
    )
    process {
        if ($PSCmdlet.ShouldProcess($InterfaceAlias, 'Enable LLDP (rx_tx)')) {
            Set-WinLldpInterface -InterfaceAlias $InterfaceAlias -Mode RxTx -Confirm:$false
        }
    }
}

function Disable-WinLldpInterface {
    <#
    .SYNOPSIS
    Disables LLDP on an interface (administrators only).
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('Name', 'Interface')]
        [string] $InterfaceAlias
    )
    process {
        if ($PSCmdlet.ShouldProcess($InterfaceAlias, 'Disable LLDP')) {
            Set-WinLldpInterface -InterfaceAlias $InterfaceAlias -Mode Disabled -Confirm:$false
        }
    }
}

function Test-WinLldpConfiguration {
    <#
    .SYNOPSIS
    Validates a WinLLDP configuration file using winlldp.exe.
    .PARAMETER Path
    Configuration file; defaults to %ProgramData%\WinLLDP\config.yaml.
    .OUTPUTS
    Boolean. Validation messages go to the error stream.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([string] $Path)
    $exe = Join-Path (Join-Path $env:ProgramFiles 'WinLLDP') 'winlldp.exe'
    if (-not (Test-Path $exe)) {
        $cmd = Get-Command winlldp.exe -ErrorAction SilentlyContinue
        if ($cmd) { $exe = $cmd.Source } else { throw "winlldp.exe not found at $exe or on PATH" }
    }
    $args = @('config', 'validate')
    if ($Path) { $args += $Path }
    $out = & $exe @args 2>&1
    if ($LASTEXITCODE -eq 0) { return $true }
    Write-Error ($out -join "`n")
    return $false
}

function Update-WinLldpConfiguration {
    <#
    .SYNOPSIS
    Asks the running service to reload config.yaml and registry policy (administrators only).
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param()
    if ($PSCmdlet.ShouldProcess('WinLLDP service', 'Reload configuration')) {
        $null = Invoke-WinLldpRequest -Op 'ReloadConfiguration'
        Write-Verbose 'Reload requested'
    }
}

Export-ModuleMember -Function @(
    'Get-WinLldpNeighbor', 'Get-WinLldpInterface', 'Get-WinLldpLocalAdvertisement',
    'Get-WinLldpServiceStatus', 'Get-WinLldpStatistic',
    'Enable-WinLldpInterface', 'Disable-WinLldpInterface', 'Set-WinLldpInterface',
    'Test-WinLldpConfiguration', 'Update-WinLldpConfiguration'
)
