#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'WinLldp.psd1') -Force
}

Describe 'Module manifest' {
    It 'exports the documented cmdlets' {
        $m = Get-Module WinLldp
        $m.ExportedFunctions.Keys | Should -Contain 'Get-WinLldpNeighbor'
        $m.ExportedFunctions.Keys | Should -Contain 'Set-WinLldpInterface'
        $m.ExportedFunctions.Keys | Should -Contain 'Update-WinLldpConfiguration'
        $m.ExportedFunctions.Count | Should -Be 10
    }
    It 'does not collide with the NetLldpAgent module' {
        (Get-Module WinLldp).ExportedFunctions.Keys | Where-Object { $_ -like '*NetLldp*' } | Should -BeNullOrEmpty
    }
}

Describe 'Request encoding' {
    It 'builds a versioned request without params' {
        InModuleScope WinLldp {
            $j = ConvertTo-WinLldpRequest -Op 'GetServiceStatus' | ConvertFrom-Json
            $j.v | Should -Be 1
            $j.op | Should -Be 'GetServiceStatus'
            $j.PSObject.Properties.Name | Should -Not -Contain 'params'
        }
    }
    It 'sends an empty params object for an operation with only optional params' {
        InModuleScope WinLldp {
            ConvertTo-WinLldpRequest -Op 'ListNeighbors' -Params @{} | Should -Be '{"v":1,"op":"ListNeighbors","params":{}}'
        }
    }
    It 'builds a request with params' {
        InModuleScope WinLldp {
            $j = ConvertTo-WinLldpRequest -Op 'SetInterfaceMode' -Params @{ interface = 'Ethernet'; mode = 'rx_only' } | ConvertFrom-Json
            $j.params.interface | Should -Be 'Ethernet'
            $j.params.mode | Should -Be 'rx_only'
        }
    }
}

Describe 'Response decoding' {
    It 'returns the result on success' {
        InModuleScope WinLldp {
            $r = ConvertFrom-WinLldpResponse -Json '{"v":1,"ok":true,"result":{"a":1}}'
            $r.a | Should -Be 1
        }
    }
    It 'throws with the error code on failure' {
        InModuleScope WinLldp {
            { ConvertFrom-WinLldpResponse -Json '{"v":1,"ok":false,"error":{"code":"forbidden","message":"needs admin"}}' } |
                Should -Throw '*forbidden*needs admin*'
        }
    }
    It 'rejects a foreign protocol version' {
        InModuleScope WinLldp {
            { ConvertFrom-WinLldpResponse -Json '{"v":2,"ok":true,"result":null}' } | Should -Throw '*protocol version 2*'
        }
    }
}

Describe 'Object shaping' {
    It 'maps a neighbor result to typed properties' {
        InModuleScope WinLldp {
            Mock Invoke-WinLldpRequest {
                @([PSCustomObject]@{
                    interface_alias = 'Ethernet'; interface_guid = '{1}'; system_name = 'SW-ACCESS-01'; system_description = 'IOS-XE'
                    chassis_id = [PSCustomObject]@{ value = 'aa:bb:cc:dd:ee:ff'; subtype_name = 'macaddress' }
                    port_id = [PSCustomObject]@{ value = 'Gi1/0/24'; subtype_name = 'interfacename' }
                    port_description = 'Workstation Access Port'
                    capabilities = [PSCustomObject]@{ enabled = @('bridge'); supported = @('bridge', 'router'); short = 'B' }
                    management_addresses = @(
                        [PSCustomObject]@{ address = '10.10.10.1'; family = 'ipv4' },
                        [PSCustomObject]@{ address = '2001:db8:10::1'; family = 'ipv6' }
                    )
                    ttl = 120; ttl_remaining = 104; first_seen_unix = 1791504000; last_seen_unix = 1791504016; expires_unix = 1791504120
                    source_mac = 'aa:bb:cc:dd:ee:ff'; scope = 'nearest_bridge'; frames = 3; org_tlvs = @(); unknown_tlvs = @()
                })
            }
            $n = Get-WinLldpNeighbor -InterfaceAlias Ethernet
            $n.PSObject.TypeNames[0] | Should -Be 'WinLldp.Neighbor'
            $n.SystemName | Should -Be 'SW-ACCESS-01'
            $n.PortId | Should -Be 'Gi1/0/24'
            $n.ManagementIPv4 | Should -Be @('10.10.10.1')
            $n.ManagementIPv6 | Should -Be @('2001:db8:10::1')
            $n.Capabilities | Should -Be @('bridge')
            $n.TtlRemaining | Should -Be 104
            $n.FirstSeen | Should -BeOfType [DateTime]
            Should -Invoke Invoke-WinLldpRequest -ParameterFilter { $Op -eq 'ListNeighbors' -and $Params.interface -eq 'Ethernet' }
        }
    }
    It 'honors -WhatIf on mutating cmdlets' {
        InModuleScope WinLldp {
            Mock Invoke-WinLldpRequest { throw 'must not be called' }
            { Set-WinLldpInterface -InterfaceAlias Ethernet -Mode RxOnly -WhatIf } | Should -Not -Throw
            Should -Invoke Invoke-WinLldpRequest -Times 0
        }
    }
}
