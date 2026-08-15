$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$VerbosePreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
Set-StrictMode -Version 2.0

function Test-Value([string]$Name) {
    return $null -ne $script:Params.PSObject.Properties[$Name] -and $null -ne $script:Params.$Name
}

function Get-RequiredString([string]$Name, [int]$Maximum = 256) {
    if (-not (Test-Value $Name) -or -not ($script:Params.$Name -is [string]) -or
        [string]::IsNullOrEmpty($script:Params.$Name) -or $script:Params.$Name.Length -gt $Maximum) {
        throw [System.ArgumentException]::new("invalid structured string")
    }
    return [string]$script:Params.$Name
}

function Get-RequiredGuid([string]$Name) {
    $Value = Get-RequiredString $Name 36
    $Parsed = [guid]::Empty
    if (-not [guid]::TryParseExact($Value, 'D', [ref]$Parsed)) {
        throw [System.ArgumentException]::new("invalid structured identifier")
    }
    return $Parsed
}

function Get-ValidatedChoice([string]$Name, [string[]]$Choices, [string]$Default = '') {
    $Value = if (Test-Value $Name) { [string]$script:Params.$Name } else { $Default }
    if ($Choices -notcontains $Value) {
        throw [System.ArgumentException]::new("invalid structured choice")
    }
    return $Value
}

function Get-ValidatedInteger([string]$Name, [long]$Minimum, [long]$Maximum, [long]$Default = -1) {
    $Value = if (Test-Value $Name) { $script:Params.$Name } else { $Default }
    if ($Value -is [bool] -or $Value -isnot [ValueType]) {
        throw [System.ArgumentException]::new("invalid structured integer")
    }
    $Parsed = [long]$Value
    if ($Parsed -lt $Minimum -or $Parsed -gt $Maximum) {
        throw [System.ArgumentOutOfRangeException]::new("structured integer out of range")
    }
    return $Parsed
}

function Assert-TargetHost {
    $Expected = Get-RequiredString 'expected_host' 253
    $Candidates = @($env:COMPUTERNAME)
    try { $Candidates += [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName } catch { Write-Verbose 'FQDN lookup unavailable' }
    if (-not ($Candidates | Where-Object { $_ -ieq $Expected })) {
        throw [System.InvalidOperationException]::new("target host identity mismatch")
    }
}

function Assert-Confirmation {
    $Confirmation = Get-RequiredString 'confirmation' 2048
    $Expected = switch ($script:Operation) {
        'vm_delete' { 'DELETE_VM:{0}:{1}' -f $script:Params.expected_host, $script:Params.vm_id }
        'checkpoint_restore' { 'RESTORE_CHECKPOINT:{0}:{1}:{2}' -f $script:Params.expected_host, $script:Params.vm_id, $script:Params.checkpoint_id }
        'checkpoint_delete' { 'DELETE_CHECKPOINT:{0}:{1}:{2}' -f $script:Params.expected_host, $script:Params.vm_id, $script:Params.checkpoint_id }
        'switch_delete' { 'DELETE_SWITCH:{0}:{1}' -f $script:Params.expected_host, $script:Params.switch_id }
        'switch_create' { if ($script:Params.switch_type -eq 'external') { 'CREATE_EXTERNAL_SWITCH:{0}:{1}' -f $script:Params.expected_host, $script:Params.name } }
        'vm_import' {
            $ImportMode = if (Test-Value 'mode') { $script:Params.mode } else { 'copy' }
            if ($ImportMode -eq 'register') { 'REGISTER_IMPORT:{0}:{1}' -f $script:Params.expected_host, $script:Params.config_host_path }
        }
        'vm_migrate' { 'MIGRATE_VM:{0}:{1}:{2}' -f $script:Params.expected_host, $script:Params.vm_id, $script:Params.destination_host }
    }
    if ($null -ne $Expected -and $Confirmation -cne $Expected) {
        throw [System.InvalidOperationException]::new("destructive confirmation mismatch")
    }
}

function Get-TargetHost {
    try { return [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName.ToLowerInvariant() } catch { return $env:COMPUTERNAME.ToLowerInvariant() }
}

function Resolve-VM {
    $Id = Get-RequiredGuid 'vm_id'
    return Get-VM -Id $Id -ErrorAction Stop
}

function Resolve-Checkpoint($Vm) {
    $Id = Get-RequiredGuid 'checkpoint_id'
    $Resolved = @(Get-VMSnapshot -VM $Vm | Where-Object { $_.Id -eq $Id })
    if ($Resolved.Count -ne 1) { throw [System.InvalidOperationException]::new("checkpoint identity did not resolve uniquely") }
    return $Resolved[0]
}

function Resolve-Switch {
    $Id = Get-RequiredGuid 'switch_id'
    $Resolved = @(Get-VMSwitch | Where-Object { $_.Id -eq $Id })
    if ($Resolved.Count -ne 1) { throw [System.InvalidOperationException]::new("switch identity did not resolve uniquely") }
    return $Resolved[0]
}

function Resolve-Adapter($Vm) {
    $Name = Get-RequiredString 'adapter_name' 256
    $Resolved = @(Get-VMNetworkAdapter -VM $Vm | Where-Object { $_.Name -ceq $Name })
    if ($Resolved.Count -ne 1) { throw [System.InvalidOperationException]::new("adapter name did not resolve uniquely") }
    return $Resolved[0]
}

function Convert-VM($Vm) {
    return [ordered]@{
        id = $Vm.Id.ToString().ToLowerInvariant()
        name = $Vm.Name
        state = $Vm.State.ToString()
        status = $Vm.Status
        generation = [int]$Vm.Generation
        version = $Vm.Version
        cpu_usage_percent = [int]$Vm.CPUUsage
        memory_assigned_bytes = [long]$Vm.MemoryAssigned
        uptime_seconds = [long]$Vm.Uptime.TotalSeconds
        configuration_host_path = $Vm.Path
    }
}

function Convert-VHD($Disk) {
    return [ordered]@{
        host_path = $Disk.Path
        format = $Disk.VhdFormat.ToString()
        type = $Disk.VhdType.ToString()
        file_size_bytes = [long]$Disk.FileSize
        virtual_size_bytes = [long]$Disk.Size
        minimum_size_bytes = if ($null -eq $Disk.MinimumSize) { $null } else { [long]$Disk.MinimumSize }
        attached = [bool]$Disk.Attached
    }
}

function Convert-Switch($Switch) {
    return [ordered]@{
        id = $Switch.Id.ToString().ToLowerInvariant()
        name = $Switch.Name
        type = $Switch.SwitchType.ToString()
        net_adapter_interface_description = $Switch.NetAdapterInterfaceDescription
        allow_management_os = [bool]$Switch.AllowManagementOS
    }
}

function Convert-Adapter($Adapter) {
    $Vlan = Get-VMNetworkAdapterVlan -VMNetworkAdapter $Adapter
    return [ordered]@{
        id = [string]$Adapter.Id
        name = $Adapter.Name
        vm_id = $Adapter.VMId.ToString().ToLowerInvariant()
        switch_name = $Adapter.SwitchName
        connected = [bool]$Adapter.Connected
        dynamic_mac_address_enabled = [bool]$Adapter.DynamicMacAddressEnabled
        mac_address = $Adapter.MacAddress
        vlan_mode = $Vlan.OperationMode.ToString()
        access_vlan_id = [int]$Vlan.AccessVlanId
    }
}

function Convert-Checkpoint($Checkpoint) {
    return [ordered]@{
        id = $Checkpoint.Id.ToString().ToLowerInvariant()
        vm_id = $Checkpoint.VMId.ToString().ToLowerInvariant()
        name = $Checkpoint.Name
        checkpoint_type = $Checkpoint.CheckpointType.ToString()
        creation_time = $Checkpoint.CreationTime.ToUniversalTime().ToString('o')
    }
}

function Convert-Replication($Replication) {
    return [ordered]@{
        vm_id = $Replication.VMId.ToString().ToLowerInvariant()
        vm_name = $Replication.VMName
        mode = $Replication.ReplicationMode.ToString()
        state = $Replication.State.ToString()
        health = $Replication.Health.ToString()
        primary_server = $Replication.PrimaryServer
        replica_server = $Replication.ReplicaServer
        last_replication_time = if ($null -eq $Replication.LastReplicationTime) { $null } else { $Replication.LastReplicationTime.ToUniversalTime().ToString('o') }
    }
}

function Write-Result($Data, [bool]$Changed = $false) {
    [ordered]@{
        operation = $script:Operation
        target_host = Get-TargetHost
        data = $Data
        meta = [ordered]@{
            changed = $Changed
            async = $false
            completed_at = [DateTime]::UtcNow.ToString('o')
        }
    } | ConvertTo-Json -Compress -Depth 8
}

try {
    if ([string]::IsNullOrEmpty($env:ATTUNE_HYPERV_INPUT_B64)) { throw [System.ArgumentException]::new("missing structured input") }
    $InputBytes = [Convert]::FromBase64String($env:ATTUNE_HYPERV_INPUT_B64)
    if ($InputBytes.Length -gt 65536) { throw [System.ArgumentOutOfRangeException]::new("structured input too large") }
    $script:Params = [Text.Encoding]::UTF8.GetString($InputBytes) | ConvertFrom-Json -ErrorAction Stop
    $script:Operation = Get-ValidatedChoice 'operation' @(
        'vm_list', 'vm_get', 'vm_create', 'vm_configure', 'vm_start', 'vm_stop', 'vm_restart', 'vm_save', 'vm_delete',
        'vhd_create', 'vhd_attach', 'vhd_detach', 'vhd_resize', 'switch_list', 'switch_create', 'switch_delete',
        'network_adapter_connect', 'network_adapter_configure', 'checkpoint_list', 'checkpoint_create', 'checkpoint_restore',
        'checkpoint_delete', 'vm_export', 'vm_import', 'vm_migrate', 'replication_status', 'job_poll'
    )
    Import-Module Hyper-V -ErrorAction Stop
    if (@(
        'vm_create', 'vm_configure', 'vm_start', 'vm_stop', 'vm_restart', 'vm_save', 'vm_delete', 'vhd_create',
        'vhd_attach', 'vhd_detach', 'vhd_resize', 'switch_create', 'switch_delete', 'network_adapter_connect',
        'network_adapter_configure', 'checkpoint_create', 'checkpoint_restore', 'checkpoint_delete', 'vm_export',
        'vm_import', 'vm_migrate'
    ) -contains $script:Operation) { Assert-TargetHost }
    if (@('vm_delete', 'checkpoint_restore', 'checkpoint_delete', 'switch_delete', 'vm_migrate') -contains $script:Operation) { Assert-Confirmation }
    if ($script:Operation -eq 'switch_create' -and $script:Params.switch_type -eq 'external') { Assert-Confirmation }
    if ($script:Operation -eq 'vm_import') {
        $ImportMode = if (Test-Value 'mode') { $script:Params.mode } else { 'copy' }
        if ($ImportMode -eq 'register') { Assert-Confirmation }
    }

    switch ($script:Operation) {
        'vm_list' {
            $VMs = @(Get-VM)
            if (Test-Value 'state') {
                $State = Get-ValidatedChoice 'state' @('Off', 'Running', 'Saved', 'Paused')
                $VMs = @($VMs | Where-Object { $_.State.ToString() -eq $State })
            }
            Write-Result @($VMs | Sort-Object Name | ForEach-Object { Convert-VM $_ })
        }
        'vm_get' { Write-Result (Convert-VM (Resolve-VM)) }
        'vm_create' {
            $Name = Get-RequiredString 'name' 100
            if (@(Get-VM | Where-Object { $_.Name -ceq $Name }).Count -ne 0) { throw [System.InvalidOperationException]::new("VM name already exists") }
            $Arguments = @{ Name = $Name; Generation = [int](Get-ValidatedInteger 'generation' 1 2 2); NoVHD = $true }
            $Arguments.MemoryStartupBytes = Get-ValidatedInteger 'memory_startup_bytes' 33554432 17592186044416 1073741824
            if (Test-Value 'switch_name') { $Arguments.SwitchName = Get-RequiredString 'switch_name' 256 }
            if (Test-Value 'vm_host_path') { $Arguments.Path = Get-RequiredString 'vm_host_path' 1024 }
            $VM = New-VM @Arguments
            Write-Result (Convert-VM $VM) $true
        }
        'vm_configure' {
            $VM = Resolve-VM
            $Changed = $false
            $SetVM = @{ VM = $VM }
            foreach ($Pair in @(@('name','Name'), @('automatic_start_action','AutomaticStartAction'), @('automatic_stop_action','AutomaticStopAction'), @('checkpoint_type','CheckpointType'))) {
                if (Test-Value $Pair[0]) { $SetVM[$Pair[1]] = Get-RequiredString $Pair[0] 100; $Changed = $true }
            }
            if ($SetVM.Count -gt 1) { Set-VM @SetVM }
            $Memory = @{ VM = $VM }
            if (Test-Value 'memory_startup_bytes') { $Memory.StartupBytes = Get-ValidatedInteger 'memory_startup_bytes' 33554432 17592186044416; $Changed = $true }
            if (Test-Value 'dynamic_memory') {
                if ($script:Params.dynamic_memory -isnot [bool]) { throw [System.ArgumentException]::new("invalid structured boolean") }
                $Memory.DynamicMemoryEnabled = [bool]$script:Params.dynamic_memory; $Changed = $true
            }
            if (Test-Value 'memory_minimum_bytes') { $Memory.MinimumBytes = Get-ValidatedInteger 'memory_minimum_bytes' 33554432 17592186044416; $Changed = $true }
            if (Test-Value 'memory_maximum_bytes') { $Memory.MaximumBytes = Get-ValidatedInteger 'memory_maximum_bytes' 33554432 17592186044416; $Changed = $true }
            if ($Memory.Count -gt 1) { Set-VMMemory @Memory }
            if (Test-Value 'processor_count') { Set-VMProcessor -VM $VM -Count ([int](Get-ValidatedInteger 'processor_count' 1 2048)); $Changed = $true }
            if (-not $Changed) { throw [System.ArgumentException]::new("no configuration field was supplied") }
            Write-Result (Convert-VM (Resolve-VM)) $true
        }
        'vm_start' {
            $VM = Resolve-VM; $Changed = $VM.State.ToString() -ne 'Running'
            if ($Changed) { Start-VM -VM $VM | Out-Null }
            Write-Result (Convert-VM (Resolve-VM)) $Changed
        }
        'vm_stop' {
            $VM = Resolve-VM; $Changed = $VM.State.ToString() -ne 'Off'
            if ($Changed) { Stop-VM -VM $VM -Shutdown -Confirm:$false | Out-Null }
            Write-Result (Convert-VM (Resolve-VM)) $Changed
        }
        'vm_restart' {
            $VM = Resolve-VM
            if ($VM.State.ToString() -ne 'Running') { throw [System.InvalidOperationException]::new("VM must be running to restart") }
            Restart-VM -VM $VM -Confirm:$false | Out-Null
            Write-Result (Convert-VM (Resolve-VM)) $true
        }
        'vm_save' {
            $VM = Resolve-VM; $Changed = $VM.State.ToString() -ne 'Saved'
            if ($Changed) { Save-VM -VM $VM -Confirm:$false | Out-Null }
            Write-Result (Convert-VM (Resolve-VM)) $Changed
        }
        'vm_delete' {
            $VM = Resolve-VM
            if ($VM.State.ToString() -ne 'Off') { throw [System.InvalidOperationException]::new("VM must be off before deletion") }
            $Deleted = Convert-VM $VM
            Remove-VM -VM $VM -Force
            Write-Result ([ordered]@{ deleted = $true; vm = $Deleted; virtual_disks_deleted = $false }) $true
        }
        'vhd_create' {
            $Path = Get-RequiredString 'vhd_host_path' 1024
            if (Test-Path -LiteralPath $Path) { throw [System.IO.IOException]::new("VHD path already exists") }
            $Type = Get-ValidatedChoice 'disk_type' @('dynamic','fixed','differencing') 'dynamic'
            if ($Type -eq 'differencing') {
                $Disk = New-VHD -Path $Path -Differencing -ParentPath (Get-RequiredString 'parent_vhd_host_path' 1024)
            } else {
                $Size = Get-ValidatedInteger 'size_bytes' 1048576 70368744177664
                $Disk = if ($Type -eq 'fixed') { New-VHD -Path $Path -SizeBytes $Size -Fixed } else { New-VHD -Path $Path -SizeBytes $Size -Dynamic }
            }
            Write-Result (Convert-VHD $Disk) $true
        }
        'vhd_attach' {
            $VM = Resolve-VM; $Path = Get-RequiredString 'vhd_host_path' 1024
            $Existing = @(Get-VMHardDiskDrive -VM $VM | Where-Object { $_.Path -ieq $Path })
            if ($Existing.Count -gt 0) { Write-Result ([ordered]@{ vm_id = $VM.Id.ToString(); host_path = $Path; attached = $true }) $false; break }
            $Arguments = @{ VM = $VM; Path = $Path; ControllerType = 'SCSI' }
            if (Test-Value 'controller_number') { $Arguments.ControllerNumber = [int](Get-ValidatedInteger 'controller_number' 0 3) }
            if (Test-Value 'controller_location') { $Arguments.ControllerLocation = [int](Get-ValidatedInteger 'controller_location' 0 63) }
            Add-VMHardDiskDrive @Arguments
            Write-Result ([ordered]@{ vm_id = $VM.Id.ToString().ToLowerInvariant(); host_path = $Path; attached = $true }) $true
        }
        'vhd_detach' {
            $VM = Resolve-VM; $Path = Get-RequiredString 'vhd_host_path' 1024
            $Drives = @(Get-VMHardDiskDrive -VM $VM | Where-Object { $_.Path -ieq $Path })
            if ($Drives.Count -gt 1) { throw [System.InvalidOperationException]::new("VHD attachment did not resolve uniquely") }
            if ($Drives.Count -eq 1) { Remove-VMHardDiskDrive -VMHardDiskDrive $Drives[0]; $Changed = $true } else { $Changed = $false }
            Write-Result ([ordered]@{ vm_id = $VM.Id.ToString().ToLowerInvariant(); host_path = $Path; attached = $false; disk_deleted = $false }) $Changed
        }
        'vhd_resize' {
            $Path = Get-RequiredString 'vhd_host_path' 1024; $Disk = Get-VHD -Path $Path
            $Size = Get-ValidatedInteger 'size_bytes' 1048576 70368744177664
            if ($Size -lt [long]$Disk.Size) { throw [System.InvalidOperationException]::new("shrinking VHDs is not supported") }
            $Changed = $Size -gt [long]$Disk.Size
            if ($Changed) { Resize-VHD -Path $Path -SizeBytes $Size }
            Write-Result (Convert-VHD (Get-VHD -Path $Path)) $Changed
        }
        'switch_list' { Write-Result @(Get-VMSwitch | Sort-Object Name | ForEach-Object { Convert-Switch $_ }) }
        'switch_create' {
            $Name = Get-RequiredString 'name' 256
            if (@(Get-VMSwitch | Where-Object { $_.Name -ceq $Name }).Count -ne 0) { throw [System.InvalidOperationException]::new("switch name already exists") }
            $Type = Get-ValidatedChoice 'switch_type' @('private','internal','external')
            if ($Type -eq 'external') {
                if (-not (Test-Value 'allow_management_os') -or $script:Params.allow_management_os -isnot [bool]) { throw [System.ArgumentException]::new("external switch requires explicit management OS choice") }
                $Switch = New-VMSwitch -Name $Name -NetAdapterName (Get-RequiredString 'network_adapter_name' 256) -AllowManagementOS ([bool]$script:Params.allow_management_os)
            } else { $Switch = New-VMSwitch -Name $Name -SwitchType $Type }
            Write-Result (Convert-Switch $Switch) $true
        }
        'switch_delete' {
            $Switch = Resolve-Switch; $Deleted = Convert-Switch $Switch
            Remove-VMSwitch -VMSwitch $Switch -Force
            Write-Result ([ordered]@{ deleted = $true; switch = $Deleted }) $true
        }
        'network_adapter_connect' {
            $VM = Resolve-VM; $Adapter = Resolve-Adapter $VM; $Switch = Resolve-Switch
            $Changed = $Adapter.SwitchId -ne $Switch.Id
            if ($Changed) { Connect-VMNetworkAdapter -VMNetworkAdapter $Adapter -SwitchName $Switch.Name }
            Write-Result (Convert-Adapter (Resolve-Adapter (Resolve-VM))) $Changed
        }
        'network_adapter_configure' {
            $VM = Resolve-VM; $Adapter = Resolve-Adapter $VM; $Changed = $false
            if (Test-Value 'mac_mode') {
                $Mode = Get-ValidatedChoice 'mac_mode' @('dynamic','static')
                if ($Mode -eq 'dynamic') { Set-VMNetworkAdapter -VMNetworkAdapter $Adapter -DynamicMacAddress }
                else {
                    $Mac = (Get-RequiredString 'mac_address' 17) -replace '[:-]', ''
                    if ($Mac -notmatch '^[0-9A-Fa-f]{12}$') { throw [System.ArgumentException]::new("invalid MAC address") }
                    Set-VMNetworkAdapter -VMNetworkAdapter $Adapter -StaticMacAddress $Mac
                }
                $Changed = $true
            }
            if (Test-Value 'vlan_id') {
                $Vlan = Get-ValidatedInteger 'vlan_id' 0 4094
                if ($Vlan -eq 0) { Set-VMNetworkAdapterVlan -VMNetworkAdapter $Adapter -Untagged }
                else { Set-VMNetworkAdapterVlan -VMNetworkAdapter $Adapter -Access -VlanId ([int]$Vlan) }
                $Changed = $true
            }
            if (-not $Changed) { throw [System.ArgumentException]::new("no adapter configuration field was supplied") }
            Write-Result (Convert-Adapter (Resolve-Adapter (Resolve-VM))) $true
        }
        'checkpoint_list' { $VM = Resolve-VM; Write-Result @(Get-VMSnapshot -VM $VM | Sort-Object CreationTime | ForEach-Object { Convert-Checkpoint $_ }) }
        'checkpoint_create' {
            $VM = Resolve-VM; $Before = @(Get-VMSnapshot -VM $VM | ForEach-Object { $_.Id })
            Checkpoint-VM -VM $VM -SnapshotName (Get-RequiredString 'name' 100) -Confirm:$false
            $Created = @(Get-VMSnapshot -VM (Resolve-VM) | Where-Object { $Before -notcontains $_.Id })
            if ($Created.Count -ne 1) { throw [System.InvalidOperationException]::new("new checkpoint did not resolve uniquely") }
            Write-Result (Convert-Checkpoint $Created[0]) $true
        }
        'checkpoint_restore' {
            $VM = Resolve-VM; $Checkpoint = Resolve-Checkpoint $VM
            Restore-VMSnapshot -VMSnapshot $Checkpoint -Confirm:$false
            Write-Result ([ordered]@{ restored = $true; checkpoint = Convert-Checkpoint $Checkpoint; vm = Convert-VM (Resolve-VM) }) $true
        }
        'checkpoint_delete' {
            $VM = Resolve-VM; $Checkpoint = Resolve-Checkpoint $VM; $Deleted = Convert-Checkpoint $Checkpoint
            Remove-VMSnapshot -VMSnapshot $Checkpoint -Confirm:$false
            Write-Result ([ordered]@{ deleted = $true; checkpoint = $Deleted }) $true
        }
        'vm_export' {
            $VM = Resolve-VM; $Path = Get-RequiredString 'export_host_path' 1024
            Export-VM -VM $VM -Path $Path
            Write-Result ([ordered]@{ vm_id = $VM.Id.ToString().ToLowerInvariant(); export_host_path = $Path; exported = $true }) $true
        }
        'vm_import' {
            $Path = Get-RequiredString 'config_host_path' 1024; $Mode = Get-ValidatedChoice 'mode' @('copy','register') 'copy'
            if ($Mode -eq 'register') { $VM = Import-VM -Path $Path -Register }
            else {
                $Arguments = @{ Path = $Path; Copy = $true }
                if (-not (Test-Value 'generate_new_id') -or $script:Params.generate_new_id -isnot [bool]) { throw [System.ArgumentException]::new("copy import requires explicit ID choice") }
                if ([bool]$script:Params.generate_new_id) { $Arguments.GenerateNewId = $true }
                if (Test-Value 'vhd_destination_host_path') { $Arguments.VhdDestinationPath = Get-RequiredString 'vhd_destination_host_path' 1024 }
                if (Test-Value 'vm_destination_host_path') { $Arguments.VirtualMachinePath = Get-RequiredString 'vm_destination_host_path' 1024 }
                $VM = Import-VM @Arguments
            }
            Write-Result (Convert-VM $VM) $true
        }
        'vm_migrate' {
            $VM = Resolve-VM; $Destination = Get-RequiredString 'destination_host' 253
            if ($Destination -ieq (Get-TargetHost) -or $Destination -ieq $env:COMPUTERNAME) { throw [System.ArgumentException]::new("migration destination equals source") }
            if (-not (Test-Value 'allow_credential_delegation') -or $script:Params.allow_credential_delegation -ne $true) { throw [System.InvalidOperationException]::new("migration delegation was not confirmed") }
            $Arguments = @{ VM = $VM; DestinationHost = $Destination; Confirm = $false }
            if (Test-Value 'include_storage') {
                if ($script:Params.include_storage -isnot [bool]) { throw [System.ArgumentException]::new("invalid structured boolean") }
                if ([bool]$script:Params.include_storage) { $Arguments.IncludeStorage = $true; $Arguments.DestinationStoragePath = Get-RequiredString 'destination_storage_host_path' 1024 }
            }
            $Moved = Move-VM @Arguments -PassThru
            Write-Result ([ordered]@{ vm_id = $VM.Id.ToString().ToLowerInvariant(); destination_host = $Destination; migrated = $true; result_name = $Moved.Name }) $true
        }
        'replication_status' {
            $VM = Resolve-VM; $Items = @(Get-VMReplication -VM $VM)
            Write-Result @($Items | ForEach-Object { Convert-Replication $_ })
        }
        'job_poll' {
            $VM = Resolve-VM; $Type = Get-ValidatedChoice 'job_type' @('vm_state','replication_state')
            $Desired = Get-RequiredString 'desired_state' 64
            $Allowed = if ($Type -eq 'vm_state') { @('Off','Running','Saved','Paused') } else { @('ReadyForInitialReplication','InitialReplicationInProgress','WaitingForInitialReplication','Replicating','Suspended','Error','Resynchronizing','FailedOver') }
            if ($Allowed -notcontains $Desired) { throw [System.ArgumentException]::new("unsupported poll state") }
            $Timeout = Get-ValidatedInteger 'poll_timeout_seconds' 1 600 60
            $Interval = Get-ValidatedInteger 'poll_interval_seconds' 1 30 5
            $Watch = [Diagnostics.Stopwatch]::StartNew(); $Completed = $false; $State = $null
            do {
                if ($Type -eq 'vm_state') { $State = (Get-VM -Id $VM.Id).State.ToString() }
                else { $State = (Get-VMReplication -VM (Get-VM -Id $VM.Id) | Select-Object -First 1).State.ToString() }
                if ($State -eq $Desired) { $Completed = $true; break }
                if ($Watch.Elapsed.TotalSeconds -lt $Timeout) { Start-Sleep -Seconds $Interval }
            } while ($Watch.Elapsed.TotalSeconds -lt $Timeout)
            Write-Result ([ordered]@{ job_type = $Type; vm_id = $VM.Id.ToString().ToLowerInvariant(); desired_state = $Desired; observed_state = $State; completed = $Completed; elapsed_seconds = [math]::Round($Watch.Elapsed.TotalSeconds, 3) })
        }
    }
} catch {
    [Console]::Error.WriteLine(('HYPERV_OPERATION_FAILED:{0}' -f $_.Exception.GetType().FullName))
    exit 1
}
