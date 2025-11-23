param([switch]$verbose)

$globalInterval = 0x0
$globalHCSPARAMSOffset = 0x4
$globalRTSOFF = 0x18
$userDefinedData = @{"DEV_" = @{"INTERVAL" = 0x4E20}}
$rwePath = "C:\Program Files (x86)\RW-Everything\Rw.exe"

function Dec-To-Hex($decimal) {
    return "0x$($decimal.ToString('X2'))"
}

function Get-Value-From-Address($address) {
    $address = Dec-To-Hex -decimal ([uint64]$address)
    $stdout = & $rwePath /Min /NoLogo /Stdout /Command="R32 $($address)" | Out-String
    $splitString = $stdout -split " "
    return [uint64]$splitString[-1]
}

function Get-Device-Addresses {
    $data = @{}
    $resources = Get-WmiObject -Class Win32_PNPAllocatedResource -ComputerName LocalHost -Namespace root\CIMV2
    foreach ($resource in $resources) {
        $deviceId = $resource.Dependent.Split("=")[1].Replace('"', '').Replace("\\", "\")
        $physicalAddress = $resource.Antecedent.Split("=")[1].Replace('"', '')
        if (-not $data.ContainsKey($deviceId) -and $deviceId -and $physicalAddress) {
            $data[$deviceId] = [uint64]$physicalAddress
        }
    }
    return $data
}

function Is-Admin {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Read-ControllerIMOD($controller, $deviceMap) {
    $deviceId = $controller.DeviceID
    if (-not $deviceMap.Contains($deviceId)) { return $null }

    $capabilityAddress = $deviceMap[$deviceId]
    $desiredInterval = $globalInterval
    $hcsparamsOffset = $globalHCSPARAMSOffset
    $rtsoff = $globalRTSOFF

    foreach ($hwid in $userDefinedData.Keys) {
        if ($deviceId -match $hwid) {
            $userDefinedController = $userDefinedData[$hwid]
            if ($userDefinedController.ContainsKey("INTERVAL")) { $desiredInterval = $userDefinedController["INTERVAL"] }
            if ($userDefinedController.ContainsKey("HCSPARAPS_OFFSET")) { $hcsparamsOffset = $userDefinedController["HCSPARAPS_OFFSET"] }
            if ($userDefinedController.ContainsKey("RTSOFF")) { $rtsoff = $userDefinedController["RTSOFF"] }
        }
    }

    $HCSPARAMSValue = Get-Value-From-Address -address ($capabilityAddress + $hcsparamsOffset)
    $HCSPARAMSBitmask = [Convert]::ToString($HCSPARAMSValue, 2)
    $maxIntrs = [Convert]::ToInt32($HCSPARAMSBitmask.Substring($HCSPARAMSBitmask.Length - 16, 8), 2)
    $RTSOFFValue = Get-Value-From-Address -address ($capabilityAddress + $rtsoff)
    $runtimeAddress = $capabilityAddress + $RTSOFFValue

    $imodValues = @()
    for ($i = 0; $i -lt $maxIntrs; $i++) {
        $interrupterAddress = $runtimeAddress + 0x24 + (0x20 * $i)
        $value = Get-Value-From-Address -address $interrupterAddress
        $imodValues += ($value -band 0xFFFF)
    }
    return $imodValues
}

function Write-ControllerIMOD($controller, $deviceMap, $newInterval) {
    $deviceId = $controller.DeviceID
    if (-not $deviceMap.Contains($deviceId)) { return $false }

    $capabilityAddress = $deviceMap[$deviceId]
    $hcsparamsOffset = $globalHCSPARAMSOffset
    $rtsoff = $globalRTSOFF

    foreach ($hwid in $userDefinedData.Keys) {
        if ($deviceId -match $hwid) {
            $userDefinedController = $userDefinedData[$hwid]
            if ($userDefinedController.ContainsKey("HCSPARAPS_OFFSET")) { $hcsparamsOffset = $userDefinedController["HCSPARAPS_OFFSET"] }
            if ($userDefinedController.ContainsKey("RTSOFF")) { $rtsoff = $userDefinedController["RTSOFF"] }
        }
    }

    $HCSPARAMSValue = Get-Value-From-Address -address ($capabilityAddress + $hcsparamsOffset)
    $HCSPARAMSBitmask = [Convert]::ToString($HCSPARAMSValue, 2)
    $maxIntrs = [Convert]::ToInt32($HCSPARAMSBitmask.Substring($HCSPARAMSBitmask.Length - 16, 8), 2)
    $RTSOFFValue = Get-Value-From-Address -address ($capabilityAddress + $rtsoff)
    $runtimeAddress = $capabilityAddress + $RTSOFFValue

    for ($i = 0; $i -lt $maxIntrs; $i++) {
        $interrupterAddress = $runtimeAddress + 0x24 + (0x20 * $i)
        $hexAddress = Dec-To-Hex -decimal ([uint64]$interrupterAddress)
        & $rwePath /Min /NoLogo /Stdout /Command="W32 $($hexAddress) $($newInterval)" | Out-Null
    }
    return $true
}

$AutoOptimize = $false
if ($args -contains "-AutoOptimize") {
    $AutoOptimize = $true
}

$FixedByteLength = 8
Add-Type -AssemblyName System.Windows.Forms, System.Drawing

$unknownDevices = Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Unknown' }
if ($unknownDevices) {
    foreach ($device in $unknownDevices) {
        try {
            Start-Process "pnputil.exe" -ArgumentList "/remove-device", "`"$($device.InstanceId)`"" -Wait -WindowStyle Hidden -ErrorAction Stop
        } 
        catch {
            Write-Warning "Failed to remove unknown device $($device.InstanceId): $_"
        }
    }
}

function Get-DeviceIRQCounts {
    $allocations = Get-CimInstance -ClassName Win32_PnPAllocatedResource -ErrorAction SilentlyContinue
    $irqCounts = @{}

    foreach ($allocation in $allocations) {
        try {
            $device = Get-CimInstance -CimInstance $allocation.Dependent -ErrorAction Stop
            
            if ($device.Name -like "*ACPI*") { continue }

            $resource = Get-CimInstance -CimInstance $allocation.Antecedent -ErrorAction Stop

            if ($resource.CimClass.CimClassName -eq 'Win32_IRQResource') {
                $deviceId = $device.DeviceID
                $formattedId = Get-PNPId $deviceId  
                
                if (-not $irqCounts.ContainsKey($formattedId)) {
                    $irqCounts[$formattedId] = 0
                }
                $irqCounts[$formattedId]++
            }
        }
        catch {
            Write-Warning "Error processing allocation: $_"
        }
    }

    return $irqCounts
}

function Create-ReservedCpuSetsUI {
    param(
        [int]$topPos
    )

    $script:reservedCheckboxes = @()

    $reservedGroupBox = New-Object System.Windows.Forms.GroupBox
    $reservedGroupBox.Text = "ReservedCpuSets"
    $reservedGroupBox.Width = 426
    $reservedGroupBox.Height = 300      
    $reservedGroupBox.Left = 10
    $reservedGroupBox.Top = $topPos
    $reservedGroupBox.ForeColor = [System.Drawing.Color]::FromArgb(219,219,219)
    $reservedGroupBox.BackColor = [System.Drawing.Color]::FromArgb(0,0,0)
    $reservedGroupBox.Font = New-Object System.Drawing.Font($fontCollection.Families[0], 11)
    $panel.Controls.Add($reservedGroupBox)

    $reservedPanel = New-Object System.Windows.Forms.Panel
    $reservedPanel.BackColor = [System.Drawing.Color]::FromArgb(0,0,0)
    $reservedPanel.BorderStyle = "FixedSingle"
    $reservedPanel.Width = 395
    $reservedPanel.Height = 208           
    $reservedPanel.Left = 10
    $reservedPanel.Top = 20
    $reservedPanel.AutoScroll = $true
    $reservedGroupBox.Controls.Add($reservedPanel)

    $logicalCount = [Environment]::ProcessorCount
    $maxCoresPerColumn = 8
    $columns = [Math]::Ceiling($logicalCount / $maxCoresPerColumn)
    $columnWidth = 100
    $rowHeight = 25

    function script:Get-ReservedCoresLocal {
        param([int]$count)
        $keyPath = "HKLM:\System\CurrentControlSet\Control\Session Manager\kernel"
        $valueName = "ReservedCpuSets"
        $reserved = New-Object bool[] $count

        if (Test-Path $keyPath) {
            $val = Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue
            if ($val -and $val.$valueName) {
                $bytes = $val.$valueName
                $bitIndex = 0
                for ($i = 0; $i -lt $bytes.Length; $i++) {
                    $byte = $bytes[$i]
                    for ($j = 0; $j -lt 8; $j++) {
                        if ($bitIndex -ge $count) { break }
                        $reserved[$bitIndex] = (($byte -band (1 -shl $j)) -ne 0)
                        $bitIndex++
                    }
                }
            }
        }
        return $reserved
    }

    function script:Apply-ReservedColoring {
        param([bool[]]$reservedArr)
        $colorDefault = [System.Drawing.Color]::FromArgb(219,219,219)
        $colorDim     = [System.Drawing.Color]::FromArgb(150,150,150)  
        $colorEffBlue = [System.Drawing.Color]::FromArgb(0,104,181)
        $colorReservedP = [System.Drawing.Color]::Yellow
        $colorReservedE = [System.Drawing.Color]::Green

        $colorCcd0      = [System.Drawing.Color]::Orange
        $colorCcd1      = [System.Drawing.Color]::Purple
        $colorCcd0Res   = [System.Drawing.Color]::Brown
        $colorCcd1Res   = [System.Drawing.Color]::Pink

        foreach ($device in $deviceList) {
            $ctrls = $deviceControls[$device]
            if (-not $ctrls) { continue }
            foreach ($chk in $ctrls.CheckBoxes) {
                $coreNum = [int]$chk.Tag
                if ($coreNum -ge $reservedArr.Length) { continue }
                $isReserved = $reservedArr[$coreNum]
                $affinityAllowed = $true
                try { $affinityAllowed = $chk.AutoCheck } catch { $affinityAllowed = $true }

                if ($script:IsDualCCDCpu) {
                    if ($script:Ccd0Cores -contains $coreNum) {
                        $chk.ForeColor = if ($isReserved) { $colorCcd0Res } else { $colorCcd0 }
                    } elseif ($script:Ccd1Cores -contains $coreNum) {
                        $chk.ForeColor = if ($isReserved) { $colorCcd1Res } else { $colorCcd1 }
                    } else {
                        $chk.ForeColor = if ($affinityAllowed) { $colorDefault } else { $colorDim }
                    }
                } else {
                    if ($isReserved) {
                        if (Is-PCore $coreNum) {
                            $chk.ForeColor = $colorReservedP
                        } else {
                            $chk.ForeColor = $colorReservedE
                        }
                    } else {
                        if (-not $affinityAllowed) {
                            $chk.ForeColor = $colorDim
                        } else {
                            if (Is-PCore $coreNum) {
                                $chk.ForeColor = $colorDefault
                            } else {
                                $chk.ForeColor = $colorEffBlue
                            }
                        }
                    }
                }
            }
        }
        foreach ($chk in $script:reservedCheckboxes) {
            $coreNum = [int]$chk.Tag
            if ($coreNum -ge $reservedArr.Length) { continue }
            $isReserved = $reservedArr[$coreNum]
            $affinityAllowed = $true
            try { $affinityAllowed = $chk.AutoCheck } catch { $affinityAllowed = $true }

            if ($script:IsDualCCDCpu) {
                if ($script:Ccd0Cores -contains $coreNum) {
                    $chk.ForeColor = if ($isReserved) { $colorCcd0Res } else { $colorCcd0 }
                } elseif ($script:Ccd1Cores -contains $coreNum) {
                    $chk.ForeColor = if ($isReserved) { $colorCcd1Res } else { $colorCcd1 }
                } else {
                    $chk.ForeColor = if ($affinityAllowed) { $colorDefault } else { $colorDim }
                }
            } else {
                if ($isReserved) {
                    if (Is-PCore $coreNum) {
                        $chk.ForeColor = $colorReservedP
                    } else {
                        $chk.ForeColor = $colorReservedE
                    }
                } else {
                    if (-not $affinityAllowed) {
                        $chk.ForeColor = $colorDim
                    } else {
                        if (Is-PCore $coreNum) {
                            $chk.ForeColor = $colorDefault
                        } else {
                            $chk.ForeColor = $colorEffBlue
                        }
                    }
                }
            }
        }
    }

    try {
        $initialReserved = script:Get-ReservedCoresLocal -count $logicalCount
    } catch {
        $initialReserved = New-Object bool[] $logicalCount
    }

    for ($col = 0; $col -lt $columns; $col++) {
        $startCPU = $col * $maxCoresPerColumn
        $endCPU = [Math]::Min($startCPU + $maxCoresPerColumn - 1, $logicalCount - 1)
        for ($row = 0; $row -lt ($endCPU - $startCPU + 1); $row++) {
            $cpuNumber = $startCPU + $row
            $chk = New-Object System.Windows.Forms.CheckBox

            $chk.Text = "CPU $cpuNumber"    
            $chk.Tag = $cpuNumber
            $chk.Width = 80
            $chk.Height = 20
            $chk.Left = 10 + $col * $columnWidth
            $chk.Top = $row * $rowHeight
            $chk.BackColor = [System.Drawing.Color]::FromArgb(0,0,0)
            $chk.FlatStyle = "Standard"
            $chk.Font = New-Object System.Drawing.Font($fontCollection.Families[0], 9)

            if ($cpuNumber -lt $initialReserved.Length) {
                $chk.Checked = $initialReserved[$cpuNumber]
            }

            if (Is-PCore $cpuNumber) {
                $chk.ForeColor = [System.Drawing.Color]::FromArgb(219,219,219)
            } else {
                $chk.ForeColor = [System.Drawing.Color]::FromArgb(0,104,181)
            }

            $reservedPanel.Controls.Add($chk)
            $script:reservedCheckboxes += $chk
        }
    }

    $btnSetReserved = New-Object System.Windows.Forms.Button
    $btnSetReserved.Text = "SET RESERVED CORES"
    $btnSetReserved.Width = 395
    $btnSetReserved.Height = 40
    $btnSetReserved.Left = 10
    $btnSetReserved.Top = $reservedPanel.Bottom + 12
    $btnSetReserved.BackColor = [System.Drawing.Color]::FromArgb(0,0,0)
    $btnSetReserved.ForeColor = [System.Drawing.Color]::FromArgb(255,255,255)
    $btnSetReserved.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $btnSetReserved.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(255,100,45)
    $btnSetReserved.FlatAppearance.BorderSize = 1
    $btnSetReserved.Font = New-Object System.Drawing.Font($fontCollection.Families[0], 11)
    $reservedGroupBox.Controls.Add($btnSetReserved)

    $btnSetReserved.Add_MouseEnter({
        $this.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(234,234,234)
        $this.FlatAppearance.BorderSize = 1
        $this.Refresh()
    })
    $btnSetReserved.Add_MouseLeave({
        $this.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(255,100,45)
        $this.FlatAppearance.BorderSize = 1
        $this.Refresh()
    })

    $btnSetReserved.Add_Click({
        $bytes = New-Object byte[] ([Math]::Ceiling($logicalCount / 8))

        foreach ($chk in $script:reservedCheckboxes) {
            $coreNum = [int]$chk.Tag
            if ($chk.Checked -and $coreNum -lt $logicalCount) {
                $byteIndex = [Math]::Floor($coreNum / 8)
                $bitIndex = $coreNum % 8
                $bytes[$byteIndex] = $bytes[$byteIndex] -bor (1 -shl $bitIndex)
            }
        }

        $keyPath = "HKLM:\System\CurrentControlSet\Control\Session Manager\kernel"
        $valueName = "ReservedCpuSets"

        try {
            if (-not (Test-Path $keyPath)) {
                New-Item -Path $keyPath -Force | Out-Null
            }
            Set-ItemProperty -Path $keyPath -Name $valueName -Value $bytes -Type Binary -ErrorAction Stop

            try {
                $newReserved = script:Get-ReservedCoresLocal -count $logicalCount
            } catch {
                $newReserved = New-Object bool[] $logicalCount
            }
            script:Apply-ReservedColoring -reservedArr $newReserved

            [System.Windows.Forms.MessageBox]::Show("ReservedCpuSets updated successfully!", "Success", "OK", "Information")
        }
        catch {
            [System.Windows.Forms.MessageBox]::Show("Failed to update ReservedCpuSets: $_", "Error", "OK", "Error")
        }
    })

    try {
        script:Apply-ReservedColoring -reservedArr $initialReserved
    } catch {
    }

    return $reservedGroupBox.Bottom + 10
}

function Get-CurrentDevicePolicy($registryPath) {
    $relativePath = Get-RelativeRegistryPath $registryPath
    $targetSubkey = "$relativePath\Device Parameters\Interrupt Management\Affinity Policy"
    try {
        $regKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($targetSubkey, $false)
        if ($regKey -ne $null) {
            $val = $regKey.GetValue("DevicePolicy", $null)
            if ($val -ne $null) { return [int]$val }
        }
    } catch { }
    return 0  
}

function Set-DevicePolicy($registryPath, $policy) {
    $relativePath = Get-RelativeRegistryPath $registryPath
    $targetSubkey = "$relativePath\Device Parameters\Interrupt Management\Affinity Policy"
    try {
        $regKey = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey(
            $targetSubkey, 
            [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree
        )
        if ($regKey -ne $null) {
            $regKey.SetValue("DevicePolicy", [int]$policy, [Microsoft.Win32.RegistryValueKind]::DWord)
            $regKey.Close()
            return $true
        }
    } catch { }
    return $false
}

$fontBytes = [System.Convert]::FromBase64String(
    "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djA3UGxhaW4AAQEBO/gQAPioAfioDAD4qQL4qQP4GASMDAH7MgwD9zQMBPt4+4T6AfofBR0ARXdpDRwPKQ8cESgRwRxHXhIAjwIAAQAIAA4AFAAaACAAJgAsADIAOAA+AEQASgBRAFgAXwBmAG0AcQB1AHkAfQCBAIUAiQCNAJEAlQCZAJ0AoQClAKkArQCxALUAuQC9AMEAxQDJAM0A0QDVAN0A5QDtAPUA/QEFAQ0BFAEaASABKAEvATYBPAFEAUwBUwFaAWEBZwFuAXUBewGCAZABmwGmAbYBwQHNAdsB5gHwAfwCBQIOAhwCJQIvAjsCRAJNAlsCZQJxAnoCgwKRApoCpAKwArkCwgLQAtkC4wLvAvgDAQMPAxgDIgMuAzcDQANJA1IDXQNlA3UDggOPA6EDrgO8A8wD2QPlA+wD8wP5BAAEBwQNBBQEGAQgBCkEMAQ7BEEESARSBFsEYgRpBHAEcwSrBLtuYnNwYWNlQS5hbHQxSy5hbHQxUi5hbHQxVi5hbHQxVy5hbHQxWC5hbHQxWS5hbHQxay5hbHQxdi5hbHQxdy5hbHQxeC5hbHQxZy5zaG9ydGouc2hvcnR5LnNob3J0cC5zaG9ydHEuc2hvcnRBLnNjQi5zY0Muc2NELnNjRS5zY0Yuc2NHLnNjSC5zY0kuc2NKLnNjSy5zY0wuc2NNLnNjTi5zY08uc2NQLnNjUS5zY1Iuc2NTLnNjVC5zY1Uuc2NWLnNjVy5zY1guc2NZLnNjWi5zY0Euc2NhbHQxSy5zY2FsdDFSLnNjYWx0MVYuc2NhbHQxVy5zY2FsdDFYLnNjYWx0MVkuc2NhbHQxemVyby5zY29uZS5zY3R3by5zY3RocmVlLnNjZm91ci5zY2ZpdmUuc2NzaXguc2NzZXZlbi5zY2VpZ2h0LnNjbmluZS5zY0FtYWNyb25FbWFjcm9uSXRpbGRlSW1hY3Jvbk9tYWNyb25VdGlsZGVVbWFjcm9uQWRpZXJlc2lzLmFsdDFBYWN1dGUuYWx0MUFncmF2ZS5hbHQxQWNpcmN1bWZsZXguYWx0MUF0aWxkZS5hbHQxQW1hY3Jvbi5hbHQxWWRpZXJlc2lzLmFsdDFZYWN1dGUuYWx0MUFyaW5nLmFsdDFBZGllcmVzaXMuc2NBYWN1dGUuc2NBZ3JhdmUuc2NBY2lyY3VtZmxleC5zY0F0aWxkZS5zY0FtYWNyb24uc2NFZGllcmVzaXMuc2NFYWN1dGUuc2NFZ3JhdmUuc2NFY2lyY3VtZmxleC5zY0VtYWNyb24uc2NJZGllcmVzaXMuc2NJYWN1dGUuc2NJZ3JhdmUuc2NJY2lyY3VtZmxleC5zY0l0aWxkZS5zY0ltYWNyb24uc2NPZGllcmVzaXMuc2NPYWN1dGUuc2NPZ3JhdmUuc2NPY2lyY3VtZmxleC5zY090aWxkZS5zY09tYWNyb24uc2NVZGllcmVzaXMuc2NVYWN1dGUuc2NVZ3JhdmUuc2NVY2lyY3VtZmxleC5zY1V0aWxkZS5zY1VtYWNyb24uc2NZZGllcmVzaXMuc2NZYWN1dGUuc2NTY2Fyb24uc2NaY2Fyb24uc2NOdGlsZGUuc2NDY2VkaWxsYS5zY0FyaW5nLnNjQWRpZXJlc2lzLnNjYWx0MUFhY3V0ZS5zY2FsdDFBZ3JhdmUuc2NhbHQxQWNpcmN1bWZsZXguc2NhbHQxQXRpbGRlLnNjYWx0MUFtYWNyb24uc2NhbHQxWWRpZXJlc2lzLnNjYWx0MVlhY3V0ZS5zY2FsdDFBcmluZy5zY2FsdDFhbWFjcm9uZW1hY3Jvbml0aWxkZWltYWNyb25vbWFjcm9udXRpbGRldW1hY3JvbkV1cm95ZW4uYWx0MWRvbGxhci5zY2NlbnQuc2NzdGVybGluZy5zY3llbi5zY0V1cm8uc2N5ZW4uc2NhbHQxUGFyYWdyYXBoYXQuYWx0MWF0LmFsdDJhdC5hbHQzYm94Q29weXJpZ2h0IChjKSAyMDA5IGJ5IFRpbm8gTWVpbmVydC4gQWxsIHJpZ2h0cyByZXNlcnZlZC5DUE1vbm9fdjA3IFBsYWluALoCAAEAFQBSAIgAtwDhAOsA/QEZARwBIQEtATQBOAE7AUYBXQFpAW4BcwGCAYcBkAGnAasBrwG4Ab0BzwHnAesB9AH6Af8CBAIJAjYCPgJFAl0CYQKoArICuQK/AsYCzQLTAtoC3gMCAwcDCwMQAxQDGwM4A3IDhwOpA60DtAO4A74DwgPJA84D0gPXA9wD6gP4BAEEIAQkBCgELAQwBDQEOQRDBE8EWARfBGUEaQRtBHQEfQSDBIgEjASTBJcEtATQBNwE4QTlBOwE9AT5BQQFEgUWBRwFIwUpBS4FNAU4BU0F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FwYLuvcTC393H3cHeISACzcdJgvm92TmA/kFFgvSeR0L8MUdC0EKAQsHJqkFCwcnwWALB/BwBQv3DEvLCwUvBgsFhwYLAAAAAooAAAAAAAAALwBZAE8ATQBgAGwATgBEAFQATQBNAF8ALwBFAEMAawBHAFsAUgAuAE0ANAAkAEIAPgBIABcATQBZABkAEAAiAB4ATwB4AEQATwAtAF0AWQBSAFIARQBaAHAAXwBIAGUAPABSAFcAYABXAFAAWwArAF4AXQBmAFIAfwBoADQAXABTACUAWwBZAFYAUQBNAD8AKwBHAFIAVwBZAGYAUgA+AGYAWQBeAG4AeABaAFwAfQBoAGMAjwBAAFgAVwB3AFMAawBoAEYAWQBTACUAWwBSAF4AKgBjAGsARQAfAEcANQBcAFUAYwBkAEAAagBmAGYAagBpALgA4wDjALUAtQCiALMA1gDkAC8ALwAvAC8ALwAvAGAAYABgAGAAYABUAFQAVABUAFQAVABDAEMAQwBDAEMAQwBNAE0ATQBNAE0ATQA+AD0AUgBIAEUATwAvABcAFwAXABcAFwAXAB4AHgAXAD4APgA+AD4APgA+AG4AbgBuAG4AbgB9AH0AfQB9AH0AfQBXAFcAVwBXAFcAVwBZAFkAWQBZAFkAWQBSAFIAaABeAFgAWQA+ACoAKgAqACoAKgAqADUANQAqAFoAWgBaAFoAWgBaAGQAZABkAGQAZABRAFEAUQBRAFEAUQBdAF0AXQBdAF0AXQBcAFwAXABcAFwAXABZAFkAaABWAF4AXgBaAFIAXAAUAD4AGAAeAGgAVwAxAFIAJwA0AQkBCQD7AQkA+wAgARUAwAECALMA+wClAPsApQDSAM8AYQBeAEwAnwBsAEoAywDJAMsAyQCiAJ8AfgB+ADsBEgESABwBCwEMAEMAVwDyAF8AXQB9AFMAaAA+AD4AeQB5AHEAXQBjAAAAPAAbACkAWQAOAFQAOgATAAoALACNABAAEgAoAF4AFAAXABoAFwBlADEAWABkAHAAdwAEAAT//gDLAL0AvACnAKUADgATAB3/HAABAAAACgAoAHQAAWxhdG4ACAAEAAAAAP//AAYAAAABAAIAAwAEAAUABmFhbHQAJmMyc2MALnNhbHQANHNtY3AAOnNzMDEAQHNzMDIARgAAAAIAAAABAAAAAQACAAAAAQAEAAAAAQADAAAAAQAFAAAAAQAGAAcAEAAYACAAKAAwADgAQAABAAAAAQIuAAMAAAABAzIAAQAAAAEAKAABAAAAAQDAAAEAAAABAVoAAQAAAAEBpAABAAAAAQHuAAID2ABNAFIAUwBUAFUAVgBXAFgAWQBaAFsAXABdAF4AXwBgAGEAYgBjAGQAZQBmAGcAaABpAGoAawBzAHQAdQB2AHcAeAB5AHoAewB8ALMAtAC1ALYAtwC4ALkAugC7ALwAvQC+AL8AwADBAMIAwwDEAMUAxgDHAMgAyQDKAMsAzADNAM4AzwDQANEA0gDTANQA1QDWAQoBCwEMAQ0BDgACA1QATgBzAHQAdQB2AHcAeAB5AHoAewB8AFIAUwBUAFUAVgBXAFgAWQBaAFsAXABdAF4AXwBgAGEAYgBjAGQAZQBmAGcAaABpAGoAawBaALMAtAC1ALYAtwC4ALkAugC7ALwAvQC+AL8AwADBAMIAwwDEAMUAxgDHAMgAyQDKAMsAzADNAM4AzwDQANEA0gDTANQA1QDWAQoBCwEMAQ0BDgACAsIAJgAdAB4AHwAgACEAIgAjAEkASgBLAEwAbABtAG4AbwBwAHEAcgCqAKsArACtAK4ArwCyALAAsQDXANgA2QDaANsA3ADdAN4A3wEJAQ8AAgJwACYAHQAeAB8AIAAhACIAIwBJAEoASwBMAGwAbQBuAG8AcABxAHIAqgCrAKwArQCuAK8AsgCwALEA1wDYANkA2gDbANwA3QDeAN8BCQEPAAICbgAFAE0ATgBQAFEATwACAmwAgwBTAFQAVQBWAFcAWABZAFoAWwBdAF4AXwBgAGEAYgBkAGUAZgBrAHMAdAB1AHYAdwB4AHkAegB7AHwAUgBTAFQAVQBWAFcAWQBaAF0AXgBfAGAAYwBkAGUAZgBrAFoAbABtAG4AbwBwAHEAcgC5ALoAuwC8AL0AvgC/AMAAwQDCAMMAxADFAMYAxwDIAMkAygDLAMwAzQDOAM8A0gDTANQA1QDXANgA2QDaANsA3ADdAN4A3wCzALQAtQC2ALcAuAC5ALoAuwC8AL0AvgC/AMAAwQDCAMMAxADFAMYAxwDIAMkAygDLAMwAzQDOAM8A0ADRANIA0wDUANUA1gEKAQsBDAEOAQ8AAQHiABoAOgBAAEYATABSAFgAXgBkAGoAcAB2AHwAggCIAI4AlACaAKAApgCsALIAuAC+AMQAygDQAAIAUgAdAAIAXAAeAAIAYwAfAAIAZwAgAAIAaAAhAAIAaQAiAAIAagAjAAIAWABNAAIAWwBOAAIAXABJAAIAYQBQAAIAYgBRAAIAZwBKAAIAaABLAAIAaQBMAAIAagBPAAIAswCqAAIAtACrAAIAtQCsAAIAtgCtAAIAtwCuAAIAuACvAAIA0ACyAAIA0QCwAAIA1gCxAAIBDQEJAAIABAADABwAAAAkAC0AGgCGAKkAJAEEAQgASAACAAIAJABIAAAA4AEIACUAAQAmAAMADQAUABgAGQAaABsAOABDAEQARQBSAFwAYwBnAGgAaQBqAIYAhwCIAIkAigCLAKMApACpALMAtAC1ALYAtwC4ANAA0QDWAQcBDQABAAUANAA3AD0APgBGAAIAFQAEAAwAAAAOABMACQAVABcADwAcABwAEgAkADMAEwA1ADYAIwA5ADwAJQA/AEIAKQBHAEgALQBSAFIALwBcAFwAMABjAGMAMQBnAGoAMgCMAKIANgClAKgATQCzALgAUQDQANEAVwDWANYAWQDgAQYAWgEIAQgAgQENAQ0AggABABoAAwANABQAGAAZABoAGwA0ADcAOAA9AD4AQwBEAEUARgCGAIcAiACJAIoAiwCjAKQAqQEH"
)


$tempFontPath = [System.IO.Path]::Combine(
    [System.IO.Path]::GetTempPath(), 
    "CPMono_v07_Plain.ttf"
)
[System.IO.File]::WriteAllBytes($tempFontPath, $fontBytes)

$fontCollection = New-Object System.Drawing.Text.PrivateFontCollection
$fontCollection.AddFontFile($tempFontPath)

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Collections.Generic;

public static class CpuInfo
{
    public const int RelationProcessorCore = 0;
    public const int ERROR_INSUFFICIENT_BUFFER = 122;

    [StructLayout(LayoutKind.Sequential)]
    public struct GROUP_AFFINITY
    {
        public ulong Mask;
        public ushort Group;
        public ushort Reserved1;
        public uint Reserved2;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESSOR_RELATIONSHIP
    {
        public byte Flags;
        public byte EfficiencyClass;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 20)]
        public byte[] Reserved;
        public ushort GroupCount;
        public GROUP_AFFINITY GroupMask;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX
    {
        public int Relationship;
        public int Size;
        public PROCESSOR_RELATIONSHIP Processor;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetLogicalProcessorInformationEx(
        int RelationshipType,
        IntPtr Buffer,
        ref int ReturnedLength
    );

    public static Dictionary<int, byte> GetCoreEfficiencyClasses()
    {
        int bufferSize = 0;
        var result = new Dictionary<int, byte>();
        int processorCount = Environment.ProcessorCount;

        if (!GetLogicalProcessorInformationEx(RelationProcessorCore, IntPtr.Zero, ref bufferSize) &&
            Marshal.GetLastWin32Error() != ERROR_INSUFFICIENT_BUFFER)
        {
            return result;
        }

        IntPtr buffer = Marshal.AllocHGlobal(bufferSize);
        try
        {
            if (GetLogicalProcessorInformationEx(RelationProcessorCore, buffer, ref bufferSize))
            {
                int offset = 0;
                while (offset < bufferSize)
                {
                    var header = (SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)Marshal.PtrToStructure(
                        new IntPtr(buffer.ToInt64() + offset), 
                        typeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)
                    );

                    if (header.Relationship == RelationProcessorCore)
                    {
                        byte effClass = header.Processor.EfficiencyClass;
                        ulong mask = header.Processor.GroupMask.Mask;
                        ushort group = header.Processor.GroupMask.Group;

                        for (int i = 0; i < 64; i++)
                        {
                            if ((mask & (1UL << i)) != 0)
                            {
                                int globalIndex = (int)(group * 64 + i);
                                if (globalIndex < processorCount && !result.ContainsKey(globalIndex))
                                {
                                    result[globalIndex] = effClass;
                                }
                            }
                        }
                    }
                    offset += header.Size;
                }
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }

        return result;
    }
}
"@

$global:coreEfficiencyMap = [CpuInfo]::GetCoreEfficiencyClasses()

$script:CoreEffUniqueCount = ($global:coreEfficiencyMap.Values | Select-Object -Unique).Count
$script:CoreMapIsHomogeneous = ($script:CoreEffUniqueCount -le 1)

function Is-DualCCD {
    $cpuName = (Get-WmiObject Win32_Processor).Name
    $dualCCDModels = @(
        "Ryzen 9 7900X",
        "Ryzen 9 7950X",
        "Ryzen 9 9900X",
        "Ryzen 9 9950X",
        "Ryzen 9 5900X",
        "Ryzen 9 5950X"
    )
    foreach ($model in $dualCCDModels) {
        if ($cpuName -like "*$model*") {
            return $true
        }
    }
    return $false
}
$script:IsDualCCDCpu = Is-DualCCD
$script:LogicalCoreCount = [Environment]::ProcessorCount
if ($script:IsDualCCDCpu) {
    $script:Ccd0Cores = 0..([Math]::Floor($script:LogicalCoreCount / 2) - 1)
    $script:Ccd1Cores = [Math]::Ceiling($script:LogicalCoreCount / 2)..($script:LogicalCoreCount - 1)
} else {
    $script:Ccd0Cores = @()
    $script:Ccd1Cores = @()
}

function Is-PCore {
    param([int]$index)
    if ($script:CoreMapIsHomogeneous -or -not $global:coreEfficiencyMap.ContainsKey($index)) {
        return $true
    }
    return ($global:coreEfficiencyMap[$index] -eq 1)
}

function Get-PNPId($registryPath) {
    $cleanPath = $registryPath -replace "^(Microsoft\.PowerShell\.Core\\Registry::)?(H[Kk]LM:\\|Hkey[_]?Local[_]?Machine\\|HKEY_LOCAL_MACHINE\\|HKLM:\\)", ""
    $cleanPath = $cleanPath -replace "^(System\\CurrentControlSet\\Enum\\)", ""
    $cleanPath = $cleanPath -replace "\\\\", "\"
    $parts = $cleanPath -split '\\'
    if ($parts.Count -ge 2) {
        $deviceId = $parts[1]  
        $idComponents = $deviceId -split '&'
        $vendor = $idComponents | Where-Object { $_ -like "VEN_*" } | Select-Object -First 1
        $device = $idComponents | Where-Object { $_ -like "DEV_*" } | Select-Object -First 1
        $formattedId = "$($parts[0])_$(if ($vendor) { $vendor } else { 'UNKNOWN_VEN' })_$(if ($device) { $device } else { 'UNKNOWN_DEV' })"
        return $formattedId
    }
    return $cleanPath
}

function Optimized-TestAudioDeviceParents {
    $allDevices = Get-PnpDevice -ErrorAction SilentlyContinue
    $audioEndpoints = $allDevices |
        Where-Object { $_.Class -eq 'AudioEndpoint' -and $_.Status -eq 'OK' }

    try {
        $scriptDir = if ($MyInvocation.MyCommand.Path) { Split-Path -Parent $MyInvocation.MyCommand.Path } else { Get-Location }
    } catch { $scriptDir = Get-Location }
    $logDir = Join-Path $scriptDir 'logs'
    if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
    $logFile = Join-Path $logDir 'logging.txt'
    if (-not (Test-Path $logFile)) { New-Item -Path $logFile -ItemType File -Force | Out-Null }
    function Write-Log {
        param($text)
        $time = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        Add-Content -Path $logFile -Value ("[$time] $text")
    }

    $getController = {
        param($instId)
        $current = $allDevices | Where-Object InstanceId -EQ $instId
        $lastUsb  = $null
        for ($depth = 0; $depth -lt 6 -and $current; $depth++) {
            $parentId = (Get-PnpDeviceProperty -InstanceId $current.InstanceId `
                         -KeyName 'DEVPKEY_Device_Parent' -ErrorAction SilentlyContinue).Data
            if (-not $parentId) { break }
            $current = $allDevices | Where-Object InstanceId -EQ $parentId
            if ($current.InstanceId -match 'PCI\\VEN_') {
                return Get-PNPId $current.InstanceId
            }
            elseif ($current.InstanceId -match 'USB\\') {
                $lastUsb = Get-PNPId $current.InstanceId
            }
        }
        return $lastUsb
    }

    foreach ($ep in $audioEndpoints) {
        $ctrlId = & $getController $ep.InstanceId

        switch -Wildcard ($ep.FriendlyName) {
            "*Headphone*"  { $type = "Headphones" }
            "*Microphone*" { $type = "Microphone" }
            "*Headset*"    { $type = "Headphones" }
            "*Earphone*"   { $type = "Headphones" }
            "*IEM*"        { $type = "Headphones" }
            "*Speaker*"    { $type = "Speakers" }
            default        { $type = "Audio" }  
        }

        try {
            $fn = if ($ep.FriendlyName) { $ep.FriendlyName } else { "<unknown>" }
            Write-Log "AudioEndpoint detected: FriendlyName='$fn' Type=$type ControllerID='$ctrlId'"
        } catch {}

        [PSCustomObject]@{
            AudioDevice  = $ep.FriendlyName
            AudioType    = $type
            ControllerID = $ctrlId
        }
    }
}

$audioParentsRaw = Optimized-TestAudioDeviceParents

$audioLookup = @{}

foreach ($row in $audioParentsRaw) {
    if ($row.ControllerID) {
        if (-not $audioLookup.ContainsKey($row.ControllerID)) {
            $audioLookup[$row.ControllerID] = [System.Collections.Generic.List[string]]::new()
        }
        $audioLookup[$row.ControllerID].Add($row.AudioType)
    }
}

function Get-RelativeRegistryPath($fullPath) {
    $path = $fullPath -replace "^Microsoft\.PowerShell\.Core\\Registry::", ""
    $path = $path -replace "^(HKLM:\\|HKEY_LOCAL_MACHINE\\)", ""
    return $path
}

function Get-RegistryInfo($deviceId) {
    $paths = @("HKLM:\SYSTEM\CurrentControlSet\Enum\$deviceId", "HKLM:\SYSTEM\ControlSet001\Enum\$deviceId")
    foreach ($path in $paths) {
        if (Test-Path $path) {
            try {
                $info = Get-ItemProperty -Path $path -ErrorAction Stop
                return @{ RegistryPath = $path; DeviceDesc = $info.DeviceDesc }
            }
            catch { continue }
        }
    }
    return @{ RegistryPath = "Not Found"; DeviceDesc = "Not Found" }
}

function Get-PciPortId($devicePath) {
    $parts = $devicePath -split '\\'
    if ($parts.Count -lt 3) { return $null }
    $lastPart = $parts[-1]
    $segments = $lastPart -split '&'
    if ($segments.Count -ge 3) { 
        return "$($segments[0])&$($segments[1])&$($segments[2])" 
    }
    return $null
}

function Is-GPU($deviceDesc) {
    return ($deviceDesc -match '(?i)(geforce|radeon)')
}

function Optimized-GetStorageDevices {
    $diskDrives = Get-PnpDevice -Class DiskDrive -ErrorAction SilentlyContinue |
                  Where-Object Status -eq 'OK'
    $regex = '(?i)(NVM|AHCI|SATA|SCSI|RAID)'

    Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Enum\PCI' -Recurse -ErrorAction SilentlyContinue |
    ForEach-Object {
        $props = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
        if ($props.DeviceDesc -and $props.DeviceDesc -match $regex) {
            $controllerInstanceId = ($_.PSPath -split '\\Enum\\')[1]

            $hasConnectedDisks = $false
            foreach ($disk in $diskDrives) {
                $current = $disk
                for ($depth = 0; $depth -lt 5 -and $current; $depth++) {
                    $parentId = (Get-PnpDeviceProperty -InstanceId $current.InstanceId `
                                 -KeyName 'DEVPKEY_Device_Parent' -ErrorAction SilentlyContinue).Data
                    if (-not $parentId) { break }
                    if ($parentId -eq $controllerInstanceId) {
                        $hasConnectedDisks = $true
                        break
                    }
                    $current = Get-PnpDevice -InstanceId $parentId -ErrorAction SilentlyContinue
                }
                if ($hasConnectedDisks) { break }
            }

            if ($hasConnectedDisks) {
                $displayName = if ($props.DeviceDesc -match '(?i)NVMe?') { 'SSD (NVME)' } else { 'SSD (SATA)' }
                [PSCustomObject]@{
                    Category     = 'SSD'
                    Role         = 'Storage'
                    DisplayName  = $displayName
                    RegistryPath = $_.PSPath
                    Description  = $props.DeviceDesc
                }
            }
        }
    }
}

function Find-NetworkAdapterPCI($device) {
    $pciRoot = "HKLM:\SYSTEM\CurrentControlSet\Enum\PCI"
    $devDesc = $device.Description
    if (-not $devDesc) { return $null }
    $pciDevices = Get-ChildItem -Path $pciRoot -Recurse -ErrorAction SilentlyContinue
    foreach ($item in $pciDevices) {
        try { $props = Get-ItemProperty -Path $item.PSPath -ErrorAction SilentlyContinue } catch { continue }
        if ($props -and $props.DeviceDesc) {
            $pciDesc = $props.DeviceDesc
            if (($pciDesc -like "*$devDesc*") -or ($devDesc -like "*$pciDesc*")) { return $item.PSPath }
        }
    }
    return $null
}

function Get-NetworkAdapterMSIRegistryPath($device) {
    if ($device.Category -eq "Network") {
         $pciKey = Find-NetworkAdapterPCI $device
         if ($pciKey -ne $null) { return $pciKey }
    }
    return $device.RegistryPath
}

function Get-NetworkAdapterAffinityRegistryPath($device) {
    if ($device.Category -eq "Network" -and $device.Role -eq "NDIS") { return $device.RegistryPath }
    elseif ($device.Category -eq "Network" -and $device.Role -eq "NetAdapterCx") {
         $pciKey = Find-NetworkAdapterPCI $device
         if ($pciKey -ne $null) { return $pciKey } else { return $device.RegistryPath }
    } else { return $device.RegistryPath }
}

function Get-AffinityHexForCore($assignmentCore, $logicalCores) {
    $numDigits = $FixedByteLength * 2
    $fmt = "{0:X$numDigits}"
    return $fmt -f (1 -shl $assignmentCore)
}

function Calculate-AffinityHex($checkboxes) {
    $mask = 0
    foreach ($chk in $checkboxes) {
        if ($chk.Checked) {
            $coreNum = [int]$chk.Tag
            $mask = $mask -bor (1 -shl $coreNum)
        }
    }
    return "0x" + $mask.ToString("X")
}

function Set-CheckboxesFromAffinity($checkboxes, $affinityHex) {
    try { $maskInt = [Convert]::ToInt64($affinityHex, 16) } catch { $maskInt = 0 }
    foreach ($chk in $checkboxes) {
        $core = [int]$chk.Tag
        if (($maskInt -band (1 -shl $core)) -ne 0) { $chk.Checked = $true } else { $chk.Checked = $false }
    }
}

function Get-CurrentAffinity($registryPath, $isNDIS) {
    if ($isNDIS) {
        try {
            $relPath = Get-RelativeRegistryPath $registryPath
            $regKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($relPath, $false)
            if ($regKey -ne $null) {
                $value = $regKey.GetValue("*RssBaseProcNumber", $null)
                if ($value -ne $null) { return "0x" + ([int]$value).ToString("X") }
            }
        } catch { }
        return "0x0"
    } else {
        try {
            $relativePath = Get-RelativeRegistryPath $registryPath
            $targetSubkey = "$relativePath\Device Parameters\Interrupt Management\Affinity Policy"
            $regKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($targetSubkey, $false)
            if ($regKey -ne $null) {
                $value = $regKey.GetValue("AssignmentSetOverride", $null)
                if ($value -ne $null) {
                    if ($value -isnot [byte[]]) { $value = [byte[]]$value }
                    [Int64]$maskInt = 0
                    for ($i = 0; $i -lt $value.Length; $i++) {
                        $maskInt += ([int]$value[$i]) -shl (8*$i)
                    }
                    return "0x" + $maskInt.ToString("X")
                }
            }
        } catch { }
        return "0x0"
    }
}

function Get-CurrentNumRssQueues {
    param([string]$registryPath)

    $relativePath = Get-RelativeRegistryPath $registryPath
    try {
        $regKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($relativePath, $false)
        if ($regKey -ne $null) {
            $val = $regKey.GetValue("*NumRssQueues", $null)
            if ($null -ne $val) {
                return [int]$val
            }
        }
        return $null
    } 
    catch {
        return $null
    }
}

function Get-CurrentPriority($registryPath) {
    try {
        $relativePath = Get-RelativeRegistryPath $registryPath
        $targetSubkey = "$relativePath\Device Parameters\Interrupt Management\Affinity Policy"
        $regKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($targetSubkey, $false)
        if ($regKey -ne $null) {
            $val = $regKey.GetValue("DevicePriority", $null)
            if ($val -ne $null) { return [int]$val }
        }
    } catch { }
    return 2
}

function Set-DevicePriority($registryPath, $priority) {
    try {
        $relativePath = Get-RelativeRegistryPath $registryPath
        $targetSubkey = "$relativePath\Device Parameters\Interrupt Management\Affinity Policy"
        $regKey = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey($targetSubkey, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree)
        if ($regKey -ne $null) {
            $regKey.SetValue("DevicePriority", [int]$priority, [Microsoft.Win32.RegistryValueKind]::DWord)
            $regKey.Close()
            return $true
        }
    } catch { }
    return $false
}

function Get-CurrentMSI($registryPath) {
    $relativePath = Get-RelativeRegistryPath $registryPath
    $subkeyPath = "$relativePath\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties"
    try {
        $regKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($subkeyPath, $false)
        if ($regKey -ne $null) {
            $msi = $regKey.GetValue("MSISupported", $null)
            $msgLimit = $regKey.GetValue("MessageNumberLimit", $null)
            if ($msi -eq $null) { $msi = 0 }
            if ($msgLimit -eq $null) { $msgLimit = "" }
            return @{ MSIEnabled = $msi; MessageLimit = $msgLimit }
        }
    } catch { }
    return @{ MSIEnabled = 0; MessageLimit = "" }
}

function Set-DeviceMSI($registryPath, $msiEnabled, $msgLimit) {
    $relativePath = Get-RelativeRegistryPath $registryPath
    $subkeyPath = "$relativePath\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties"
    try {
        $regKey = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey($subkeyPath, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree)
        if ($regKey -ne $null) {
            $regKey.SetValue("MSISupported", [int]$msiEnabled, [Microsoft.Win32.RegistryValueKind]::DWord)
            if ($msgLimit -eq "" -or $msgLimit -eq "Unlimited" -or ([int]$msgLimit) -eq 0) {
                if ($regKey.GetValue("MessageNumberLimit", $null) -ne $null) {
                    $regKey.DeleteValue("MessageNumberLimit", $false)
                }
            }
            else {
                $regKey.SetValue("MessageNumberLimit", [int]$msgLimit, [Microsoft.Win32.RegistryValueKind]::DWord)
            }
            $regKey.Close()
            return $true
        }
    } catch { }
    return $false
}

function Set-DeviceAffinity($registryPath, $affinityHex) {
    $relativePath = Get-RelativeRegistryPath $registryPath
    $targetSubkey = "$relativePath\Device Parameters\Interrupt Management\Affinity Policy"
    
    try {
        $maskInt = [Convert]::ToInt64($affinityHex, 16)
        
        if ($maskInt -ne 0) {
            $regKey = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey(
                $targetSubkey, 
                [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree
            )
            
            if ($regKey -ne $null) {
                $maskBytes = New-Object byte[] $FixedByteLength
                for ($i = 0; $i -lt $FixedByteLength; $i++) {
                    $maskBytes[$i] = ($maskInt -shr (8 * $i)) -band 0xFF
                }
                $regKey.SetValue("AssignmentSetOverride", $maskBytes, [Microsoft.Win32.RegistryValueKind]::Binary)
                $regKey.SetValue("DevicePolicy", 4, [Microsoft.Win32.RegistryValueKind]::DWord)
                $regKey.Close()
            }
        }
        return $true
    } 
    catch { 
        return $false
    }
}

function Get-HIDDevicesWithUSBControllers {
    $pnpCache = @{}
    function Resolve-DeviceInfo {
        param($instanceId)
        if (-not $pnpCache.ContainsKey($instanceId)) {
            $dev = Get-PnpDevice -InstanceId $instanceId -ErrorAction SilentlyContinue
            $friendly = if ($dev -and $dev.FriendlyName) { $dev.FriendlyName } else { $instanceId }
            $pnpCache[$instanceId] = @{ DeviceDesc = $friendly }
        }
        return $pnpCache[$instanceId]
    }

    function Get-DeviceTypeFromName {
        param([string]$productName)
        $name = $productName.ToLower()
        if ($name -match 'samson') { return $null }
        if ($name -eq "usb receiver") { return "Mouse" }
        if ($name -eq "usb device")  { return "Keyboard" }
        if ($name -eq "<none>")      { return "Keyboard" }
        if ($name -eq "wireless-receiver") { return "Mouse" }
        if ($name -match "usb gaming keyboard" -or $name -match "ctl") { return $null }

        $keyboardPatterns = @(
            "keyboard", "kbd", "kb", "he", "68", "75", "80", "63", "irok", "87", "96", "104", "820", "none",
            "60%", "65%", "tkl", "varmilo", "blackwidow", "keypad", "mechanical", "comard", "ak820",
            "cherry mx", "gateron", "keychron", "ducky", "leopold", "filco", "akko", "85",
            "gmmk", "iqunix", "nuphy", "apex pro", "k70", "k95", "optical switch", "RS",
            "75%", "fullsize", "tenkeyless", "macro pad", "keymap", "keycap", "switch"
        )

        $mousePatterns = @(
            "mouse", "ms", "8k", "2.4g", "4k", "pulsefire", "haste", "deathadder", "helios",
            "viper", "ajazz", "model o", "model d", "g pro", "g502", "g703", "g903", "Mad",
            "pulsar", "glorious", "zowie", "trackball", "sensor", "dpi", "gaming mouse",
            "g-wolves", "xm1", "skoll", "hsk", "viper mini", "orca", "superlight", "MCHOSE",
            "scroll wheel", "side button", "ergonomic", "ambidextrous", "fingertip", "MAJOR",
            "palm grip", "claw grip", "lod", "ips", "polling rate", "wlmouse", "xd"
        )

        $brandMapping = @{
            "varmilo"     = "Keyboard"
            "ajazz"       = "Mouse"
            "lamzu"       = "Mouse"
            "razer"       = "Mouse"
            "logitech"    = "Mouse"
            "steelseries" = "Mouse"
            "endgame"     = "Mouse"
            "finalmouse"  = "Mouse"
            "keychron"    = "Keyboard"
            "hexgears"    = "Keyboard"
            "ducky"       = "Keyboard"
            "leopold"     = "Keyboard"
            "filco"       = "Keyboard"
            "akko"        = "Keyboard"
            "iqunix"      = "Keyboard"
            "nuphy"       = "Keyboard"
            "corsair"     = "Keyboard"
            "hyperx"      = "Keyboard"
            "asus"        = "Keyboard"
            "msi"         = "Keyboard"
            "bloody"      = "Mouse"
            "roccat"      = "Mouse"
            "coolermaster"= "Keyboard"
        }

        $patternMatches = @{}
        foreach ($pattern in $keyboardPatterns) {
            try {
                $count = ([regex]::Matches($name, [regex]::Escape($pattern), [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)).Count
                if ($count -gt 0) { $patternMatches[$pattern] = $count }
            } catch {}
        }
        foreach ($pattern in $mousePatterns) {
            try {
                $count = ([regex]::Matches($name, [regex]::Escape($pattern), [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)).Count
                if ($count -gt 0) {
                    if ($patternMatches.ContainsKey($pattern)) { $patternMatches[$pattern] += $count } else { $patternMatches[$pattern] = $count }
                }
            } catch {}
        }
        foreach ($brand in $brandMapping.Keys) {
            try {
                $count = ([regex]::Matches($name, [regex]::Escape($brand), [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)).Count
                if ($count -gt 0) {
                    if ($patternMatches.ContainsKey($brand)) { $patternMatches[$brand] += $count } else { $patternMatches[$brand] = $count }
                }
            } catch {}
        }

        $countKeyboard = 0
        $countMouse = 0
        foreach ($k in $patternMatches.Keys) {
            $c = $patternMatches[$k]
            if ($keyboardPatterns -contains $k) {
                $countKeyboard += $c
            } elseif ($mousePatterns -contains $k) {
                $countMouse += $c
            } elseif ($brandMapping.ContainsKey($k)) {
                if ($brandMapping[$k] -eq "Keyboard") { $countKeyboard += $c } else { $countMouse += $c }
            }
        }

        if ($countMouse -gt $countKeyboard) { return "Mouse" }
        if ($countKeyboard -gt $countMouse) { return "Keyboard" }

        $keyboardEvidence = $keyboardPatterns | Where-Object { $patternMatches.ContainsKey($_) }
        $mouseEvidence = $mousePatterns | Where-Object { $patternMatches.ContainsKey($_) }
        $brandEvidence = $brandMapping.Keys | Where-Object { $patternMatches.ContainsKey($_) }

        if ($keyboardEvidence.Count -gt 0 -and $mouseEvidence.Count -eq 0) { return "Keyboard" }
        if ($mouseEvidence.Count -gt 0 -and $keyboardEvidence.Count -eq 0) { return "Mouse" }

        foreach ($brand in $brandEvidence) {
            $mapped = $brandMapping[$brand]
            if ($mapped -eq "Keyboard") { return "Keyboard" }
            if ($mapped -eq "Mouse")    { return "Mouse" }
        }

        foreach ($pattern in $keyboardPatterns) {
            if ($name -like "*$pattern*") { return "Keyboard" }
        }
        foreach ($pattern in $mousePatterns) {
            if ($name -like "*$pattern*") { return "Mouse" }
        }

        return $null
    }

    Add-Type -TypeDefinition @"
using System; using System.Text; using System.Runtime.InteropServices;
public class HidInterop {
    public const int DIGCF_PRESENT = 0x2;
    public const int DIGCF_DEVICEINTERFACE = 0x10;
    public static readonly Guid GUID_DEVINTERFACE_HID = new Guid("4D1E55B2-F16F-11CF-88CB-001111000030");
    [StructLayout(LayoutKind.Sequential)] public struct SP_DEVICE_INTERFACE_DATA {
        public int cbSize; public Guid InterfaceClassGuid; public int Flags; public IntPtr Reserved;
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    public struct SP_DEVICE_INTERFACE_DETAIL_DATA {
        public int cbSize;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string DevicePath;
    }
    [DllImport("setupapi.dll", SetLastError = true)]
    public static extern IntPtr SetupDiGetClassDevs(
        ref Guid ClassGuid, IntPtr Enumerator, IntPtr hwndParent, int Flags);
    [DllImport("setupapi.dll", SetLastError = true)]
    public static extern bool SetupDiEnumDeviceInterfaces(
        IntPtr DeviceInfoSet, IntPtr DeviceInfoData, ref Guid InterfaceClassGuid,
        int MemberIndex, ref SP_DEVICE_INTERFACE_DATA DeviceInterfaceData);
    [DllImport("setupapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
    public static extern bool SetupDiGetDeviceInterfaceDetail(
        IntPtr DeviceInfoSet, ref SP_DEVICE_INTERFACE_DATA DeviceInterfaceData,
        ref SP_DEVICE_INTERFACE_DETAIL_DATA DeviceInterfaceDetailData,
        int DeviceInterfaceDetailDataSize, out int RequiredSize, IntPtr DeviceInfoData);
    [DllImport("hid.dll", SetLastError = true)]
    public static extern bool HidD_GetProductString(
        IntPtr HidDeviceObject, byte[] Buffer, int BufferLength);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateFile(
        string lpFileName, uint dwDesiredAccess, uint dwShareMode,
        IntPtr lpSecurityAttributes, uint dwCreationDisposition,
        uint dwFlagsAndAttributes, IntPtr hTemplateFile);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);
}
"@

    try {
        $scriptDir = if ($MyInvocation.MyCommand.Path) { Split-Path -Parent $MyInvocation.MyCommand.Path } else { Get-Location }
    } catch {
        $scriptDir = Get-Location
    }
    $logDir = Join-Path $scriptDir 'logs'
    if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
    $logFile = Join-Path $logDir 'logging.txt'
    if (-not (Test-Path $logFile)) { New-Item -Path $logFile -ItemType File -Force | Out-Null }

    function Write-LogLocal { param($txt) $time = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss"); Add-Content -Path $logFile -Value "[$time] $txt" }

    $guid    = [HidInterop]::GUID_DEVINTERFACE_HID
    $flags   = [HidInterop]::DIGCF_PRESENT -bor [HidInterop]::DIGCF_DEVICEINTERFACE
    $devInfo = [HidInterop]::SetupDiGetClassDevs([ref]$guid, [IntPtr]::Zero, [IntPtr]::Zero, $flags)
    if ($devInfo -eq [IntPtr]::Zero) { return @() }

    $index = 0
    $results = @()
    $unmatchedDevices = @()
    $productStats = @{}

    while ($true) {
        $iface = New-Object HidInterop+SP_DEVICE_INTERFACE_DATA
        $iface.cbSize = [Runtime.InteropServices.Marshal]::SizeOf($iface)
        if (-not [HidInterop]::SetupDiEnumDeviceInterfaces($devInfo, [IntPtr]::Zero, [ref]$guid, $index, [ref]$iface)) {
            break
        }

        $detail       = New-Object HidInterop+SP_DEVICE_INTERFACE_DETAIL_DATA
        $detail.cbSize = if ([IntPtr]::Size -eq 8) { 8 } else { 5 }
        [int]$reqSize = 0
        if (-not [HidInterop]::SetupDiGetDeviceInterfaceDetail(
                $devInfo, [ref]$iface, [ref]$detail,
                [Runtime.InteropServices.Marshal]::SizeOf($detail),
                [ref]$reqSize, [IntPtr]::Zero)) {
            $index++; continue
        }
        $devicePath = $detail.DevicePath

        $handle  = [HidInterop]::CreateFile($devicePath,0,3,[IntPtr]::Zero,3,0,[IntPtr]::Zero)
        $product = "<none>"
        if ($handle -ne [IntPtr]::Zero -and $handle -ne -1) {
            $buf = New-Object Byte[] 256
            if ([HidInterop]::HidD_GetProductString($handle, $buf, $buf.Length)) {
                $product = [Text.Encoding]::Unicode.GetString($buf).Trim([char]0)
            }
            [HidInterop]::CloseHandle($handle) | Out-Null
        }

        try { Write-LogLocal "HID Device detected: ProductString='$product'" } catch {}

        $deviceType = Get-DeviceTypeFromName -productName $product

        $name = $product.ToLower()
        if ($name -match 'samson') {
            try { Write-LogLocal "Ignoring Samson device: $product" } catch {}
            $index++
            continue
        }

        $patternDetails = @{ }

        $klist = @(
            "keyboard", "kbd", "kb", "he", "68", "75", "80", "63", "irok", "87", "96", "104", "none",
            "60%", "65%", "tkl", "varmilo", "blackwidow", "keypad", "mechanical", "comard",
            "cherry mx", "gateron", "keychron", "ducky", "leopold", "filco", "akko",
            "gmmk", "iqunix", "nuphy", "apex pro", "k70", "k95", "optical switch", "RS",
            "75%", "fullsize", "tenkeyless", "macro pad", "keymap", "keycap", "switch"
        )
        $mlist = @(
            "mouse", "ms", "8k", "2.4g", "4k", "pulsefire", "haste", "deathadder", "helios",
            "viper", "ajazz", "model o", "model d", "g pro", "g502", "g703", "g903", "MAD",
            "pulsar", "glorious", "zowie", "trackball", "sensor", "dpi", "gaming mouse",
            "g-wolves", "xm1", "skoll", "hsk", "viper mini", "orca", "superlight",
            "scroll wheel", "side button", "ergonomic", "ambidextrous", "fingertip",
            "palm grip", "claw grip", "lod", "ips", "polling rate", "wlmouse", "xd", "MAJOR"
        )
        $brandMap = @{
            "varmilo"     = "Keyboard"
            "ajazz"       = "Mouse"
            "lamzu"       = "Mouse"
            "razer"       = "Mouse"
            "logitech"    = "Mouse"
            "steelseries" = "Mouse"
            "endgame"     = "Mouse"
            "finalmouse"  = "Mouse"
            "keychron"    = "Keyboard"
            "hexgears"    = "Keyboard"
            "ducky"       = "Keyboard"
            "leopold"     = "Keyboard"
            "filco"       = "Keyboard"
            "akko"        = "Keyboard"
            "iqunix"      = "Keyboard"
            "nuphy"       = "Keyboard"
            "corsair"     = "Keyboard"
            "hyperx"      = "Keyboard"
            "asus"        = "Keyboard"
            "msi"         = "Keyboard"
            "bloody"      = "Mouse"
            "roccat"      = "Mouse"
            "coolermaster"= "Keyboard"
        }

        foreach ($p in $klist) {
            try {
                $c = ([regex]::Matches($name, [regex]::Escape($p), [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)).Count
                if ($c -gt 0) { $patternDetails[$p] = $c }
            } catch {}
        }
        foreach ($p in $mlist) {
            try {
                $c = ([regex]::Matches($name, [regex]::Escape($p), [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)).Count
                if ($c -gt 0) {
                    if ($patternDetails.ContainsKey($p)) { $patternDetails[$p] += $c } else { $patternDetails[$p] = $c }
                }
            } catch {}
        }
        foreach ($p in $brandMap.Keys) {
            try {
                $c = ([regex]::Matches($name, [regex]::Escape($p), [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)).Count
                if ($c -gt 0) {
                    if ($patternDetails.ContainsKey($p)) { $patternDetails[$p] += $c } else { $patternDetails[$p] = $c }
                }
            } catch {}
        }

        if ($patternDetails.Count -gt 0) {
            $detailStrings = $patternDetails.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }

            $mappingList = @()
            foreach ($k in $patternDetails.Keys) {
                if ($klist -contains $k) {
                    $mappingList += "$k=Keyboard"
                } elseif ($mlist -contains $k) {
                    $mappingList += "$k=Mouse"
                } elseif ($brandMap.ContainsKey($k)) {
                    $mappingList += "$k=$($brandMap[$k])"
                } else {
                    $mappingList += "$k=Unknown"
                }
            }

            try { Write-LogLocal "  Pattern matches: $($detailStrings -join '; ')" } catch {}
            try { Write-LogLocal "  Pattern -> Type mapping: $($mappingList -join '; ')" } catch {}

            $countKeyboard = 0
            $countMouse = 0
            foreach ($k in $patternDetails.Keys) {
                $c = $patternDetails[$k]
                if ($klist -contains $k) {
                    $countKeyboard += $c
                } elseif ($mlist -contains $k) {
                    $countMouse += $c
                } elseif ($brandMap.ContainsKey($k)) {
                    if ($brandMap[$k] -eq "Keyboard") { $countKeyboard += $c } else { $countMouse += $c }
                }
            }
            try { Write-LogLocal "  Totals => Keyboard=$countKeyboard Mouse=$countMouse" } catch {}
        } else {
            try { Write-LogLocal "  Pattern matches: <none>" } catch {}
            $unmatchedDevices += [PSCustomObject]@{ Product = $product }
        }

        if (-not $deviceType) {
            try { Write-LogLocal "  Determined DeviceType: <none>" } catch {}
        } else {
            try { Write-LogLocal "  Determined DeviceType: $deviceType" } catch {}
        }

        if (-not $productStats.ContainsKey($product)) {
            $productStats[$product] = @{
                Occurrences = 0
                Classification = @{ Keyboard = 0; Mouse = 0; None = 0 }
                TotalPatternMatches = 0
                PatternTotals = @{}
            }
        }
        $productStats[$product].Occurrences++
        $classKey = if ($deviceType) { $deviceType } else { 'None' }
        $productStats[$product].Classification[$classKey]++
        $sumMatches = 0
        foreach ($k in $patternDetails.Keys) {
            $c = $patternDetails[$k]
            $sumMatches += $c
            if (-not $productStats[$product].PatternTotals.ContainsKey($k)) { $productStats[$product].PatternTotals[$k] = 0 }
            $productStats[$product].PatternTotals[$k] += $c
        }
        $productStats[$product].TotalPatternMatches += $sumMatches

        $inst = if ($devicePath -match '^\\\\\?\\hid#([^#]+)#') {
            ($Matches[1] -replace '#','\').ToUpper()
        } else { $null }

        $ctrls = @()
        if ($inst) {
            Get-WmiObject Win32_USBControllerDevice -ErrorAction SilentlyContinue |
              Where-Object { $_.Dependent -match [regex]::Escape($inst) } |
              ForEach-Object {
                  $cid  = ([regex]::Match($_.Antecedent,'DeviceID="([^"]+)"')).Groups[1].Value
                  $info = Resolve-DeviceInfo $cid
                  $ctrls += [PSCustomObject]@{
                      ControllerPNPID = $cid
                      ControllerName  = $info.DeviceDesc
                  }
              }
            $ctrls = $ctrls | Sort-Object ControllerPNPID -Unique
        }

        $results += [PSCustomObject]@{
            ProductString    = $product
            DeviceType       = $deviceType
            DevicePath       = $devicePath
            DeviceInstanceID = $inst
            USBControllers   = if ($ctrls) { $ctrls } else { $null }
            PatternDetails   = $patternDetails
            MatchTotal       = if ($patternDetails.Values) { ($patternDetails.Values | Measure-Object -Sum).Sum } else { 0 }
        }

        $index++
    }

    if ($productStats.Keys.Count -gt 0) {
        try { Write-LogLocal "SUMMARY: HID product statistics (aggregated by ProductString):" } catch {}
        foreach ($prod in $productStats.Keys) {
            $entry = $productStats[$prod]
            $occ = $entry.Occurrences
            $kbd = $entry.Classification.Keyboard
            $ms  = $entry.Classification.Mouse
            $n   = $entry.Classification.None
            $totalMatches = $entry.TotalPatternMatches
            try { Write-LogLocal "  - Product='$prod' Occurrences=$occ Keyboard=$kbd Mouse=$ms None=$n TotalPatternMatches=$totalMatches" } catch {}
            if ($entry.PatternTotals.Keys.Count -gt 0) {
                $pt = $entry.PatternTotals.GetEnumerator() | Sort-Object -Property Value -Descending | ForEach-Object { "$($_.Key)=$($_.Value)" }
                try { Write-LogLocal "      PatternTotals: $($pt -join '; ')" } catch {}
            }
        }
    } else {
        try { Write-LogLocal "SUMMARY: No HID products detected." } catch {}
    }

    return $results
}

function Get-USBControllers {
    $assocs = Get-WmiObject Win32_USBControllerDevice -ErrorAction SilentlyContinue

    $pnpCache = @{}
    function Resolve-DeviceInfo {
        param($instanceId)
        if (-not $pnpCache.ContainsKey($instanceId)) {
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\$instanceId"
            if (Test-Path $regPath) {
                $desc = (Get-ItemProperty $regPath -ErrorAction SilentlyContinue).DeviceDesc
                $pnpCache[$instanceId] = @{ RegistryPath = $regPath; DeviceDesc = $desc }
            } else {
                $w = Get-PnpDevice -InstanceId $instanceId -ErrorAction SilentlyContinue
                $friendly = if ($w -and $w.FriendlyName) { $w.FriendlyName } else { $instanceId }
                $pnpCache[$instanceId] = @{ RegistryPath = "PNP:$instanceId"; DeviceDesc = $friendly }
            }
        }
        return $pnpCache[$instanceId]
    }

    try {
        $scriptDir = if ($MyInvocation.MyCommand.Path) { Split-Path -Parent $MyInvocation.MyCommand.Path } else { Get-Location }
    } catch { $scriptDir = Get-Location }
    $logDir = Join-Path $scriptDir 'logs'
    if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
    $logFile = Join-Path $logDir 'logging.txt'
    if (-not (Test-Path $logFile)) { New-Item -Path $logFile -ItemType File -Force | Out-Null }

    function Write-LogLocal { param($txt) $time = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss"); Add-Content -Path $logFile -Value "[$time] $txt" }

    try {
        $lines = Get-Content -Path $logFile -ErrorAction SilentlyContinue
        if ($lines) {
            $out = New-Object System.Collections.Generic.List[string]
            $seenAssigned = @{}
            foreach ($line in $lines) {
                if ($line -match 'Get-USBControllers: Assigned audio role ''?([^'']+)''? to controller ''?([^'']+)''?') {
                    $role = $Matches[1]
                    $controller = $Matches[2]
                    $key = "$controller|$role"
                    if (-not $seenAssigned.ContainsKey($key)) {
                        $seenAssigned[$key] = $true
                        $out.Add($line)
                    } else {
                    }
                } else {
                    $out.Add($line)
                }
            }
            if ($out.Count -ne $lines.Count) {
                Set-Content -Path $logFile -Value $out -Encoding UTF8
                Write-LogLocal "Get-USBControllers: Cleaned duplicate historical 'Assigned audio role' log entries."
            }
        }
    } catch {}

    $hidDevices = Get-HIDDevicesWithUSBControllers
    $hidRoleMap = @{}
    $productAggregation = @{}

    foreach ($device in $hidDevices) {
        if (-not $device.USBControllers) { continue }

        $prod = $device.ProductString
        if (-not $productAggregation.ContainsKey($prod)) {
            $productAggregation[$prod] = @{
                Occurrences = 0
                Classification = @{ Keyboard = 0; Mouse = 0; None = 0 }
                TotalPatternMatches = 0
                PatternTotals = @{}
            }
        }
        $productAggregation[$prod].Occurrences++
        $ck = if ($device.DeviceType) { $device.DeviceType } else { 'None' }
        $productAggregation[$prod].Classification[$ck]++
        $mt = 0
        try { $mt = [int]$device.MatchTotal } catch {}
        $productAggregation[$prod].TotalPatternMatches += $mt
        if ($device.PatternDetails) {
            foreach ($k in $device.PatternDetails.Keys) {
                $c = $device.PatternDetails[$k]
                if (-not $productAggregation[$prod].PatternTotals.ContainsKey($k)) { $productAggregation[$prod].PatternTotals[$k] = 0 }
                $productAggregation[$prod].PatternTotals[$k] += $c
            }
        }

        foreach ($controller in $device.USBControllers) {
            $pnpId = Get-PNPId $controller.ControllerPNPID
            if (-not $hidRoleMap.ContainsKey($pnpId)) {
                $hidRoleMap[$pnpId] = @{
                    Keyboard = $false
                    Mouse    = $false
                }
            }
            if ($device.DeviceType -eq 'Keyboard') {
                $hidRoleMap[$pnpId].Keyboard = $true
            } elseif ($device.DeviceType -eq 'Mouse') {
                $hidRoleMap[$pnpId].Mouse = $true
            }
        }
    }

    $controllerMap = @{}
    $loggedRoleKeys = @{}    

    foreach ($assoc in $assocs) {
        $ctrlId = ([regex]::Match($assoc.Antecedent, 'DeviceID="([^"]+)"')).Groups[1].Value
        $devId  = ([regex]::Match($assoc.Dependent,  'DeviceID="([^"]+)"')).Groups[1].Value
        $ctrlKey = Get-PNPId $ctrlId
        $ctrlInfo = Resolve-DeviceInfo $ctrlId

        if (-not $controllerMap.ContainsKey($ctrlKey)) {
            $controllerMap[$ctrlKey] = @{
                RegistryPath = $ctrlInfo.RegistryPath
                Description  = $ctrlInfo.DeviceDesc
                Roles        = [System.Collections.Generic.HashSet[string]]::new()
            }
        }

        $devInfo = Resolve-DeviceInfo $devId
        if ($devInfo.DeviceDesc -match '(?i)game controller|Xbox') {
            $controllerMap[$ctrlKey].Roles.Add('Controller') | Out-Null
        }

        if ($audioLookup -and $audioLookup.ContainsKey($ctrlKey)) {
            foreach ($atype in $audioLookup[$ctrlKey] | Select-Object -Unique) {
                if (-not $controllerMap[$ctrlKey].Roles.Contains($atype)) {
                    $controllerMap[$ctrlKey].Roles.Add($atype) | Out-Null
                    $logKey = "$ctrlKey|$atype"
                    if (-not $loggedRoleKeys.ContainsKey($logKey)) {
                        $loggedRoleKeys[$logKey] = $true
                        try {
                            Write-LogLocal "Get-USBControllers: Assigned audio role '$atype' to controller '$ctrlKey' (desc='$($controllerMap[$ctrlKey].Description)')"
                        } catch {}
                    }
                } else {
                }
            }
        }
    }

    foreach ($ctrlKey in $hidRoleMap.Keys) {
        if (-not $controllerMap.ContainsKey($ctrlKey)) { continue }
        if ($hidRoleMap[$ctrlKey].Keyboard) {
            if (-not $controllerMap[$ctrlKey].Roles.Contains('Keyboard')) {
                $controllerMap[$ctrlKey].Roles.Add('Keyboard') | Out-Null
                $logKey = "$ctrlKey|Keyboard"
                if (-not $loggedRoleKeys.ContainsKey($logKey)) {
                    $loggedRoleKeys[$logKey] = $true
                    Write-LogLocal "Get-USBControllers: Assigned HID role 'Keyboard' to controller '$ctrlKey' (desc='$($controllerMap[$ctrlKey].Description)')"
                }
            }
        }
        if ($hidRoleMap[$ctrlKey].Mouse) {
            if (-not $controllerMap[$ctrlKey].Roles.Contains('Mouse')) {
                $controllerMap[$ctrlKey].Roles.Add('Mouse') | Out-Null
                $logKey = "$ctrlKey|Mouse"
                if (-not $loggedRoleKeys.ContainsKey($logKey)) {
                    $loggedRoleKeys[$logKey] = $true
                    Write-LogLocal "Get-USBControllers: Assigned HID role 'Mouse' to controller '$ctrlKey' (desc='$($controllerMap[$ctrlKey].Description)')"
                }
            }
        }
    }

    try {
        Write-LogLocal "Get-USBControllers: Final controller map collected for GUI:"
        foreach ($entry in $controllerMap.GetEnumerator()) {
            $key = $entry.Key
            $desc = $entry.Value.Description
            $roles = if ($entry.Value.Roles.Count -gt 0) { ($entry.Value.Roles | Sort-Object | ForEach-Object { $_ }) -join '/' } else { '<none>' }
            Write-LogLocal "  Controller='$key' Roles='$roles' Path='$($entry.Value.RegistryPath)' Desc='$desc'"
        }
    } catch {}

    $usbDevices = @()
    foreach ($entry in $controllerMap.GetEnumerator()) {
        $rolesArr = @()
        foreach ($r in $entry.Value.Roles) { $rolesArr += $r }
        if ($rolesArr.Count -eq 0) { continue }
        $usbDevices += [PSCustomObject]@{
            Category     = 'USB'
            Roles        = $rolesArr
            DisplayName  = "USB Host Controller (" + ($rolesArr -join "/") + ")"
            RegistryPath = $entry.Value.RegistryPath
            Description  = $entry.Value.Description
        }
    }

    return $usbDevices
}

function Get-AudioEndpointMappings {
    $allDevices = Get-PnpDevice -ErrorAction SilentlyContinue
    $controllers = $allDevices | Where-Object { 
        $_.FriendlyName -like '*Audio Controller*' -and $_.Status -eq 'OK' 
    }
    $endpoints = Get-PnpDevice -Class AudioEndpoint -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'OK' }

    try {
        $scriptDir = if ($MyInvocation.MyCommand.Path) { Split-Path -Parent $MyInvocation.MyCommand.Path } else { Get-Location }
    } catch { $scriptDir = Get-Location }
    $logDir = Join-Path $scriptDir 'logs'
    if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
    $logFile = Join-Path $logDir 'logging.txt'
    if (-not (Test-Path $logFile)) { New-Item -Path $logFile -ItemType File -Force | Out-Null }
    function Write-Log {
        param($text)
        $time = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        Add-Content -Path $logFile -Value ("[$time] $text")
    }

    $controllerMap = @{}
    foreach ($ep in $endpoints) {
        $parent1 = Get-PnpDeviceProperty -InstanceId $ep.InstanceId -KeyName 'DEVPKEY_Device_Parent' -ErrorAction SilentlyContinue
        if (-not $parent1) { continue }
        
        $parent2 = Get-PnpDeviceProperty -InstanceId $parent1.Data -KeyName 'DEVPKEY_Device_Parent' -ErrorAction SilentlyContinue
        if (-not $parent2) { continue }

        $controller = $controllers | Where-Object { $_.InstanceId -eq $parent2.Data }
        if (-not $controller) { continue }

        $type = "Unknown Audio Device"
        if ($ep.FriendlyName -match 'headphone|headset|earphone|iem') { $type = "Headphones" }
        elseif ($ep.FriendlyName -match 'microphone|mic') { $type = "Microphone" }
        elseif ($ep.FriendlyName -match 'speaker|dynamic') { $type = "Speakers" }

        $pnpId = Get-PNPId $controller.InstanceId
        if (-not $controllerMap.ContainsKey($pnpId)) {
            $controllerMap[$pnpId] = @{
                Types = @()
                Descriptions = @()
            }
        }
        if ($type -ne "Unknown Audio Device") {
            $controllerMap[$pnpId].Types += $type
            $controllerMap[$pnpId].Descriptions += $ep.FriendlyName
            try {
                $fn = if ($ep.FriendlyName) { $ep.FriendlyName } else { "<unknown>" }
                Write-Log "Audio mapping: ControllerPNP='$pnpId' EndpointName='$fn' MatchedType='$type'"
            } catch {}
        } else {
            try {
                $fn = if ($ep.FriendlyName) { $ep.FriendlyName } else { "<unknown>" }
                Write-Log "Audio mapping: ControllerPNP='$pnpId' EndpointName='$fn' MatchedType='Unknown'"
            } catch {}
        }
    }

    return $controllerMap
}

function Get-PCIDevices {
    $pciRoot   = 'HKLM:\SYSTEM\CurrentControlSet\Enum\PCI'
    $allPciKey = Get-ChildItem -Path $pciRoot -Recurse -ErrorAction SilentlyContinue

    $pciDescMap = @{}
    foreach ($key in $allPciKey) {
        $props = Get-ItemProperty -Path $key.PSPath -ErrorAction SilentlyContinue
        if ($props.DeviceDesc) {
            $pciDescMap[$key.PSPath] = $props.DeviceDesc
        }
    }

    try {
        $scriptDir = if ($MyInvocation.MyCommand.Path) { Split-Path -Parent $MyInvocation.MyCommand.Path } else { Get-Location }
    } catch { $scriptDir = Get-Location }
    $logDir = Join-Path $scriptDir 'logs'
    if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
    $logFile = Join-Path $logDir 'logging.txt'
    if (-not (Test-Path $logFile)) { New-Item -Path $logFile -ItemType File -Force | Out-Null }

    function Write-LogLocal { param($txt) $time = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss"); Add-Content -Path $logFile -Value "[$time] $txt" }

    $gpuPorts   = New-Object System.Collections.Generic.HashSet[string]
    $gpuDevices = @()
    foreach ($psPath in $pciDescMap.Keys) {
        $desc = $pciDescMap[$psPath]
        if ($desc -match '(?i)(geforce|radeon)') {
            $segments = ($psPath -split '\\')[-1] -split '&'
            $portId   = $segments[0..2] -join '&'
            $gpuPorts.Add($portId) | Out-Null
            $gpuDevices += [PSCustomObject]@{
                Category    = 'PCI'
                Role        = 'GPU'
                DisplayName = 'GPU'
                RegistryPath= $psPath
                Description = $desc
                Port        = $portId
            }
            try { Write-LogLocal "Get-PCIDevices: GPU detected: Path='$psPath' Port='$portId' Desc='$desc'" } catch {}
        }
    }

    $audioMappings = $audioLookup   
    $audioDevices  = @()
    $ignoredAudio  = @()

    foreach ($psPath in $pciDescMap.Keys) {
        $desc = $pciDescMap[$psPath]

        if ($desc -match '(?i)Audio Controller') {
            $segments = ($psPath -split '\\')[-1] -split '&'
            $portId   = $segments[0..2] -join '&'
            $pnpId    = Get-PNPId $psPath

            if ($audioMappings -and $audioMappings.ContainsKey($pnpId)) {
                $types = $audioMappings[$pnpId] |
                         Where-Object { $_ -ne 'Unknown Audio Device' } |
                         Sort-Object -Unique
                if ($types.Count) {
                    $display = 'Audio (Audio Controller) - ' + ($types -join '/')
                    $audioDevices += [PSCustomObject]@{
                        Category    = 'PCI'
                        Role        = 'Audio'
                        DisplayName = $display
                        RegistryPath= $psPath
                        Description = $desc
                        Port        = $portId
                        AudioTypes  = $types
                        PNPID       = $pnpId
                    }
                    try { Write-LogLocal "Get-PCIDevices: INCLUDED Audio controller -> PNPID='$pnpId' Path='$psPath' Port='$portId' Desc='$desc' Types='$(if ($types) { $types -join '/' } else { '<none>' })'" } catch {}
                } else {
                    $ignoredAudio += @{ Path = $psPath; PNPID = $pnpId; Desc = $desc; Reason = "Mapped but no usable audio types" }
                    try { Write-LogLocal "Get-PCIDevices: IGNORED Audio controller (mapped but no usable types) -> PNPID='$pnpId' Path='$psPath' Desc='$desc'" } catch {}
                }
            } else {
                $ignoredAudio += @{ Path = $psPath; PNPID = $pnpId; Desc = $desc; Reason = "No audio endpoint mapping found" }
                try { Write-LogLocal "Get-PCIDevices: IGNORED Audio controller (no mapping) -> PNPID='$pnpId' Path='$psPath' Desc='$desc'" } catch {}
            }
        }
    }

    foreach ($a in $audioDevices) {
        if ($a.Port -and $gpuPorts.Contains($a.Port) -and $a.AudioTypes -and $a.AudioTypes.Count -gt 0) {
            $oldDisplay = $a.DisplayName
            $a.DisplayName = 'Audio - GPU'
            $a.Role        = 'AudioGPU'
            try { Write-LogLocal "Get-PCIDevices: Audio controller upgraded to Audio-GPU -> PNPID='$($a.PNPID)' Path='$($a.RegistryPath)' Port='$($a.Port)' OldDisplay='$oldDisplay' NewDisplay='Audio - GPU'" } catch {}
        }
    }

    try {
        Write-LogLocal "Get-PCIDevices: Summary - GPUs found: $($gpuDevices.Count), Audio controllers included: $($audioDevices.Count), Audio controllers ignored: $($ignoredAudio.Count)"
        if ($audioDevices.Count -gt 0) {
            foreach ($ad in $audioDevices) {
                $types = if ($ad.AudioTypes -and $ad.AudioTypes.Count -gt 0) { ($ad.AudioTypes -join '/') } else { '<none>' }
                Write-LogLocal "  Included Audio: PNPID='$($ad.PNPID)' Path='$($ad.RegistryPath)' Port='$($ad.Port)' Desc='$($ad.Description)' Types='$types'"
            }
        }
        if ($ignoredAudio.Count -gt 0) {
            foreach ($ia in $ignoredAudio) {
                Write-LogLocal "  Ignored Audio: PNPID='$($ia.PNPID)' Path='$($ia.Path)' Desc='$($ia.Desc)' Reason='$($ia.Reason)'"
            }
        }
    } catch {}

    return @{
        GPU   = $gpuDevices
        Audio = $audioDevices
    }
}

function Get-NetworkAdapters {
    $svcRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services'

    $anyCx = Get-ChildItem -Path $svcRoot -ErrorAction SilentlyContinue |
             Where-Object {
                 $_.PSChildName -ne 'rtcx21' -and
                 (Get-ItemProperty -Path $_.PSPath -Name 'DisplayName' -ErrorAction SilentlyContinue).DisplayName -match 'NetAdapter' -and
                 (Test-Path -Path "$($_.PSPath)\Enum" -ErrorAction SilentlyContinue)
             } |
             Select-Object -First 1

    $useCx = $anyCx -ne $null

    $classKey    = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}'
    $adapterKeys = Get-ChildItem -Path $classKey -ErrorAction SilentlyContinue

    try {
        $scriptDir = if ($MyInvocation.MyCommand.Path) { Split-Path -Parent $MyInvocation.MyCommand.Path } else { Get-Location }
    } catch { $scriptDir = Get-Location }
    $logDir = Join-Path $scriptDir 'logs'
    if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
    $logFile = Join-Path $logDir 'logging.txt'
    if (-not (Test-Path $logFile)) { New-Item -Path $logFile -ItemType File -Force | Out-Null }
    function Write-LogLocal { param($txt) $time = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss"); Add-Content -Path $logFile -Value "[$time] $txt" }

    $out = @()

    function ProviderPrefixedPath($pspath) {
        if (-not $pspath) { return $null }
        return $pspath
    }

    function Find-EnumInstancePathForDriverDesc($driverDesc) {
        if (-not $driverDesc) { return $null }

        $pciRoot = 'HKLM:\SYSTEM\CurrentControlSet\Enum\PCI'
        try {
            $pciCandidates = Get-ChildItem -Path $pciRoot -Recurse -ErrorAction SilentlyContinue
            foreach ($p in $pciCandidates) {
                try {
                    $pp = Get-ItemProperty -Path $p.PSPath -ErrorAction SilentlyContinue
                    if ($pp) {
                        $candidateDesc = $pp.DeviceDesc
                        if ($candidateDesc) {
                            if ($candidateDesc -like "*$driverDesc*" -or $driverDesc -like "*$candidateDesc*") {
                                return $p.PSPath
                            }
                        }
                    }
                } catch {}
            }
        } catch {}

        $enumRoot = 'HKLM:\SYSTEM\CurrentControlSet\Enum'
        try {
            $enumCandidates = Get-ChildItem -Path $enumRoot -Recurse -ErrorAction SilentlyContinue
            foreach ($e in $enumCandidates) {
                try {
                    $ep = Get-ItemProperty -Path $e.PSPath -ErrorAction SilentlyContinue
                    if ($ep) {
                        $candidateDesc = $ep.DeviceDesc
                        if (-not $candidateDesc) { $candidateDesc = $ep.DriverDesc }
                        if ($candidateDesc) {
                            if ($candidateDesc -like "*$driverDesc*" -or $driverDesc -like "*$candidateDesc*") {
                                return $e.PSPath
                            }
                        }
                    }
                } catch {}
            }
        } catch {}

        return $null
    }

    foreach ($key in $adapterKeys) {
        $props = Get-ItemProperty -Path $key.PSPath -ErrorAction SilentlyContinue
        if (-not $props -or -not $props.DriverDesc) { continue }

        if ($props.DriverDesc -notmatch '(?i)Intel|Marvell|Mellanox|Broadcom|Realtek') { continue }

        if ($props.DriverDesc -match '(?i)Intel' -and $props.DriverDesc -match '(?i)LPC|SMBUS|HD|Serial|Xeon|Series|Advanced|ME|PCI|Smart|VirtualBox|VMware|Shared|SRAM|DRAM|GNA|GPIO|PEG10|SPI|Monitoring') {
            continue
        }

        if ($useCx) {
            $role    = 'NetAdapterCx'
            $display = 'Network Interface Card (NetAdapterCx)'
        } else {
            $role    = 'NDIS'
            $display = 'Network Interface Card (NDIS)'
        }

        $classPath = $key.PSPath

        $enumPath = $null
        try {
            $enumPath = Find-EnumInstancePathForDriverDesc -driverDesc $props.DriverDesc
        } catch {}

        $configPath = if ($enumPath) { $enumPath } else { $classPath }

        $entry = [PSCustomObject]@{
            Category     = 'Network'
            Role         = $role
            DisplayName  = $display
            RegistryPath = $classPath                 
            Description  = $props.DriverDesc
            ConfigPath   = $configPath                
        }

        $out += $entry

        try {
            Write-LogLocal "Get-NetworkAdapters: Detected network adapter -> Name='$($props.DriverDesc)' Role='$role'"
            Write-LogLocal "  ClassPath: $($classPath)"
            Write-LogLocal "  ConfigPath: $($configPath)"
        } catch {}
    }

    $pciRoot = 'HKLM:\SYSTEM\CurrentControlSet\Enum\PCI'
    $pciKeys = Get-ChildItem -Path $pciRoot -Recurse -ErrorAction SilentlyContinue

    foreach ($pciKey in $pciKeys) {
        try {
            $pciProps = Get-ItemProperty -Path $pciKey.PSPath -ErrorAction Stop
        }
        catch {
            continue
        }

        if (-not $pciProps.DeviceDesc) { continue }

        if ($pciProps.DeviceDesc -notmatch '(?i)Intel|Marvell|Mellanox|Broadcom|Realtek') { continue }

        if ($pciProps.DeviceDesc -match '(?i)Intel' -and $pciProps.DeviceDesc -match '(?i)LPC|SMBUS|HD|Serial|Xeon|Series|Advanced|ME|PCI|Smart|VirtualBox|VMware|Shared|SRAM|DRAM|GNA|GPIO|PEG10|SPI|Monitoring') {
            continue
        }

        $cleanDesc = if ($pciProps.DeviceDesc -match ';') {
            $pciProps.DeviceDesc.Split(';')[-1].Trim()
        } else {
            $pciProps.DeviceDesc
        }

        if ($out | Where-Object { $_.Description -eq $cleanDesc }) { continue }

        if ($useCx) {
            $role    = 'NetAdapterCx'
            $display = 'Network Interface Card (NetAdapterCx)'
        } else {
            $role    = 'NDIS'
            $display = 'Network Interface Card (NDIS)'
        }

        $entry = [PSCustomObject]@{
            Category     = 'Network'
            Role         = $role
            DisplayName  = $display
            RegistryPath = $pciKey.PSPath           
            Description  = $cleanDesc
            ConfigPath   = $pciKey.PSPath
        }

        $out += $entry

        try {
            Write-LogLocal "Get-NetworkAdapters: Detected PCI network adapter -> Name='$cleanDesc' Role='$role'"
            Write-LogLocal "  PCIPath: $($pciKey.PSPath)"
            Write-LogLocal "  ConfigPath: $($pciKey.PSPath)"
        } catch {}
    }

    try {
        Write-LogLocal "Get-NetworkAdapters: Summary - Network adapters detected: $($out.Count)."
        foreach ($a in $out) {
            Write-LogLocal "  Detected Adapter: Name='$($a.Description)' Role='$($a.Role)' ClassPath='$($a.RegistryPath)' ConfigPath='$($a.ConfigPath)'"
        }
    } catch {}

    return $out
}

$deviceList = @()
$deviceList += Get-USBControllers
$pciDevices = Get-PCIDevices

if ($pciDevices.GPU) { $deviceList += $pciDevices.GPU }

if ($pciDevices.Audio) {
    $deviceList += $pciDevices.Audio | Where-Object { $_.AudioTypes -and ($_.AudioTypes.Count -gt 0) }
}
$deviceList += Get-NetworkAdapters
$deviceList += Optimized-GetStorageDevices

$deviceControls = @{}

$globalDeviceAddressMap = Get-Device-Addresses

function Refresh-DeviceUI {
    foreach ($device in $deviceList) {
        $ctrls = $deviceControls[$device]
        if ($device.Category -eq "Network" -and $device.Role -eq "NDIS") {
            $affinityPath = $device.RegistryPath
        }
        elseif ($device.Category -eq "Network" -and $device.Role -eq "NetAdapterCx") {
            $affinityPath = Get-NetworkAdapterAffinityRegistryPath $device
        }
        else {
            $affinityPath = $device.RegistryPath
        }
        $newVal = Get-CurrentAffinity $affinityPath ($device.Category -eq "Network" -and $device.Role -eq "NDIS")
        $ctrls.InitialValue = $newVal
        if ($device.Category -eq "Network" -and $device.Role -eq "NDIS") {
            try {
                $selectedBase = [Convert]::ToInt32($newVal,16)
            } catch {
                $selectedBase = -1
            }
            $numQueues = 1
            try { $numQueues = Get-CurrentNumRssQueues $affinityPath } catch { $numQueues = 1 }

            if ($numQueues -lt 1) { $numQueues = 1 }

            $logicalCount = [Environment]::ProcessorCount

            $selectedSet = @()
            if ($selectedBase -ge 0) {
                for ($i = 0; $i -lt $numQueues; $i++) {
                    $c = ($selectedBase + $i) % $logicalCount
                    $selectedSet += $c
                }
            }

            $script:NDISUpdating = $true
            foreach ($chk in $ctrls.CheckBoxes) {
                $core = [int]$chk.Tag
                if ($selectedSet -contains $core) {
                    $chk.Checked = $true
                    $chk.AutoCheck = $false   
                } else {
                    $chk.Checked = $false
                    $chk.AutoCheck = $true
                }
            }
            $script:NDISUpdating = $false

            if ($selectedBase -ge 0) {
                $maskInt = 0
                foreach ($c in $selectedSet) { $maskInt = $maskInt -bor (1 -shl $c) }
                $displayVal = "0x" + ([Convert]::ToString($maskInt,16)).ToUpper()
            } else {
                $displayVal = "0x0"
            }

            if ($ctrls.ContainsKey('NumQueues') -and $ctrls.NumQueues -ne $null) {
                try { $ctrls.NumQueues.Value = $numQueues } catch {}
                $ctrls.NumQueues.Visible = $true
            }
        } else {
            Set-CheckboxesFromAffinity $ctrls.CheckBoxes $newVal
            $displayVal = $newVal
            if ($ctrls.ContainsKey('NumQueues') -and $ctrls.NumQueues -ne $null) {
                $ctrls.NumQueues.Visible = $false
            }
        }
        $ctrls.MaskLabel.Text = "Affinity Mask: "
        $ctrls.MaskValue.Text = $displayVal
        $ctrls.MaskValue.ForeColor = [System.Drawing.Color]::FromArgb(255,100,45)
        
        if ($device.Category -eq "Network") {
            $msiPath = Get-NetworkAdapterMSIRegistryPath $device
        } else {
            $msiPath = $device.RegistryPath
        }
        $msi = Get-CurrentMSI $msiPath
        if ($msi.MSIEnabled -eq 1) {
            $ctrls.MSICombo.SelectedIndex = 1
        } else {
            $ctrls.MSICombo.SelectedIndex = 0
        }
        if ($msi.MessageLimit -eq "") {
            $ctrls.MsgLimitBox.Text = "Unlimited"
        }
        else {
            $ctrls.MsgLimitBox.Text = $msi.MessageLimit.ToString()
        }
        if ($device.Category -eq "Network") {
            $priPath = Get-NetworkAdapterMSIRegistryPath $device
        } else {
            $priPath = $device.RegistryPath
        }
        $priority = Get-CurrentPriority $priPath
        switch ($priority) {
            1 { $ctrls.PriorityCombo.SelectedIndex = 0 }
            2 { $ctrls.PriorityCombo.SelectedIndex = 1 }
            3 { $ctrls.PriorityCombo.SelectedIndex = 2 }
            default { $ctrls.PriorityCombo.SelectedIndex = 1 }
        }

        if (-not ($device.Category -eq "Network" -and $device.Role -eq "NDIS")) {
            $policy = Get-CurrentDevicePolicy $device.RegistryPath
            $ctrls.PolicyCombo.SelectedIndex = $policy
            
        $enableAffinity = ($policy -eq 4)  
        foreach ($chk in $ctrls.CheckBoxes) {
            $chk.AutoCheck = $enableAffinity
            $chk.Enabled   = $true
        }

        try {
            $reservedArr = script:Get-ReservedCoresLocal -count ([Environment]::ProcessorCount)
            script:Apply-ReservedColoring -reservedArr $reservedArr
        } catch { }
        }

    }
}

function Get-FreeCore {
    param(
        [int[]]$occupiedCores,
        [int]  $logicalCount
    )
    $occupied = @{}
    $occupiedCores | ForEach-Object { $occupied[$_] = $true }
    for ($i = 1; $i -lt $logicalCount; $i++) {
        if (-not $occupied.ContainsKey($i)) { return $i }
    }
    return (if (-not $occupied.ContainsKey(0)) { 0 } else { -1 })
}

function Update-ConfigFile {
    param (
        [string]$filePath,
        [string]$coresString,
        [int]   $mouseCore = -1,
        [int]   $dwmCore   = -1
    )
    $content = if (Test-Path $filePath) {
        Get-Content $filePath -Raw -Encoding UTF8  
    } else {
        ""
    }

    if ($dwmCore -ge 0 -and $filePath -like '*system_priorities.cfg') {
        $content = $content -replace 'threaddesc=DWM Kernel Sensor Thread, \(.*?\)',
                                     "threaddesc=DWM Kernel Sensor Thread, ($dwmCore)"
        $content = $content -replace 'threaddesc=DWM Master Input Thread, \(.*?\)',
                                     "threaddesc=DWM Master Input Thread, ($mouseCore)"
    }

    $content = $content -replace '(?m)^occupied_affinity_cores=.*$',
                                 "occupied_affinity_cores=$coresString"
    $content = $content -replace '(?m)^occupied_ideal_processor_cores=.*$',
                                 "occupied_ideal_processor_cores=$coresString"

    if ($content -notmatch 'occupied_affinity_cores=') {
        $content += "`r`noccupied_affinity_cores=$coresString"
    }
    if ($content -notmatch 'occupied_ideal_processor_cores=') {
        $content += "`r`noccupied_ideal_processor_cores=$coresString"
    }

    Set-Content -Path $filePath -Value $content.Trim() -Encoding UTF8
}

$form = New-Object System.Windows.Forms.Form
$form.Text = "DEVICE-TWEAKER"
$form.Size = New-Object System.Drawing.Size(770,1000)  
$form.StartPosition = "CenterScreen"
$form.AutoScroll = $true
$form.Font = New-Object System.Drawing.Font($fontCollection.Families[0], 11)

$panel = New-Object System.Windows.Forms.Panel
$panel.Dock = "Fill"
$panel.AutoScroll = $true
$panel.BackColor = [System.Drawing.Color]::FromArgb(0,0,0)
$panel.Font = New-Object System.Drawing.Font($fontCollection.Families[0], 11)
$form.Controls.Add($panel)

$base64Icon = "AAABAAEAMDAAAAEACACoDgAAFgAAACgAAAAwAAAAYAAAAAEACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIiIiAEdHRwBtbW0AmZmZAMXFxQD///8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEGBgYGBgYGBgYGBgYCAAABBgYGBgYGBgYGBgYGAgAAAAMGBgYGBgYGBgYEAAAAAAEGBgYGBgYGBgYGBgYCAAABBgYGBgYGBgYGBgYGAgAAAQYGBgYGBgYGBgYGAwAAAAEGBgQCAgICAgICAgIBAAABBgYEAgICAgICAgICAQAAAgYGAgICAgICAgYGBAAAAAEGBgIAAAAAAAAAAAAAAAABBgYCAAAAAAAAAAAAAAAAAgYGAAAAAAAAAAUGBAAAAAEGBgIAAAAAAAAAAAAAAAABBgYCAAAAAAAAAAAAAAAAAgYGAAAAAAAAAAUGBAAAAAEGBgIAAAAAAAAAAAAAAAABBgYCAAAAAAAAAAAAAAAAAgYGAAAAAAAAAAUGBAAAAAEGBgIAAAAAAAAAAAAAAAABBgYCAAAAAAAAAAAAAAAAAgYGAAAAAAAAAAUGBAAAAAEGBgIAAAAAAAAAAAAAAAABBgYCAAAAAAAAAAAAAAAAAgYGAAAEBgYGBgYGBAAAAAEGBgIAAAAAAAAAAAAAAAABBgYCAAAAAAAAAAAAAAAAAgYGAAAEBgYGBgYGBAAAAAEGBgIAAAAAAAAAAAAAAAABBgYCAAAAAAAAAAAAAAAAAgYGAAABAgICAgICAQAAAAEGBgIAAAAAAAAAAAAAAAABBgYCAAAAAAAAAAAAAAAAAgYGAAAAAAAAAAAAAAAAAAEGBgIAAAAAAAAAAAAAAAABBgYCAAAAAAAAAAAAAAAAAgYGAAAAAAAAAAAAAAAAAAEGBgIAAAAAAAAAAAAAAAABBgYCAAAAAAAAAAAAAAAAAgYGAAAAAAAAAAUGBAAAAAEGBgIAAAAAAAAAAAAAAAABBgYCAAAAAAAAAAAAAAAAAgYGAAAAAAAAAAUGBAAAAAEGBgIAAAAAAAAAAAAAAAABBgYCAAAAAAAAAAAAAAAAAgYGAgICAgICAgYGBAAAAAEGBgIAAAAAAAAAAAAAAAABBgYCAAAAAAAAAAAAAAAAAQYGBgYGBgYGBgYGAwAAAAEGBgIAAAAAAAAAAAAAAAABBgYCAAAAAAAAAAAAAAAAAAMGBgYGBgYGBgYEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" 

$iconBytes = [Convert]::FromBase64String($base64Icon)
$stream = New-Object System.IO.MemoryStream($iconBytes, $false)
$icon = New-Object System.Drawing.Icon($stream)
$form.Icon = $icon

$lblTitlePart1 = New-Object System.Windows.Forms.Label
$lblTitlePart1.Text = "DEVICE-TWEAKER - BY "
$lblTitlePart1.AutoSize = $true
$lblTitlePart1.Font = New-Object System.Drawing.Font($fontCollection.Families[0], 26)
$lblTitlePart1.ForeColor = [System.Drawing.Color]::FromArgb(219,219,219)
$lblTitlePart1.Left = 12
$lblTitlePart1.Top = 40
$panel.Controls.Add($lblTitlePart1)

$lnkTitlePart2 = New-Object System.Windows.Forms.LinkLabel
$lnkTitlePart2.Text = "BYND_PERF"
$lnkTitlePart2.AutoSize = $true
$lnkTitlePart2.Font = New-Object System.Drawing.Font($fontCollection.Families[0], 26)
$lnkTitlePart2.LinkColor = [System.Drawing.Color]::FromArgb(0, 116, 222)
$lnkTitlePart2.ActiveLinkColor = [System.Drawing.Color]::FromArgb(255, 100, 45)
$lnkTitlePart2.Left = $lblTitlePart1.Right
$lnkTitlePart2.Top = 40
$lnkTitlePart2.Add_LinkClicked({[System.Diagnostics.Process]::Start("https://x.com/BEYONDPERF_LLG")})
$panel.Controls.Add($lnkTitlePart2)

$linkLabelTop = $lblTitle.Bottom + 93
$hoverColor = [System.Drawing.Color]::FromArgb(255, 100, 45)

$lblBeyond = New-Object System.Windows.Forms.Label
$lblBeyond.Text = "BEYOND PERFORMANCE - "
$lblBeyond.AutoSize = $true
$lblBeyond.Font = New-Object System.Drawing.Font($fontCollection.Families[0], 13)
$lblBeyond.ForeColor = [System.Drawing.Color]::FromArgb(219,219,219)
$lblBeyond.Left = 16
$lblBeyond.Top = $linkLabelTop
$panel.Controls.Add($lblBeyond)

$lnkService = New-Object System.Windows.Forms.LinkLabel
$lnkService.Text = "PC OPTIMIZATION SERVICE"
$lnkService.AutoSize = $true
$lnkService.Font = $lblBeyond.Font
$lnkService.LinkColor = [System.Drawing.Color]::FromArgb(0, 116, 222)
$lnkService.ActiveLinkColor = [System.Drawing.Color]::FromArgb(255, 100, 45)
$lnkService.Left = $lblBeyond.Right
$lnkService.Top = $lblBeyond.Top
$lnkService.Add_LinkClicked({ [System.Diagnostics.Process]::Start("https://discord.com/invite/BVfab6GYQB") })
$panel.Controls.Add($lnkService)

$lblBeyondGuides = New-Object System.Windows.Forms.Label
$lblBeyondGuides.Text = "BEYOND PERFORMANCE - "
$lblBeyondGuides.AutoSize = $true
$lblBeyondGuides.Font = $lblBeyond.Font
$lblBeyondGuides.ForeColor = $lblBeyond.ForeColor
$lblBeyondGuides.Left = 16
$lblBeyondGuides.Top = $lnkService.Bottom + 8
$panel.Controls.Add($lblBeyondGuides)

$lnkGuides = New-Object System.Windows.Forms.LinkLabel
$lnkGuides.Text = "GUIDES"
$lnkGuides.AutoSize = $true
$lnkGuides.Font = $lblBeyond.Font
$lnkGuides.LinkColor = $lnkService.LinkColor
$lnkGuides.ActiveLinkColor = $lnkService.ActiveLinkColor
$lnkGuides.Left = $lblBeyondGuides.Right
$lnkGuides.Top = $lblBeyondGuides.Top
$lnkGuides.Add_LinkClicked({ [System.Diagnostics.Process]::Start("https://cryptpad.fr/pad/#/2/pad/view/7qhwcrrOLFJCmptks7PnZn1YgS5QHULwLLzuPk8+Q7Q/embed/") })
$panel.Controls.Add($lnkGuides)

$lnkGaming = New-Object System.Windows.Forms.LinkLabel
$lnkGaming.Text = "L0W LATENCY GAM1NG (RU)"
$lnkGaming.AutoSize = $true
$lnkGaming.Font = $lblBeyond.Font
$lnkGaming.LinkColor = $lnkService.LinkColor
$lnkGaming.ActiveLinkColor = $lnkService.ActiveLinkColor
$lnkGaming.Left = 16
$lnkGaming.Top = $lnkGuides.Bottom + 8
$lnkGaming.Add_LinkClicked({ [System.Diagnostics.Process]::Start("https://discord.gg/MGj3GZ4thv") })
$panel.Controls.Add($lnkGaming)

$lnkPills = New-Object System.Windows.Forms.LinkLabel
$lnkPills.Text = "pills.gg"
$lnkPills.AutoSize = $true
$lnkPills.Font = $lblBeyond.Font
$lnkPills.LinkColor = $lnkService.LinkColor
$lnkPills.ActiveLinkColor = $lnkService.ActiveLinkColor
$lnkPills.Left = $lnkGaming.Right + 500  
$lnkPills.Top = $lnkGaming.Top
$lnkPills.Add_LinkClicked({ [System.Diagnostics.Process]::Start("https://pills.gg") })
$panel.Controls.Add($lnkPills)

$hoverColor = [System.Drawing.Color]::FromArgb(255,100,45)
$linkLabels = @($lnkTitlePart2, $lnkService, $lnkGuides, $lnkGaming, $lnkPills)
foreach ($lnk in $linkLabels) {
    $lnk.Add_MouseEnter({ $this.LinkColor = $hoverColor })
    $lnk.Add_MouseLeave({ $this.LinkColor = [System.Drawing.Color]::FromArgb(0,116,222) })
}

$cpu = Get-WmiObject Win32_Processor | Select-Object -First 1
$logicalCount = [Environment]::ProcessorCount
$physicalCount = $cpu.NumberOfCores
if ($logicalCount -gt $physicalCount) { 
    $htStatus = "Enabled"
    $htColor = [System.Drawing.Color]::FromArgb(255,100,45)
} else { 
    $htStatus = "Disabled"
    $htColor = [System.Drawing.Color]::FromArgb(255,100,45)
}

$lblHT = New-Object System.Windows.Forms.Label
$lblHT.Text = "Hyper-Threading -"
$lblHT.AutoSize = $true
$lblHT.Font = New-Object System.Drawing.Font($fontCollection.Families[0],22)
$lblHT.ForeColor = [System.Drawing.Color]::FromArgb(219,219,219)
$lblHT.Left = 14
$lblHT.Top = $lnkGaming.Bottom + 26
$panel.Controls.Add($lblHT)

$lblHTStatus = New-Object System.Windows.Forms.Label
$lblHTStatus.Text = $htStatus
$lblHTStatus.AutoSize = $true
$lblHTStatus.Font = New-Object System.Drawing.Font($fontCollection.Families[0],22)
$lblHTStatus.ForeColor = $htColor
$lblHTStatus.Left = $lblHT.Right
$lblHTStatus.Top = $lnkGaming.Bottom + 26
$panel.Controls.Add($lblHTStatus)

$btnApply = New-Object System.Windows.Forms.Button
$btnApply.Text = "APPLY"
$btnApply.Width = 191
$btnApply.Height = 40
$btnApply.Left = 20
$btnApply.Top = $lblHTStatus.Bottom + 16
$btnApply.BackColor = [System.Drawing.Color]::FromArgb(0,0,0)
$btnApply.ForeColor = [System.Drawing.Color]::FromArgb(255,255,255)
$btnApply.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btnApply.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(255,100,45)
$btnApply.FlatAppearance.BorderSize = 1
$btnApply.Font = New-Object System.Drawing.Font($fontCollection.Families[0],11)
$panel.Controls.Add($btnApply)

$btnApply.Add_MouseEnter({
    $this.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(234,234,234)
    $this.FlatAppearance.BorderSize = 1
    $this.Refresh()
})

$btnApply.Add_MouseLeave({
    $this.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(255,100,45)
    $this.FlatAppearance.BorderSize = 1
    $this.Refresh()
})

$btnAutoOpt = New-Object System.Windows.Forms.Button
$btnAutoOpt.Text = "AUTO-OPTIMIZATION"
$btnAutoOpt.Width = 191
$btnAutoOpt.Height = 40
$btnAutoOpt.Left = $btnApply.Right + 10
$btnAutoOpt.Top = $btnApply.Top
$btnAutoOpt.BackColor = [System.Drawing.Color]::FromArgb(0,0,0)
$btnAutoOpt.ForeColor = [System.Drawing.Color]::FromArgb(255,255,255)
$btnAutoOpt.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btnAutoOpt.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(255,100,45)
$btnAutoOpt.FlatAppearance.BorderSize = 1
$btnAutoOpt.Font = New-Object System.Drawing.Font($fontCollection.Families[0],11)
$panel.Controls.Add($btnAutoOpt)

$btnAutoOpt.Add_MouseEnter({
    $this.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(234,234,234)
    $this.FlatAppearance.BorderSize = 1
    $this.Refresh()
})

$btnAutoOpt.Add_MouseLeave({
    $this.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(255,100,45)
    $this.FlatAppearance.BorderSize = 1
    $this.Refresh()
})

$btnIRQ = New-Object System.Windows.Forms.Button
$btnIRQ.Text = "CALCULATE IRQ COUNTS"
$btnIRQ.Width = 281
$btnIRQ.Height = 40
$btnIRQ.Left = $btnAutoOpt.Right + 23
$btnIRQ.Top = $btnAutoOpt.Top
$btnIRQ.BackColor = [System.Drawing.Color]::FromArgb(0,0,0)
$btnIRQ.ForeColor = [System.Drawing.Color]::FromArgb(255,255,255)
$btnIRQ.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btnIRQ.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(255,100,45)
$btnIRQ.FlatAppearance.BorderSize = 1
$btnIRQ.Font = New-Object System.Drawing.Font($fontCollection.Families[0],11)
$panel.Controls.Add($btnIRQ)

$btnIRQ.Add_MouseEnter({
    $this.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(234,234,234)
    $this.FlatAppearance.BorderSize = 1
    $this.Refresh()
})

$btnIRQ.Add_MouseLeave({
    $this.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(255,100,45)
    $this.FlatAppearance.BorderSize = 1
    $this.Refresh()
})

$btnIRQ.Add_Click({
    $btnIRQ.Enabled = $false
    $btnIRQ.Text = "Calculating..."
    $btnIRQ.Refresh()
    
    try {
        $irqCounts = Get-DeviceIRQCounts
        
        foreach ($device in $deviceList) {
            $ctrls = $deviceControls[$device]
            $pnpId = $ctrls.PNPID
            
            if ($irqCounts.ContainsKey($pnpId)) {
                $ctrls.IRQValueLabel.Text = "$($irqCounts[$pnpId])"
                $ctrls.IRQValueLabel.ForeColor = [System.Drawing.Color]::FromArgb(255,100,45)
            }
            else {
                $ctrls.IRQValueLabel.Text = "0"
                $ctrls.IRQValueLabel.ForeColor = [System.Drawing.Color]::FromArgb(255,100,45)
            }
        }
        
        [System.Windows.Forms.MessageBox]::Show("IRQ counts calculated successfully!", "Done", "OK", "Information")
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show("Error calculating IRQ counts: $_", "Error", "OK", "Error")
    }
    finally {
        $btnIRQ.Enabled = $true
        $btnIRQ.Text = "CALCULATE IRQ COUNTS"
    }
})

$linkLabelTop = $lnkTitlePart2.Bottom + 15
$hoverColor = [System.Drawing.Color]::FromArgb(255, 100, 45)
$deviceBoxSpacing = 6

function Create-DeviceGroupBox($device, [int]$topPosition) {
    $groupBox = New-Object System.Windows.Forms.GroupBox
    $groupBox.Text = $device.DisplayName
    $groupBox.Width = 716
    if ($device.Category -eq "USB") {
        $groupBox.Height = 385  
    } else {
    $groupBox.Height = 340
    $groupBox.Height = 340
        $groupBox.Height = 340
    }
    $groupBox.Left = 10
    $groupBox.Top = $topPosition
    $groupBox.Tag = $device
    $groupBox.ForeColor = [System.Drawing.Color]::FromArgb(219,219,219)
    $groupBox.BackColor = [System.Drawing.Color]::FromArgb(0,0,0)
    $groupBox.Font = New-Object System.Drawing.Font($fontCollection.Families[0], 11)
    
    $affPanel = New-Object System.Windows.Forms.Panel
    $affPanel.BackColor = [System.Drawing.Color]::FromArgb(0,0,0)
    $affPanel.BorderStyle = "FixedSingle"
    $affPanel.Width = 395
    $affPanel.Height = 210
    $affPanel.Left = 10
    $affPanel.Top = 20
    $affPanel.AutoScroll = $true
    $affPanel.Font = New-Object System.Drawing.Font($fontCollection.Families[0], 11)
    $groupBox.Controls.Add($affPanel)
    
        
    $coreCount = [Environment]::ProcessorCount
    $checkboxes = @()
    $maxCoresPerColumn = 8  
    $columns = [Math]::Ceiling($coreCount / $maxCoresPerColumn)
    $columnWidth = 100
    $rowHeight = 25
    for ($col = 0; $col -lt $columns; $col++) {
        $startCPU = $col * $maxCoresPerColumn
        $endCPU = [Math]::Min($startCPU + $maxCoresPerColumn - 1, $coreCount - 1)
        for ($row = 0; $row -lt ($endCPU - $startCPU + 1); $row++) {
            $cpuNumber = $startCPU + $row
$chk = New-Object System.Windows.Forms.CheckBox
$chk.Text = "CPU $cpuNumber"
$chk.Tag = $cpuNumber
$chk.Width = 80
$chk.Left = 10 + $col * $columnWidth
$chk.Top = $row * $rowHeight

if (Is-PCore $cpuNumber) {
    $chk.ForeColor = [System.Drawing.Color]::FromArgb(219,219,219)
} else {
    $chk.ForeColor = [System.Drawing.Color]::FromArgb(0,104,181)
}

$chk.BackColor = [System.Drawing.Color]::FromArgb(0,0,0)
$chk.FlatStyle = "Standard"
$chk.Font = New-Object System.Drawing.Font($fontCollection.Families[0], 9)
            $affPanel.Controls.Add($chk)
            $checkboxes += $chk
        }
    }
    
    $lblMask = New-Object System.Windows.Forms.Label
    $lblMask.AutoSize = $true
    $lblMask.Left = 7
    $lblMask.Top = $affPanel.Bottom + 15
    $lblMask.Text = "Affinity Mask: "
    $lblMask.ForeColor = [System.Drawing.Color]::FromArgb(219,219,219)
    $lblMask.Font = New-Object System.Drawing.Font($fontCollection.Families[0], 11)
    $groupBox.Controls.Add($lblMask)
    
    if ($device.Category -eq "Network" -and $device.Role -eq "NDIS") {
        $affinityPath = $device.RegistryPath
    }
    elseif ($device.Category -eq "Network" -and $device.Role -eq "NetAdapterCx") {
        $affinityPath = Get-NetworkAdapterAffinityRegistryPath $device
    }
    else {
        $affinityPath = $device.RegistryPath
    }
    $initialValue = Get-CurrentAffinity $affinityPath ($device.Category -eq "Network" -and $device.Role -eq "NDIS")
    if ($device.Category -eq "Network" -and $device.Role -eq "NDIS") {
        try { 
            $selectedBase = [Convert]::ToInt32($initialValue,16) 
        } catch { 
            $selectedBase = -1 
        }
        
        $numQueues = Get-CurrentNumRssQueues -registryPath $device.RegistryPath
        if (-not $numQueues -or $numQueues -lt 1) { $numQueues = 1 }
        
        $logicalCount = [Environment]::ProcessorCount
        $selectedSet = @()
        if ($selectedBase -ge 0) {
            for ($i = 0; $i -lt $numQueues; $i++) {
                $coreIndex = ($selectedBase + $i) % $logicalCount
                $selectedSet += $coreIndex
            }
        }
        
        foreach ($chk in $checkboxes) {
            $coreNum = [int]$chk.Tag
            $chk.Checked = ($selectedSet -contains $coreNum)
        }
    } else {
        Set-CheckboxesFromAffinity $checkboxes $initialValue
    }
    $lblMask.Text = "Affinity Mask:"
    $lblMaskValue = New-Object System.Windows.Forms.Label
    $lblMaskValue.AutoSize = $true
    $lblMaskValue.Left = $lblMask.Right + 7
    $lblMaskValue.Top = $lblMask.Top
    if ($device.Category -eq "Network" -and $device.Role -eq "NDIS") {
        if ($selectedBase -ge 0) {
            $maskInt = 0
            for ($i = 0; $i -lt $numQueues; $i++) {
                $coreIndex = ($selectedBase + $i) % $logicalCount
                $maskInt = $maskInt -bor (1 -shl $coreIndex)
            }
            $lblMaskValue.Text = "0x" + $maskInt.ToString("X")
        } else {
            $lblMaskValue.Text = "0x0"
        }
    } else {
        $lblMaskValue.Text = $initialValue
    }
    $lblMaskValue.ForeColor = [System.Drawing.Color]::FromArgb(255,100,45)
    $lblMaskValue.Font = New-Object System.Drawing.Font($fontCollection.Families[0], 11)
    $groupBox.Controls.Add($lblMaskValue)
    
    if ($device.Category -eq "SSD") {
        $lblNote = New-Object System.Windows.Forms.Label
        $lblNote.Text = "(Affinity doesn't work for SSD)"
        $lblNote.ForeColor = [System.Drawing.Color]::FromArgb(219,25,25)
        $lblNote.AutoSize = $true
        $lblNote.Left = 112
        $lblNote.Top = $lblPNP.Top 
        $lblNote.Font = New-Object System.Drawing.Font($fontCollection.Families[0], 11)
        $groupBox.Controls.Add($lblNote)
    }
    
    $msiPanel = New-Object System.Windows.Forms.Panel
    $msiPanel.Width = 282
    $msiPanel.Height = if ($device.Category -eq "Network" -and $device.Role -eq "NDIS") { 165 } else { 163 }    
    $msiPanel.Left = $affPanel.Right + 20
    $msiPanel.Top = 20
    $msiPanel.BorderStyle = "FixedSingle"
    $msiPanel.BackColor = [System.Drawing.Color]::FromArgb(0,0,0)
    $groupBox.Controls.Add($msiPanel)
    
    $lblMSI = New-Object System.Windows.Forms.Label
    $lblMSI.Text = "MSI Mode:"
    $lblMSI.AutoSize = $true
    $lblMSI.Left = 10
    $lblMSI.Top = 10
    $lblMSI.ForeColor = [System.Drawing.Color]::FromArgb(219,219,219)
    $lblMSI.Font = New-Object System.Drawing.Font($fontCollection.Families[0], 11)
    $msiPanel.Controls.Add($lblMSI)
    
    $cboMSI = New-Object System.Windows.Forms.ComboBox
    $cboMSI.Left = 150
    $cboMSI.Top = 5
    $cboMSI.Width = 120
    $cboMSI.DropDownStyle = "DropDownList"
    $cboMSI.BackColor = [System.Drawing.Color]::FromArgb(0,0,0)
    $cboMSI.ForeColor = [System.Drawing.Color]::FromArgb(219,219,219)
    $cboMSI.FlatStyle = "Flat"
    $cboMSI.Font = New-Object System.Drawing.Font($fontCollection.Families[0], 12)
    $cboMSI.Items.Add("Disabled")
    $cboMSI.Items.Add("Enabled")
    $msiPanel.Controls.Add($cboMSI)
    
    $lblMsg = New-Object System.Windows.Forms.Label
    $lblMsg.Text = "MSI Limit:"
    $lblMsg.AutoSize = $true
    $lblMsg.Left = 10
    $lblMsg.Top = $lblMSI.Bottom + 20
    $lblMsg.Font = New-Object System.Drawing.Font($fontCollection.Families[0], 11)
    $msiPanel.Controls.Add($lblMsg)
    
    $msgLimitBox = New-Object System.Windows.Forms.TextBox
    $msgLimitBox.Left = 150
    $msgLimitBox.Top = $lblMSI.Bottom + 17
    $msgLimitBox.Width = 103
    $msgLimitBox.BorderStyle = "FixedSingle"
    $msgLimitBox.BackColor = [System.Drawing.Color]::FromArgb(0,0,0)
    $msgLimitBox.ForeColor = [System.Drawing.Color]::FromArgb(219,219,219)
    $msgLimitBox.Font = New-Object System.Drawing.Font($fontCollection.Families[0], 12)
    $msiPanel.Controls.Add($msgLimitBox)
    
    $lblPri = New-Object System.Windows.Forms.Label
    $lblPri.Text = "IRQ Priority:"
    $lblPri.AutoSize = $true
    $lblPri.Left = 10
    $lblPri.Top = $lblMsg.Bottom + 20
    $lblPri.Font = New-Object System.Drawing.Font($fontCollection.Families[0], 11)
    $msiPanel.Controls.Add($lblPri)
    
    $cboPriority = New-Object System.Windows.Forms.ComboBox
    $cboPriority.Left = 150
    $cboPriority.Top = $lblMsg.Bottom + 15
    $cboPriority.Width = 120
    $cboPriority.DropDownStyle = "DropDownList"
    $cboPriority.BackColor = [System.Drawing.Color]::FromArgb(0,0,0)
    $cboPriority.ForeColor = [System.Drawing.Color]::FromArgb(219,219,219)
    $cboPriority.FlatStyle = "Flat"
    $cboPriority.Font = New-Object System.Drawing.Font($fontCollection.Families[0], 12)
    $cboPriority.Items.Add("Low")
    $cboPriority.Items.Add("Normal")
    $cboPriority.Items.Add("High")
    $msiPanel.Controls.Add($cboPriority)
    
    if ($device.Category -eq "Network") {
        $msiPath = Get-NetworkAdapterMSIRegistryPath $device
    } else {
        $msiPath = $device.RegistryPath
    }
    $msi = Get-CurrentMSI $msiPath
    if ($msi.MSIEnabled -eq 1) {
        $cboMSI.SelectedIndex = 1
    } else {
        $cboMSI.SelectedIndex = 0
    }
    if ($msi.MessageLimit -eq "") {
        $msgLimitBox.Text = "Unlimited"
    } else {
        $msgLimitBox.Text = $msi.MessageLimit.ToString()
    }
    $priority = Get-CurrentPriority $msiPath
    switch ($priority) {
        1 { $cboPriority.SelectedIndex = 0 }
        2 { $cboPriority.SelectedIndex = 1 }
        3 { $cboPriority.SelectedIndex = 2 }
        default { $cboPriority.SelectedIndex = 1 }
    }

    $isNDIS = ($device.Category -eq "Network" -and $device.Role -eq "NDIS")

    $lblNumQueues = New-Object System.Windows.Forms.Label
    $lblNumQueues.Text = "RSS Queues:"
    $lblNumQueues.AutoSize = $true
    $lblNumQueues.Left = 10
    $lblNumQueues.Top = $lblPri.Bottom + 15
    $lblNumQueues.Font = New-Object System.Drawing.Font($fontCollection.Families[0], 11)
    $lblNumQueues.ForeColor = [System.Drawing.Color]::FromArgb(219,219,219)
    $lblNumQueues.Visible = $isNDIS  
    $msiPanel.Controls.Add($lblNumQueues)

    $nudNumQueues = New-Object System.Windows.Forms.NumericUpDown
    $nudNumQueues.Left = $lblNumQueues.Right + 27
    $nudNumQueues.Top = $lblNumQueues.Top + -6
    $nudNumQueues.Width = 45
    $nudNumQueues.Minimum = 1
    $nudNumQueues.Maximum = [Environment]::ProcessorCount
    $nudNumQueues.Value = 1
    $nudNumQueues.Font = New-Object System.Drawing.Font($fontCollection.Families[0], 12)
    $nudNumQueues.BorderStyle = 'FixedSingle'
    $nudNumQueues.BackColor = [System.Drawing.Color]::FromArgb(0,0,0)
    $nudNumQueues.ForeColor = [System.Drawing.Color]::FromArgb(219,219,219)  
    $nudNumQueues.Visible = $isNDIS

    $currentNumQueues = Get-CurrentNumRssQueues -registryPath $device.RegistryPath
    if ($null -ne $currentNumQueues -and $currentNumQueues -ge 1) {
        $nudNumQueues.Value = $currentNumQueues
    } else {
        $nudNumQueues.Value = 1
    }

    $msiPanel.Controls.Add($nudNumQueues)

    $nudNumQueues.Add_ValueChanged({
        if ($script:NDISUpdating) { return }
        $parentGroup = $this.Parent.Parent
        $dev = $parentGroup.Tag
        $ctrls = $deviceControls[$dev]
        if (-not $ctrls) { return }
        $selectedBase = $null
        foreach ($cb in $ctrls.CheckBoxes) { if ($cb.Checked) { $selectedBase = [int]$cb.Tag; break } }
        if ($selectedBase -eq $null) { return }

        $numQueuesLocal = [int]$this.Value
        if ($numQueuesLocal -lt 1) { $numQueuesLocal = 1 }

        $logicalCount = [Environment]::ProcessorCount
        $selectedSet = @()
        for ($i=0; $i -lt $numQueuesLocal; $i++) {
            $c = ($selectedBase + $i) % $logicalCount
            $selectedSet += $c
        }

        $script:NDISUpdating = $true
        foreach ($cb in $ctrls.CheckBoxes) {
            $core = [int]$cb.Tag
            if ($selectedSet -contains $core) {
                $cb.Checked = $true
                $cb.AutoCheck = $false
            } else {
                $cb.Checked = $false
                $cb.AutoCheck = $true
            }
        }
        $script:NDISUpdating = $false

        $maskInt = 0
        foreach ($c in $selectedSet) { $maskInt = $maskInt -bor (1 -shl $c) }
        $ctrls.MaskValue.Text = "0x" + ([Convert]::ToString($maskInt,16)).ToUpper()
    })

    if ($device.Category -eq "Network") {
        $msiPathForPNP = Get-NetworkAdapterMSIRegistryPath $device
    } else {
        $msiPathForPNP = $device.RegistryPath
    }
    $pnpID = Get-PNPId $msiPathForPNP

if (-not ($device.Category -eq "Network" -and $device.Role -eq "NDIS")) {
    $lblPolicy = New-Object System.Windows.Forms.Label
    $lblPolicy.Text = "Policy:"
    $lblPolicy.AutoSize = $true
    $lblPolicy.Left = 10
    $lblPolicy.Top = $cboPriority.Bottom + 20
    $lblPolicy.Font = New-Object System.Drawing.Font($fontCollection.Families[0], 11)
    $msiPanel.Controls.Add($lblPolicy)

    $cboPolicy = New-Object System.Windows.Forms.ComboBox
    $cboPolicy.Left = 90
    $cboPolicy.Top = $lblPolicy.Top + -5
    $cboPolicy.Width = 180
    $cboPolicy.DropDownStyle = "DropDownList"
    $cboPolicy.BackColor = [System.Drawing.Color]::FromArgb(0,0,0)
    $cboPolicy.ForeColor = [System.Drawing.Color]::FromArgb(219,219,219)
    $cboPolicy.FlatStyle = "Flat"
    $cboPolicy.Font = New-Object System.Drawing.Font($fontCollection.Families[0], 12)
$cboPolicy.Items.AddRange(@(
    "MachineDefault",   # MachineDefault 
    "AllCloseCPU",      # AllCloseProcessors 
    "OneCloseCPU",      # OneCloseProcessor 
    "AllCPUInMach",     # AllProcessorsInMachine 
    "SpecCPU",          # SpecifiedProcessors 
    "SpreadMsgsCPU",    # SpreadMessagesAcrossAllProcessors 
    "AllCPUInMachSt"    # AllProcessorsInMachineWhenSteered 
))


    $msiPanel.Controls.Add($cboPolicy)
    
    $policyValue = Get-CurrentDevicePolicy $device.RegistryPath
    $cboPolicy.SelectedIndex = $policyValue
    
    $enableAffinity = ($policyValue -eq 4)  
    foreach ($chk in $checkboxes) {
        $chk.AutoCheck = $enableAffinity
        $chk.Enabled   = $true
    }

    try {
        $reservedArr = script:Get-ReservedCoresLocal -count ([Environment]::ProcessorCount)
        script:Apply-ReservedColoring -reservedArr $reservedArr
    } catch { }
    
    $cboPolicy.Add_SelectedIndexChanged({
        $enableAffinityNow = ($this.SelectedIndex -eq 4)  
        $parentGroup = $this.Parent.Parent
        $dev = $parentGroup.Tag
        $ctrls = $deviceControls[$dev]

        foreach ($chk in $ctrls.CheckBoxes) {
            $chk.AutoCheck = $enableAffinityNow
            $chk.Enabled   = $true
        }

        try {
            $reservedArr = script:Get-ReservedCoresLocal -count ([Environment]::ProcessorCount)
            script:Apply-ReservedColoring -reservedArr $reservedArr
        } catch { }
    })
}

$lblPNP = New-Object System.Windows.Forms.Label
$lblPNP.AutoSize = $true
$lblPNP.Left = 6
$lblPNP.Top = $lblMask.Bottom + 10
$lblPNP.Text = "PNP ID: "
$lblPNP.Font = New-Object System.Drawing.Font($fontCollection.Families[0], 11)
$lblPNP.ForeColor = [System.Drawing.Color]::FromArgb(219,219,219)
$groupBox.Controls.Add($lblPNP)

$currentLeft = $lblPNP.Right

if ($pnpID -match '^([^_]+)(_VEN_)([^_]+)(_DEV_)([^_]+)(.*)$') {
    $busType = $matches[1]
    $venPrefix = $matches[2]
    $vendorId = $matches[3]
    $devPrefix = $matches[4]
    $deviceId = $matches[5]
    $remainder = $matches[6]
    
    $font = New-Object System.Drawing.Font($fontCollection.Families[0], 11)
    $offset = -4  
    
    $lblBusType = New-Object System.Windows.Forms.Label
    $lblBusType.Left = $currentLeft
    $lblBusType.Top = $lblPNP.Top
    $lblBusType.Text = $busType
    $lblBusType.Font = $font
    $lblBusType.ForeColor = [System.Drawing.Color]::FromArgb(219,219,219)
    $lblBusType.AutoSize = $true
    $groupBox.Controls.Add($lblBusType)
    $currentLeft = $lblBusType.Right + $offset
    
    $lblVenPrefix = New-Object System.Windows.Forms.Label
    $lblVenPrefix.Left = $currentLeft
    $lblVenPrefix.Top = $lblPNP.Top
    $lblVenPrefix.Text = $venPrefix
    $lblVenPrefix.Font = $font
    $lblVenPrefix.ForeColor = [System.Drawing.Color]::FromArgb(219,219,219)
    $lblVenPrefix.AutoSize = $true
    $groupBox.Controls.Add($lblVenPrefix)
    $currentLeft = $lblVenPrefix.Right + $offset
    
    $lblVendorId = New-Object System.Windows.Forms.Label
    $lblVendorId.Left = $currentLeft
    $lblVendorId.Top = $lblPNP.Top
    $lblVendorId.Text = $vendorId
    $lblVendorId.Font = $font
    $lblVendorId.ForeColor = [System.Drawing.Color]::FromArgb(255,100,45)
    $lblVendorId.AutoSize = $true
    $groupBox.Controls.Add($lblVendorId)
    $currentLeft = $lblVendorId.Right + $offset
    
    $lblDevPrefix = New-Object System.Windows.Forms.Label
    $lblDevPrefix.Left = $currentLeft
    $lblDevPrefix.Top = $lblPNP.Top
    $lblDevPrefix.Text = $devPrefix
    $lblDevPrefix.Font = $font
    $lblDevPrefix.ForeColor = [System.Drawing.Color]::FromArgb(219,219,219)
    $lblDevPrefix.AutoSize = $true
    $groupBox.Controls.Add($lblDevPrefix)
    $currentLeft = $lblDevPrefix.Right + $offset
    
    $lblDeviceId = New-Object System.Windows.Forms.Label
    $lblDeviceId.Left = $currentLeft
    $lblDeviceId.Top = $lblPNP.Top
    $lblDeviceId.Text = $deviceId
    $lblDeviceId.Font = $font
    $lblDeviceId.ForeColor = [System.Drawing.Color]::FromArgb(255,100,45)
    $lblDeviceId.AutoSize = $true
    $groupBox.Controls.Add($lblDeviceId)
    $currentLeft = $lblDeviceId.Right + $offset
    
    if ($remainder) {
        $lblRemainder = New-Object System.Windows.Forms.Label
        $lblRemainder.Left = $currentLeft
        $lblRemainder.Top = $lblPNP.Top
        $lblRemainder.Text = $remainder
        $lblRemainder.Font = $font
        $lblRemainder.ForeColor = [System.Drawing.Color]::FromArgb(219,219,219)
        $lblRemainder.AutoSize = $true
        $groupBox.Controls.Add($lblRemainder)
    }
}
else {
    $lblPNPValue = New-Object System.Windows.Forms.Label
    $lblPNPValue.AutoSize = $true
    $lblPNPValue.Left = $currentLeft
    $lblPNPValue.Top = $lblPNP.Top
    $lblPNPValue.Text = $pnpID
    $lblPNPValue.Font = New-Object System.Drawing.Font($fontCollection.Families[0], 11)
    $lblPNPValue.ForeColor = [System.Drawing.Color]::FromArgb(219,219,219)
    $groupBox.Controls.Add($lblPNPValue)
}

$lblIRQ = New-Object System.Windows.Forms.Label
$lblIRQ.AutoSize = $true
$lblIRQ.Left = 6
$lblIRQ.Top = $lblPNP.Bottom + 8
$lblIRQ.Text = "IRQ Count: "
$lblIRQ.Font = New-Object System.Drawing.Font($fontCollection.Families[0], 11)
$lblIRQ.ForeColor = [System.Drawing.Color]::FromArgb(219,219,219)
$groupBox.Controls.Add($lblIRQ)

$lblIRQValue = New-Object System.Windows.Forms.Label
$lblIRQValue.AutoSize = $true
$lblIRQValue.Left = $lblIRQ.Right
$lblIRQValue.Top = $lblIRQ.Top
$lblIRQValue.Text = "(Click CALCULATE IRQ COUNTS)"
$lblIRQValue.Font = New-Object System.Drawing.Font($fontCollection.Families[0], 11)
$lblIRQValue.ForeColor = [System.Drawing.Color]::FromArgb(219,219,219)
$groupBox.Controls.Add($lblIRQValue)

if ($device.Category -eq "USB") {
    $imodPanel = New-Object System.Windows.Forms.Panel
    $imodPanel.Left = 6
    $imodPanel.Top = $lblIRQ.Bottom + 8
    $imodPanel.Width = 600
    $imodPanel.Height = 35
$imodPanel.BackColor = [System.Drawing.Color]::Transparent
    $groupBox.Controls.Add($imodPanel)

    $lblIMOD = New-Object System.Windows.Forms.Label
    $lblIMOD.Text = "IMOD INTERVAL:"
    $lblIMOD.AutoSize = $true
    $lblIMOD.Left = 0
    $lblIMOD.Top = 8
    $lblIMOD.Font = New-Object System.Drawing.Font($fontCollection.Families[0], 11)
    $lblIMOD.ForeColor = [System.Drawing.Color]::FromArgb(219, 219, 219)
    $imodPanel.Controls.Add($lblIMOD)

    $txtNewIMOD = New-Object System.Windows.Forms.TextBox
    $txtNewIMOD.Width = 70
    $txtNewIMOD.MaxLength = 6
    $txtNewIMOD.Left = $lblIMOD.Right + 10
    $txtNewIMOD.Top = 5
    $txtNewIMOD.Font = $lblIMOD.Font
    $txtNewIMOD.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $txtNewIMOD.ForeColor = [System.Drawing.Color]::FromArgb(219, 219, 219)
    $txtNewIMOD.BorderStyle = 'FixedSingle'
    $imodPanel.Controls.Add($txtNewIMOD)
function Update-IMOD-NsLabel {
    param($textBox, $label)

    $raw = $textBox.Text.Trim()

    if ($raw -match '^0x[0-9A-Fa-f]{1,4}$') {
        try {
            $val = [Convert]::ToUInt16($raw, 16)
            $ns = $val * 250

            if ($ns -ge 1000) {
                $usExact = $ns / 1000.0
                $label.Text = "$usExact µs"
            } else {
                $label.Text = "$ns ns"
            }
        } catch {
            $label.Text = ""
        }
    } else {
        $label.Text = ""
    }
}


$txtNewIMOD.Add_TextChanged({
    Update-IMOD-NsLabel -textBox $this -label $lblIMODns
})

$lblIMODns = New-Object System.Windows.Forms.Label
$lblIMODns.Text = ""
$lblIMODns.AutoSize = $true
$lblIMODns.Left = $txtNewIMOD.Right + 11
$lblIMODns.Top = 9
$lblIMODns.Font = $lblIMOD.Font
$lblIMODns.ForeColor = [System.Drawing.Color]::FromArgb(160, 160, 160)
$imodPanel.Controls.Add($lblIMODns)

$btnSetIMOD = New-Object System.Windows.Forms.Button
$btnSetIMOD.Text = "SET"
$btnSetIMOD.Width = 60
$btnSetIMOD.Height = 28
$btnSetIMOD.Left = $lblIMODns.Right + 333
$btnSetIMOD.Top = 5
$btnSetIMOD.Tag = $device
$btnSetIMOD.BackColor = [System.Drawing.Color]::FromArgb(0, 0, 0)
$btnSetIMOD.ForeColor = [System.Drawing.Color]::FromArgb(255, 255, 255)
$btnSetIMOD.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btnSetIMOD.Font = New-Object System.Drawing.Font($fontCollection.Families[0], 13)

$imodPanel.Controls.Add($btnSetIMOD)

$btnSave = New-Object System.Windows.Forms.Button
$btnSave.Text = "SAVE"
$btnSave.Width = 65
$btnSave.Height = 28
$btnSave.Left = $lblIMODns.Right + 402
$btnSave.Top = 5
$btnSave.BackColor = [System.Drawing.Color]::FromArgb(0,0,0)
$btnSave.ForeColor = [System.Drawing.Color]::FromArgb(255,255,255)
$btnSave.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btnSave.Font = New-Object System.Drawing.Font($fontCollection.Families[0],13)
$btnSave.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(255,100,45)
$btnSave.FlatAppearance.BorderSize = 1
$imodPanel.Controls.Add($btnSave)
$imodPanel.Width = $btnSave.Right + 15
$btnSave.Add_MouseEnter({
    $this.FlatAppearance.BorderColor = [System.Drawing.Color]::White
})
$btnSave.Add_MouseLeave({
    $this.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(255,100,45)
})
$btnSave.Add_Click({
    $scriptContent = @'
$globalInterval = 0x0
$globalHCSPARAMSOffset = 0x4
$globalRTSOFF = 0x18
$userDefinedData = @{
'@
    $imodSettings = @{}
    foreach ($device in $deviceList | Where-Object { $_.Category -eq "USB" }) {
        $ctrls = $deviceControls[$device]
        $pnpId = $ctrls.PNPID
        
        if ($pnpId -match 'DEV_([0-9A-F]{4})') {
            $devId = "DEV_$($Matches[1])"
            $imodValue = $ctrls.NewIMOD.Text
            $imodSettings[$devId] = $imodValue
        }
    }
    foreach ($key in $imodSettings.Keys) {
        $scriptContent += "    `"$key`" = @{`r`n"
        $scriptContent += "        `"INTERVAL`" = $($imodSettings[$key])`r`n"
        $scriptContent += "    }`r`n"
    }
    $scriptContent += @'
}
$rwePath = "C:\Program Files (x86)\RW-Everything\Rw.exe"
function Dec-To-Hex($decimal) {
    return "0x$($decimal.ToString('X2'))"
}
function Get-Value-From-Address($address) {
    $address = Dec-To-Hex -decimal ([uint64]$address)
    $stdout = & $rwePath /Min /NoLogo /Stdout /Command="R32 $($address)" | Out-String
    $splitString = $stdout -split " "
    return [uint64]$splitString[-1]
}
function Get-Device-Addresses {
    $data = @{}
    $resources = Get-WmiObject -Class Win32_PNPAllocatedResource -ComputerName LocalHost -Namespace root\CIMV2
    foreach ($resource in $resources) {
        $deviceId = $resource.Dependent.Split("=")[1].Replace('"', '').Replace("\\", "\")
        $physicalAddress = $resource.Antecedent.Split("=")[1].Replace('"', '')
        if (-not $data.ContainsKey($deviceId) -and $deviceId -and $physicalAddress) {
            $data[$deviceId] = [uint64]$physicalAddress
        }
    }
    return $data
}
function Is-Admin {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
function Read-ControllerIMOD($controller, $deviceMap) {
    $deviceId = $controller.DeviceID
    if (-not $deviceMap.Contains($deviceId)) { return $null }
    $capabilityAddress = $deviceMap[$deviceId]
    $desiredInterval = $globalInterval
    $hcsparamsOffset = $globalHCSPARAMSOffset
    $rtsoff = $globalRTSOFF
    foreach ($hwid in $userDefinedData.Keys) {
        if ($deviceId -match $hwid) {
            $userDefinedController = $userDefinedData[$hwid]
            if ($userDefinedController.ContainsKey("INTERVAL"))            { $desiredInterval = $userDefinedController["INTERVAL"] }
            if ($userDefinedController.ContainsKey("HCSPARAMS_OFFSET"))    { $hcsparamsOffset = $userDefinedController["HCSPARAMS_OFFSET"] }
            if ($userDefinedController.ContainsKey("RTSOFF"))              { $rtsoff = $userDefinedController["RTSOFF"] }
        }
    }
}  
function Write-ControllerIMOD($controller, $deviceMap, $newInterval) {
    $deviceId = $controller.DeviceID
    if (-not $deviceMap.Contains($deviceId)) { return $false }
    $capabilityAddress = $deviceMap[$deviceId]
    $hcsparamsOffset = $globalHCSPARAMSOffset
    $rtsoff = $globalRTSOFF
    foreach ($hwid in $userDefinedData.Keys) {
        if ($deviceId -match $hwid) {
            $userDefinedController = $userDefinedData[$hwid]
            if ($userDefinedController.ContainsKey("HCSPARAMS_OFFSET")) { $hcsparamsOffset = $userDefinedController["HCSPARAMS_OFFSET"] }
            if ($userDefinedController.ContainsKey("RTSOFF"))           { $rtsoff          = $userDefinedController["RTSOFF"] }
        }
    }
}  
function main {
    if (-not (Is-Admin)) {
        Write-Host "error: administrator privileges required"
        return 1
    }
    if (-not (Test-Path $rwePath -PathType Leaf)) {
        Write-Host "error: $($rwePath) not exists, edit the script to change the path to Rw.exe"
        Write-Host "http://rweverything.com/download"
        return 1
    }
    Stop-Process -Name "Rw" -ErrorAction SilentlyContinue
    $deviceMap = Get-Device-Addresses
    foreach ($xhciController in Get-WmiObject Win32_USBController) {
        $isDisabled = $xhciController.ConfigManagerErrorCode -eq 22
        if ($isDisabled) { continue }
        $deviceId = $xhciController.DeviceID
        Write-Host "$($xhciController.Caption) - $($deviceId)"
        if (-not $deviceMap.Contains($deviceId)) {
            Write-Host "error: could not obtain base address`n"
            continue
        }
        $desiredInterval = $globalInterval
        $hcsparamsOffset = $globalHCSPARAMSOffset
        $rtsoff = $globalRTSOFF
        foreach ($hwid in $userDefinedData.Keys) {
            if ($deviceId -match $hwid) {
                $userDefinedController = $userDefinedData[$hwid]
                if ($userDefinedController.ContainsKey("INTERVAL")) {
                    $desiredInterval = $userDefinedController["INTERVAL"]
                }
                if ($userDefinedController.ContainsKey("HCSPARAPS_OFFSET")) {
                    $hcsparamsOffset = $userDefinedController["HCSPARAPS_OFFSET"]
                }
                if ($userDefinedController.ContainsKey("RTSOFF")) {
                    $rtsoff = $userDefinedController["RTSOFF"]
                }
            }
        }
        $capabilityAddress = $deviceMap[$deviceId]
        $HCSPARAMSValue = Get-Value-From-Address -address ($capabilityAddress + $hcsparamsOffset)
        $HCSPARAMSBitmask = [Convert]::ToString($HCSPARAMSValue, 2)
        $maxIntrs = [Convert]::ToInt32($HCSPARAMSBitmask.Substring($HCSPARAMSBitmask.Length - 16, 8), 2)
        $RTSOFFValue = Get-Value-From-Address -address ($capabilityAddress + $rtsoff)
        $runtimeAddress = $capabilityAddress + $RTSOFFValue
        for ($i = 0; $i -lt $maxIntrs; $i++) {
            $interrupterAddress = Dec-To-Hex -decimal ([uint64]($runtimeAddress + 0x24 + (0x20 * $i)))
            & $rwePath /Min /NoLogo /Stdout /Command="W32 $($interrupterAddress) $($desiredInterval)" | Write-Host
        }
        Write-Host
    }
    return 0
}
$_exitCode = main
exit $_exitCode
'@
    $startupPath = [Environment]::GetFolderPath('Startup')
    $scriptPath = Join-Path $startupPath "ApplyIMOD.ps1"
    Set-Content -Path $scriptPath -Value $scriptContent -Encoding UTF8
    [System.Windows.Forms.MessageBox]::Show(
        "IMOD script saved to:`n$scriptPath`n`nIt will run at every startup.",
        "IMOD Settings Saved",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Information
    )
})

$btnSetIMOD.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(255, 100, 45)
$btnSetIMOD.FlatAppearance.BorderSize = 1

$btnSetIMOD.Add_MouseEnter({
    $this.FlatAppearance.BorderColor = [System.Drawing.Color]::White
})

$btnSetIMOD.Add_MouseLeave({
    $this.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(255, 100, 45)
})

    $deviceControls[$device] = @{
        CurrentIMOD = $txtCurrentIMOD
        NewIMOD     = $txtNewIMOD
    }

    function Read-AndDisplayIMOD {
        $ctrls = $deviceControls[$device]
        $instanceId = Split-Path -Leaf $device.RegistryPath

        $controllers = Get-WmiObject Win32_USBController | Where-Object {
            $_.ConfigManagerErrorCode -ne 22
        }

        $matchedController = $null
        foreach ($controller in $controllers) {
            $controllerId = $controller.DeviceID -replace '\\\\', '\\'
            if ($controllerId -match [regex]::Escape($instanceId)) {
                $matchedController = $controller
                break
            }
        }

        if (-not $matchedController) {
            $ctrls.CurrentIMOD.Text = "Error: No matching controller"
            return
        }

        $imodValues = Read-ControllerIMOD $matchedController $globalDeviceAddressMap

        if ($imodValues) {
            $unique = $imodValues | Select-Object -Unique
            if ($unique.Count -eq 1) {
                $hexVal = "0x$($unique[0].ToString('X4'))"
                $ctrls.CurrentIMOD.Text = $hexVal
$ctrls.NewIMOD.Text = $hexVal
Update-IMOD-NsLabel -textBox $ctrls.NewIMOD -label $lblIMODns

            } else {
                $ctrls.CurrentIMOD.Text = "Multiple values"
            }
        } else {
            $ctrls.CurrentIMOD.Text = "Error reading"
        }
    }

    Read-AndDisplayIMOD

$btnSetIMOD.Add_Click({
    function Update-IMOD-NsLabel {
        param($textBox, $label)

        $raw = $textBox.Text.Trim()

        if ($raw -match '^0x[0-9A-Fa-f]{1,4}$') {
            try {
                $val = [Convert]::ToUInt16($raw, 16)
                $ns = $val * 250

                if ($ns -ge 1000) {
                    $usExact = $ns / 1000.0
                    $label.Text = "$usExact µs"
                } else {
                    $label.Text = "$ns ns"
                }
            } catch {
                $label.Text = ""
            }
        } else {
            $label.Text = ""
        }
    }

    $device = $this.Tag
    $ctrls = $deviceControls[$device]
    $newIMOD = $ctrls.NewIMOD.Text
    
    Write-Host "CurrentIMOD type: $($ctrls.CurrentIMOD.GetType().FullName)"
    Write-Host "NewIMOD type: $($ctrls.NewIMOD.GetType().FullName)"
    
    if (-not ($newIMOD -match '^0x[0-9A-Fa-f]{1,4}$')) {
        [System.Windows.Forms.MessageBox]::Show("Invalid IMOD format. Use hex format (e.g., 0x4E20)", "Error", "OK", "Error")
        return
    }
    
    $instanceId = Split-Path -Leaf $device.RegistryPath
    
    $controllers = Get-WmiObject Win32_USBController | Where-Object {
        $_.ConfigManagerErrorCode -ne 22
    }
    
    $matchedController = $null
    foreach ($controller in $controllers) {
        $controllerId = $controller.DeviceID -replace '\\\\', '\\' 
        if ($controllerId -match [regex]::Escape($instanceId)) {
            $matchedController = $controller
            break
        }
    }
    
    if (-not $matchedController) {
        [System.Windows.Forms.MessageBox]::Show("No matching controller found", "Error", "OK", "Error")
        return
    }
    
    $imodValue = [Convert]::ToUInt16($newIMOD, 16)  
    $result = Write-ControllerIMOD $matchedController $globalDeviceAddressMap $imodValue
    
    if ($result) {
        if ($ctrls.CurrentIMOD) {
            $objectType = $ctrls.CurrentIMOD.GetType().Name
            Write-Host "Attempting to update CurrentIMOD of type: $objectType"
            
            try {
                if ($objectType -eq "TextBox") {
                    $ctrls.CurrentIMOD.Text = "0x$($imodValue.ToString('X4'))"
                } elseif ($objectType -eq "Label") {
                    $ctrls.CurrentIMOD.Text = "0x$($imodValue.ToString('X4'))"
                } else {
                    if ($ctrls.CurrentIMOD | Get-Member -Name "Text") {
                        $ctrls.CurrentIMOD.Text = "0x$($imodValue.ToString('X4'))"
                    } else {
                        Write-Host "CurrentIMOD does not have Text property"
                    }
                }
            } catch {
                Write-Host "Error updating CurrentIMOD: $($_.Exception.Message)"
            }
        }
        
        if ($ctrls.NewIMOD -and $ctrls.IMODNsLabel) {
            try {
                Update-IMOD-NsLabel -textBox $ctrls.NewIMOD -label $ctrls.IMODNsLabel
            } catch {
                Write-Host "Error updating IMOD ns label: $($_.Exception.Message)"
            }
        }
    }
    else {
        [System.Windows.Forms.MessageBox]::Show("Failed to apply IMOD settings", "Error", "OK", "Error")
    }
})

$btnSetIMOD.Add_Click({
    function Update-IMOD-NsLabel {
        param($textBox, $label)

        $raw = $textBox.Text.Trim()

        if ($raw -match '^0x[0-9A-Fa-f]{1,4}$') {
            try {
                $val = [Convert]::ToUInt16($raw, 16)
                $ns = $val * 250

                if ($ns -ge 1000) {
                    $usExact = $ns / 1000.0
                    $label.Text = "$usExact µs"
                } else {
                    $label.Text = "$ns ns"
                }
            } catch {
                $label.Text = ""
            }
        } else {
            $label.Text = ""
        }
    }

    $device = $this.Tag
    $ctrls = $deviceControls[$device]
    $newIMOD = $ctrls.NewIMOD.Text
    
    if (-not ($newIMOD -match '^0x[0-9A-Fa-f]{1,4}$')) {
        [System.Windows.Forms.MessageBox]::Show("Invalid IMOD format. Use hex format (e.g., 0x4E20)", "Error", "OK", "Error")
        return
    }
    
    $instanceId = Split-Path -Leaf $device.RegistryPath
    
    $controllers = Get-WmiObject Win32_USBController | Where-Object {
        $_.ConfigManagerErrorCode -ne 22
    }
    
    $matchedController = $null
    foreach ($controller in $controllers) {
        $controllerId = $controller.DeviceID -replace '\\\\', '\\'
        if ($controllerId -match [regex]::Escape($instanceId)) {
            $matchedController = $controller
            break
        }
    }
    
    if (-not $matchedController) {
        [System.Windows.Forms.MessageBox]::Show("No matching controller found", "Error", "OK", "Error")
        return
    }
    
    $imodValue = [Convert]::ToUInt16($newIMOD, 16)
    $result = Write-ControllerIMOD $matchedController $globalDeviceAddressMap $imodValue
    
    if ($result) {
        $imodPanel = $this.Parent
        $currentIMODTextBox = $null
        
        foreach ($control in $imodPanel.Controls) {
            if ($control -is [System.Windows.Forms.TextBox] -and $control.Name -like "*Current*") {
                $currentIMODTextBox = $control
                break
            }
        }
        
        if ($currentIMODTextBox) {
            $currentIMODTextBox.Text = "0x$($imodValue.ToString('X4'))"
        }
        
        $nsLabel = $null
        foreach ($control in $imodPanel.Controls) {
            if ($control -is [System.Windows.Forms.Label] -and $control.ForeColor.Name -eq "ffa0a0a0") {
                $nsLabel = $control
                break
            }
        }
        
        if ($ctrls.NewIMOD -and $nsLabel) {
            Update-IMOD-NsLabel -textBox $ctrls.NewIMOD -label $nsLabel
        }
    }
    else {
        [System.Windows.Forms.MessageBox]::Show("Failed to apply IMOD settings", "Error", "OK", "Error")
    }
})

    $deviceControls[$device] = @{
        CheckBoxes    = $checkboxes;
        MaskLabel     = $lblMask;
        MaskValue     = $lblMaskValue;
        InitialValue  = $initialValue;
        MSICombo      = $cboMSI;
        MsgLimitBox   = $msgLimitBox;
        PriorityCombo = $cboPriority;
        PNPID         = $pnpId;
        IRQLabel      = $lblIRQ;
        IRQValueLabel = $lblIRQValue;
        CurrentIMOD   = $txtCurrentIMOD;
        NewIMOD       = $txtNewIMOD
        PolicyCombo   = $cboPolicy
        NumQueues     = $nudNumQueues
    }
    
    $btnReadIMOD.Add_Click({
        $device = $this.Tag
        $ctrls = $deviceControls[$device]
        
        $instanceId = Split-Path -Leaf $device.RegistryPath
        
        $controllers = Get-WmiObject Win32_USBController | Where-Object {
            $_.ConfigManagerErrorCode -ne 22
        }
        
        $matchedController = $null
        foreach ($controller in $controllers) {
            $controllerId = $controller.DeviceID -replace '\\\\', '\\'  
            if ($controllerId -match [regex]::Escape($instanceId)) {
                $matchedController = $controller
                break
            }
        }
        
        if (-not $matchedController) {
            $ctrls.CurrentIMOD.Text = "Error: No matching controller"
            return
        }
        
        $imodValues = Read-ControllerIMOD $matchedController $globalDeviceAddressMap
        
    if ($imodValues) {
        $unique = $imodValues | Select-Object -Unique
        if ($unique.Count -eq 1) {
            $ctrls.CurrentIMOD.Text = "0x$($unique[0].ToString('X4'))"
        } else {
            $ctrls.CurrentIMOD.Text = "Multiple values"
        }
    }
    else {
        $ctrls.CurrentIMOD.Text = "Error reading"
    }
})
    
    $btnSetIMOD.Add_Click({
        $device = $this.Tag
        $ctrls = $deviceControls[$device]
        $newIMOD = $ctrls.NewIMOD.Text
        
        if (-not ($newIMOD -match '^0x[0-9A-Fa-f]{1,4}$')) {
            [System.Windows.Forms.MessageBox]::Show("Invalid IMOD format. Use hex format (e.g., 0x4E20)", "Error", "OK", "Error")
            return
        }
        
        $instanceId = Split-Path -Leaf $device.RegistryPath
        
        $controllers = Get-WmiObject Win32_USBController | Where-Object {
            $_.ConfigManagerErrorCode -ne 22
        }
        
        $matchedController = $null
        foreach ($controller in $controllers) {
            $controllerId = $controller.DeviceID -replace '\\\\', '\\'  
            if ($controllerId -match [regex]::Escape($instanceId)) {
                $matchedController = $controller
                break
            }
        }
        
        if (-not $matchedController) {
            [System.Windows.Forms.MessageBox]::Show("No matching controller found", "Error", "OK", "Error")
            return
        }
        
    $imodValue = [Convert]::ToUInt16($newIMOD, 16)  
    $result = Write-ControllerIMOD $matchedController $globalDeviceAddressMap $imodValue
    
    if ($result) {
        $ctrls.CurrentIMOD.Text = "0x$($imodValue.ToString('X4'))"
    }
    else {
        [System.Windows.Forms.MessageBox]::Show("Failed to apply IMOD settings", "Error", "OK", "Error")
    }
})
}
else {
    $deviceControls[$device] = @{
        CheckBoxes    = $checkboxes;
        MaskLabel     = $lblMask;
        MaskValue     = $lblMaskValue;
        InitialValue  = $initialValue;
        MSICombo      = $cboMSI;
        MsgLimitBox   = $msgLimitBox;
        PriorityCombo = $cboPriority;
        PNPID         = $pnpId;
        IRQLabel      = $lblIRQ;
        IRQValueLabel = $lblIRQValue
        PolicyCombo   = $cboPolicy
        NumQueues     = $nudNumQueues
    }
}

    foreach ($chk in $checkboxes) {
        $chk.Add_CheckedChanged({
            param($sender, $e)
            if ($script:NDISUpdating) { return } 

            $parentGroup = $sender.Parent.Parent
            $dev = $parentGroup.Tag
            $ctrls = $deviceControls[$dev]

            if ($dev.Category -eq "Network" -and $dev.Role -eq "NDIS") {

                if ($sender.Checked) {
                    $baseCore = [int]$sender.Tag
                    $numQueues = 1
                    try { $numQueues = [int]$ctrls.NumQueues.Value } catch { $numQueues = 1 }
                    if ($numQueues -lt 1) { $numQueues = 1 }

                    $logicalCount = [Environment]::ProcessorCount
                    $selectedSet = @()
                    for ($i=0; $i -lt $numQueues; $i++) {
                        $c = ($baseCore + $i) % $logicalCount
                        $selectedSet += $c
                    }

                    $script:NDISUpdating = $true
                    foreach ($other in $ctrls.CheckBoxes) {
                        $core = [int]$other.Tag
                        if ($selectedSet -contains $core) {
                            $other.Checked = $true
                            $other.AutoCheck = $false
                        } else {
                            $other.Checked = $false
                            $other.AutoCheck = $true
                        }
                    }
                    $script:NDISUpdating = $false

                    $maskInt = 0
                    foreach ($c in $selectedSet) { $maskInt = $maskInt -bor (1 -shl $c) }
                    $ctrls.MaskValue.Text = "0x" + ([Convert]::ToString($maskInt,16)).ToUpper()
                }
                else {
                    $script:NDISUpdating = $true
                    foreach ($other in $ctrls.CheckBoxes) {
                        $other.Checked = $false
                        $other.AutoCheck = $true
                    }
                    $script:NDISUpdating = $false
                    $ctrls.MaskValue.Text = "0x0"
                }
            } else {
                $newHex = Calculate-AffinityHex $ctrls.CheckBoxes
                if ($newHex -eq "0x0") {
                    $ctrls.MaskLabel.Text = "Affinity Mask: "
                    $ctrls.MaskValue.Text = "0x0"
                } else {
                    $ctrls.MaskLabel.Text = "Affinity Mask: "
                    $ctrls.MaskValue.Text = $newHex
                }
            }
        })
    }
    $panel.Controls.Add($groupBox)
}

$btnSaveIMOD.Add_MouseEnter({
    $this.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(234,234,234)
    $this.FlatAppearance.BorderSize = 1
    $this.Refresh()
})
$btnSaveIMOD.Add_MouseLeave({
    $this.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(255,100,45)
    $this.FlatAppearance.BorderSize = 1
    $this.Refresh()
})
$btnSaveIMOD.Add_Click({
    $scriptContent = @'
$globalInterval = 0x0
$globalHCSPARAMSOffset = 0x4
$globalRTSOFF = 0x18
$userDefinedData = @{
'@
    $imodSettings = @{}
    foreach ($device in $deviceList | Where-Object { $_.Category -eq "USB" }) {
        $ctrls = $deviceControls[$device]
        $pnpId = $ctrls.PNPID
        
        if ($pnpId -match 'DEV_([0-9A-F]{4})') {
            $devId = "DEV_$($Matches[1])"
            $imodValue = $ctrls.NewIMOD.Text
            $imodSettings[$devId] = $imodValue
        }
    }
    foreach ($key in $imodSettings.Keys) {
        $scriptContent += "    `"$key`" = @{`r`n"
        $scriptContent += "        `"INTERVAL`" = $($imodSettings[$key])`r`n"
        $scriptContent += "    }`r`n"
    }
    $scriptContent += @'
}
$rwePath = "C:\Program Files (x86)\RW-Everything\Rw.exe"
function Dec-To-Hex($decimal) {
    return "0x$($decimal.ToString('X2'))"
}
function Get-Value-From-Address($address) {
    $address = Dec-To-Hex -decimal ([uint64]$address)
    $stdout = & $rwePath /Min /NoLogo /Stdout /Command="R32 $($address)" | Out-String
    $splitString = $stdout -split " "
    return [uint64]$splitString[-1]
}
function Get-Device-Addresses {
    $data = @{}
    $resources = Get-WmiObject -Class Win32_PNPAllocatedResource -ComputerName LocalHost -Namespace root\CIMV2
    foreach ($resource in $resources) {
        $deviceId = $resource.Dependent.Split("=")[1].Replace('"', '').Replace("\\", "\")
        $physicalAddress = $resource.Antecedent.Split("=")[1].Replace('"', '')
        if (-not $data.ContainsKey($deviceId) -and $deviceId -and $physicalAddress) {
            $data[$deviceId] = [uint64]$physicalAddress
        }
    }
    return $data
}
function Is-Admin {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
function Read-ControllerIMOD($controller, $deviceMap) {
    $deviceId = $controller.DeviceID
    if (-not $deviceMap.Contains($deviceId)) { return $null }
    $capabilityAddress = $deviceMap[$deviceId]
    $desiredInterval = $globalInterval
    $hcsparamsOffset = $globalHCSPARAMSOffset
    $rtsoff = $globalRTSOFF
    foreach ($hwid in $userDefinedData.Keys) {
        if ($deviceId -match $hwid) {
            $userDefinedController = $userDefinedData[$hwid]
            if ($userDefinedController.ContainsKey("INTERVAL"))            { $desiredInterval = $userDefinedController["INTERVAL"] }
            if ($userDefinedController.ContainsKey("HCSPARAMS_OFFSET"))    { $hcsparamsOffset = $userDefinedController["HCSPARAMS_OFFSET"] }
            if ($userDefinedController.ContainsKey("RTSOFF"))              { $rtsoff = $userDefinedController["RTSOFF"] }
        }
    }
}  
function Write-ControllerIMOD($controller, $deviceMap, $newInterval) {
    $deviceId = $controller.DeviceID
    if (-not $deviceMap.Contains($deviceId)) { return $false }
    $capabilityAddress = $deviceMap[$deviceId]
    $hcsparamsOffset = $globalHCSPARAMSOffset
    $rtsoff = $globalRTSOFF
    foreach ($hwid in $userDefinedData.Keys) {
        if ($deviceId -match $hwid) {
            $userDefinedController = $userDefinedData[$hwid]
            if ($userDefinedController.ContainsKey("HCSPARAMS_OFFSET")) { $hcsparamsOffset = $userDefinedController["HCSPARAMS_OFFSET"] }
            if ($userDefinedController.ContainsKey("RTSOFF"))           { $rtsoff          = $userDefinedController["RTSOFF"] }
        }
    }
}  
function main {
    if (-not (Is-Admin)) {
        Write-Host "error: administrator privileges required"
        return 1
    }
    if (-not (Test-Path $rwePath -PathType Leaf)) {
        Write-Host "error: $($rwePath) not exists, edit the script to change the path to Rw.exe"
        Write-Host "http://rweverything.com/download"
        return 1
    }
    Stop-Process -Name "Rw" -ErrorAction SilentlyContinue
    $deviceMap = Get-Device-Addresses
    foreach ($xhciController in Get-WmiObject Win32_USBController) {
        $isDisabled = $xhciController.ConfigManagerErrorCode -eq 22
        if ($isDisabled) { continue }
        $deviceId = $xhciController.DeviceID
        Write-Host "$($xhciController.Caption) - $($deviceId)"
        if (-not $deviceMap.Contains($deviceId)) {
            Write-Host "error: could not obtain base address`n"
            continue
        }
        $desiredInterval = $globalInterval
        $hcsparamsOffset = $globalHCSPARAMSOffset
        $rtsoff = $globalRTSOFF
        foreach ($hwid in $userDefinedData.Keys) {
            if ($deviceId -match $hwid) {
                $userDefinedController = $userDefinedData[$hwid]
                if ($userDefinedController.ContainsKey("INTERVAL")) {
                    $desiredInterval = $userDefinedController["INTERVAL"]
                }
                if ($userDefinedController.ContainsKey("HCSPARAPS_OFFSET")) {
                    $hcsparamsOffset = $userDefinedController["HCSPARAPS_OFFSET"]
                }
                if ($userDefinedController.ContainsKey("RTSOFF")) {
                    $rtsoff = $userDefinedController["RTSOFF"]
                }
            }
        }
        $capabilityAddress = $deviceMap[$deviceId]
        $HCSPARAMSValue = Get-Value-From-Address -address ($capabilityAddress + $hcsparamsOffset)
        $HCSPARAMSBitmask = [Convert]::ToString($HCSPARAMSValue, 2)
        $maxIntrs = [Convert]::ToInt32($HCSPARAMSBitmask.Substring($HCSPARAMSBitmask.Length - 16, 8), 2)
        $RTSOFFValue = Get-Value-From-Address -address ($capabilityAddress + $rtsoff)
        $runtimeAddress = $capabilityAddress + $RTSOFFValue
        for ($i = 0; $i -lt $maxIntrs; $i++) {
            $interrupterAddress = Dec-To-Hex -decimal ([uint64]($runtimeAddress + 0x24 + (0x20 * $i)))
            & $rwePath /Min /NoLogo /Stdout /Command="W32 $($interrupterAddress) $($desiredInterval)" | Write-Host
        }
        Write-Host
    }
    return 0
}
$_exitCode = main
exit $_exitCode
'@
    $startupPath = [Environment]::GetFolderPath('Startup')
    $scriptPath = Join-Path $startupPath "ApplyIMOD.ps1"
    Set-Content -Path $scriptPath -Value $scriptContent -Encoding UTF8
    [System.Windows.Forms.MessageBox]::Show(
        "IMOD script saved to:`n$scriptPath`n`nIt will run at every startup.",
        "IMOD Settings Saved",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Information
    )
})

$form.SuspendLayout()
$panel.SuspendLayout()

$bindingFlags = [System.Reflection.BindingFlags] "NonPublic, Instance"
$form.GetType().GetProperty('DoubleBuffered', $bindingFlags).SetValue($form, $true, $null)
$panel.GetType().GetProperty('DoubleBuffered', $bindingFlags).SetValue($panel, $true, $null)

$topPos = $btnAutoOpt.Bottom + 26
foreach ($dev in $deviceList) {
    Create-DeviceGroupBox $dev $topPos
    $boxHeight = if ($dev.Category -eq "USB") { 395 } else { 340 }
    $topPos += $boxHeight + $deviceBoxSpacing 
}

$topPos = Create-ReservedCpuSetsUI -topPos $topPos

$panel.ResumeLayout()
$form.ResumeLayout()

$btnApply.Add_Click({
    $occupiedCores = @()
    $weakOccupiedCores = @()          
    $logicalCount = [Environment]::ProcessorCount

    foreach ($device in $deviceList) {
        $normRoles = @()
        foreach ($rr in $device.Roles) {
            if (-not $rr) { continue }
            $parts = $rr -split '[\/,;]+' 
            foreach ($pp in $parts) {
                $tokRaw = $pp.Trim()
                if ($tokRaw -eq '') { continue }
                $l = $tokRaw.ToLower()
                if ($l -match 'mic|microphone')                      { $tok = 'Audio' }
                elseif ($l -match 'headphone|headphones|headset')   { $tok = 'Audio' }
                elseif ($l -match 'earphone|earphones|iem')         { $tok = 'Audio' }
                elseif ($l -match 'speaker|speakers')               { $tok = 'Audio' }
                elseif ($l -match '^audio$')                        { $tok = 'Audio' }
                elseif ($l -match 'keyboard|kbd')                   { $tok = 'Keyboard' }
                elseif ($l -match 'mouse|ms')                       { $tok = 'Mouse' }
                else                                                 { $tok = $tokRaw }
                if (-not ($normRoles -contains $tok)) { $normRoles += $tok }
            }
        }
        $ctrls = $deviceControls[$device]

        if ($device.Category -eq "Network" -and $device.Role -eq "NDIS") {
            $selectedBase = $null
            foreach ($chk in $ctrls.CheckBoxes) { if ($chk.Checked) { $selectedBase = [int]$chk.Tag; break } }
            if ($selectedBase -eq $null) { $assignedCores = @(); $valueToSet = "" }
            else {
                $numQueuesToWrite = 1
                try { $numQueuesToWrite = [int]$ctrls.NumQueues.Value } catch { $numQueuesToWrite = 1 }
                if ($numQueuesToWrite -lt 1) { $numQueuesToWrite = 1 }

                $valueToSet = "$selectedBase"
                try {
                    Set-ItemProperty -Path $device.RegistryPath -Name "*RssBaseProcNumber" -Value $valueToSet -Type String -ErrorAction Stop
                } catch { }

                try {
                    Set-ItemProperty -Path $device.RegistryPath -Name "*NumRssQueues" -Value ("$numQueuesToWrite") -Type String -ErrorAction Stop
                } catch { }

                $assignedCores = @()
                $logicalCount = [Environment]::ProcessorCount
                for ($i=0; $i -lt $numQueuesToWrite; $i++) {
                    $c = ($selectedBase + $i) % $logicalCount
                    $assignedCores += $c
                }
            }
        }
        elseif ($device.Category -eq "Network" -and $device.Role -eq "NetAdapterCx") {
            $targetRegistryPath = Get-NetworkAdapterAffinityRegistryPath $device
            $computed = Calculate-AffinityHex $ctrls.CheckBoxes
            if ($computed -eq "0x0") { }
            $result = Set-DeviceAffinity $targetRegistryPath $computed
            if ($result) { }
            $maskText = $ctrls.MaskValue.Text -replace "0x",""
            $assignedCores = @()
            if ($maskText -and ([int]::TryParse($maskText, [System.Globalization.NumberStyles]::HexNumber, $null, [ref]$null))) {
                $maskInt = [Convert]::ToInt64($maskText, 16)
                $binary = [Convert]::ToString($maskInt, 2).PadLeft($logicalCount, '0')
                for ($i = 0; $i -lt $binary.Length; $i++) {
                    if ($binary[$i] -eq '1') {
                        $assignedCores += ($binary.Length - $i - 1)
                    }
                }
            }
        }
        else {
            $computed = Calculate-AffinityHex $ctrls.CheckBoxes
            if ($computed -eq "0x0") { }
            $result = Set-DeviceAffinity $device.RegistryPath $computed
            if ($result) { }
            $maskText = $ctrls.MaskValue.Text -replace "0x",""
            $assignedCores = @()
            if ($maskText -and ([int]::TryParse($maskText, [System.Globalization.NumberStyles]::HexNumber, $null, [ref]$null))) {
                $maskInt = [Convert]::ToInt64($maskText, 16)
                $binary = [Convert]::ToString($maskInt, 2).PadLeft($logicalCount, '0')
                for ($i = 0; $i -lt $binary.Length; $i++) {
                    if ($binary[$i] -eq '1') {
                        $assignedCores += ($binary.Length - $i - 1)
                    }
                }
            }
        }

        if ($device.Category -eq "Network") {
            $targetRegistryPath = Get-NetworkAdapterMSIRegistryPath $device
        } else {
            $targetRegistryPath = $device.RegistryPath
        }
        $msiEnabled = 0
        if ($ctrls.MSICombo.SelectedItem -eq "Enabled") { $msiEnabled = 1 } else { $msiEnabled = 0 }
        $msgLimit = $ctrls.MsgLimitBox.Text
        if ($msgLimit -eq "Unlimited" -or $msgLimit -eq "0") {
            $msgLimit = ""
        }
        if ($msgLimit -eq "") { $displayMsgLimit = "Unlimited" } else { $displayMsgLimit = $msgLimit }
        $msiResult = Set-DeviceMSI $targetRegistryPath $msiEnabled $msgLimit
        if (-not $msiResult) { }
        $priorityVal = 2
        switch ($ctrls.PriorityCombo.SelectedItem) {
            "Low" { $priorityVal = 1 }
            "Normal" { $priorityVal = 2 }
            "High" { $priorityVal = 3 }
        }
        $priResult = Set-DevicePriority $targetRegistryPath $priorityVal
        if (-not $priResult) { }

        if (-not ($device.Category -eq "Network" -and $device.Role -eq "NDIS")) {
            $policyValue = $ctrls.PolicyCombo.SelectedIndex
            $policyResult = Set-DevicePolicy $device.RegistryPath $policyValue
        }

        $shouldConsiderCores = $false
        if ($device.Category -eq "Network" -and $device.Role -eq "NDIS") {
            $shouldConsiderCores = $true
        } else {
            if ($deviceControls[$device].ContainsKey('PolicyCombo')) {
                $policyValue = $deviceControls[$device].PolicyCombo.SelectedIndex
                if ($policyValue -eq 4) {
                    $shouldConsiderCores = $true
                }
            }
        }

        if ($shouldConsiderCores) {
            if (-not $assignedCores -or $assignedCores.Count -eq 0) {
                $ctrls = $deviceControls[$device]
                $assignedCores = @()
                $maskText = ($ctrls.MaskValue.Text -replace "0x","").Trim()
                if ($maskText -and ([int]::TryParse($maskText, [System.Globalization.NumberStyles]::HexNumber, $null, [ref]$null))) {
                    $maskInt = [Convert]::ToInt64($maskText, 16)
                    for ($i = 0; $i -lt [Environment]::ProcessorCount; $i++) {
                        if (($maskInt -band (1 -shl $i)) -ne 0) { $assignedCores += $i }
                    }
                } else {
                    foreach ($chk in $ctrls.CheckBoxes) {
                        if ($chk.Checked) { $assignedCores += [int]$chk.Tag }
                    }
                    $assignedCores = $assignedCores | Select-Object -Unique
                }
            }
            if ($device.Category -eq "PCI" -and $device.Role -eq "GPU") {
                $occupiedCores += $assignedCores
            }
            elseif ($device.Category -eq "USB" -and ($normRoles -contains "Mouse" -or $normRoles -contains "Controller")) {
                $occupiedCores += $assignedCores
            }
            elseif ($device.Category -eq "USB" -and ($normRoles -contains "Audio") -and ($normRoles.Count -eq 1)) {
                $weakOccupiedCores += $assignedCores
            }
            elseif ($device.Category -eq "PCI" -and $device.Role -eq "Audio") {
                $weakOccupiedCores += $assignedCores
            }
            elseif ($device.Category -eq "Network") {
                $weakOccupiedCores += $assignedCores
            }
            elseif ($normRoles -contains "Keyboard" -and $normRoles -contains "Audio") {
                $weakOccupiedCores += $assignedCores
            }
            elseif ($device.Category -eq "USB" -and ($normRoles -contains "Keyboard") -and ($normRoles.Count -eq 1)) {
                $weakOccupiedCores += $assignedCores
            }
            else {
                if ($assignedCores) {
                    $weakOccupiedCores += $assignedCores
                }
            }
        }
    }

    $occupiedCores = $occupiedCores | Select-Object -Unique | Sort-Object
    $occupiedCoresString = $occupiedCores -join ','

    $weakOccupiedCores = $weakOccupiedCores | Select-Object -Unique | Sort-Object
    $weakOccupiedCoresString = $weakOccupiedCores -join ','

    $mouseCore = $null 
    foreach ($dev in $deviceList) {
        if ($dev.Category -eq "USB" -and $dev.Roles -contains "Mouse") {
            $ctrls = $deviceControls[$dev]
            $maskValue = $ctrls.MaskValue.Text -replace "0x",""

            if ([int]::TryParse($maskValue, [System.Globalization.NumberStyles]::HexNumber, $null, [ref]$null)) {
                $maskInt = [Convert]::ToInt64($maskValue, 16)
                if ($maskInt -gt 0) {
                    for ($i = 0; $i -lt [Environment]::ProcessorCount; $i++) {
                        if (($maskInt -band (1 -shl $i)) -ne 0) {
                            $mouseCore = $i
                            break
                        }
                    }
                }
            }
            break
        }
    }

    Refresh-DeviceUI

    $scriptPath = $MyInvocation.MyCommand.Path
    $scriptDir = if ($scriptPath) { Split-Path -Parent $scriptPath } else { Get-Location }
    $gamesCfgPath = Join-Path $scriptDir "games_priorities.cfg"
    $systemCfgPath = Join-Path $scriptDir "system_priorities.cfg"

    function Update-ConfigFile {
        param (
            [string]$filePath,
            [string]$coresString,
            [string]$weakCoresString = "",   
            [int]   $mouseCore = -1,
            [int]   $dwmCore   = -1
        )
        $content = if (Test-Path $filePath) { 
            [System.IO.File]::ReadAllText($filePath, [System.Text.Encoding]::UTF8) 
        } else { 
            "" 
        }

        if ($dwmCore -ge 0 -and $filePath.EndsWith("system_priorities.cfg")) {
            $pattern = 'threaddesc=DWM Kernel Sensor Thread, \(.*?\)'
            $replacement = "threaddesc=DWM Kernel Sensor Thread, ($dwmCore)"
            $content = $content -replace $pattern, $replacement
        }

        if ($mouseCore -ge 0 -and $filePath.EndsWith("system_priorities.cfg")) {
            $pattern = 'threaddesc=DWM Master Input Thread, \(.*?\)'
            $replacement = "threaddesc=DWM Master Input Thread, ($mouseCore)"
            $content = $content -replace $pattern, $replacement
        }

        $content = $content -replace '(?m)^occupied_affinity_cores=.*$', "occupied_affinity_cores=$coresString"
        $content = $content -replace '(?m)^occupied_ideal_processor_cores=.*$', "occupied_ideal_processor_cores=$coresString"

        $content = $content -replace '(?m)^occupied_weak_affinity_cores=.*$', "occupied_weak_affinity_cores=$weakCoresString"
        $content = $content -replace '(?m)^occupied_weak_ideal_processor_cores=.*$', "occupied_weak_ideal_processor_cores=$weakCoresString"

        if (-not ($content -match "occupied_affinity_cores=")) {
            $content += "`r`noccupied_affinity_cores=$coresString"
        }
        if (-not ($content -match "occupied_ideal_processor_cores=")) {
            $content += "`r`noccupied_ideal_processor_cores=$coresString"
        }

        if (-not ($content -match "occupied_weak_affinity_cores=")) {
            $content += "`r`noccupied_weak_affinity_cores=$weakCoresString"
        }
        if (-not ($content -match "occupied_weak_ideal_processor_cores=")) {
            $content += "`r`noccupied_weak_ideal_processor_cores=$weakCoresString"
        }

        [System.IO.File]::WriteAllText($filePath, $content.Trim(), [System.Text.UTF8Encoding]::new($false))
    }

    Update-ConfigFile -filePath $gamesCfgPath -coresString $occupiedCoresString -weakCoresString $weakOccupiedCoresString
    Update-ConfigFile -filePath $systemCfgPath -coresString $occupiedCoresString -weakCoresString $weakOccupiedCoresString -mouseCore $mouseCore -dwmCore $dwmCore

    [System.Windows.Forms.MessageBox]::Show("Settings applied. A system restart required.", "Done")
})

function Get-AutoOptRoles($device) {

    function Normalize-RawRoles($rawRoles) {
        $norm = @()
        foreach ($r in $rawRoles) {
            if (-not $r) { continue }
            $parts = $r -split '[\/,;]+' 
            foreach ($p in $parts) {
                $t = $p.Trim()
                if ($t -eq '') { continue }
                $lt = $t.ToLower()
                if ($lt -match 'mic|microphone')                      { $tok = 'Audio' }
                elseif ($lt -match 'headphone|headphones|headset')   { $tok = 'Audio' }
                elseif ($lt -match 'earphone|earphones|iem')         { $tok = 'Audio' }
                elseif ($lt -match 'speaker|speakers')               { $tok = 'Audio' }
                elseif ($lt -match '^audio$')                        { $tok = 'Audio' }
                elseif ($lt -match 'keyboard|kbd')                   { $tok = 'Keyboard' }
                elseif ($lt -match 'mouse|ms')                       { $tok = 'Mouse' }
                else                                                 { $tok = $t }  
                if (-not ($norm -contains $tok)) { $norm += $tok }
            }
        }
        return $norm
    }

    if ($device.Category -eq 'USB') {
        $normRoles = Normalize-RawRoles $device.Roles
        $nonAudio = $normRoles | Where-Object { $_ -ne 'Audio' }
        if (-not $nonAudio -and $normRoles.Count -gt 0) { return @('Audio') }

        $result = @()
        if ($normRoles -contains 'Audio') { $result += 'Audio' }
        foreach ($t in $normRoles) { if ($t -ne 'Audio' -and -not ($result -contains $t)) { $result += $t } }
        return $result
    }

    return Normalize-RawRoles $device.Roles
}

function Get-PCoreIndices {
    $pCoreIndices = @()
    $logicalCount = [Environment]::ProcessorCount
    for ($i = 0; $i -lt $logicalCount; $i++) {
        if (Is-PCore $i) {
            $pCoreIndices += $i
        }
    }
    return $pCoreIndices
}

function Get-SmtSets($logicalCount, $pCores) {
    $smtSets = @()
    $maxSetIndex = [math]::Floor(($logicalCount - 1) / 2)
    for ($set = 0; $set -le $maxSetIndex; $set++) {
        $coreA = $set * 2
        $coreB = $coreA + 1
        if ($coreB -ge $logicalCount) { continue }
        if (($pCores -contains $coreA) -and ($pCores -contains $coreB)) {
            $smtSets += @{ Id = [int]$set; Cores = @($coreA, $coreB) }
        }
    }
    return $smtSets
}

function CoreMaskFromIndex($coreIndex) {
    $maskInt = [uint64](1 -shl $coreIndex)
    return ("{0:X16}" -f $maskInt)
}

function Reserve-Core($core, [ref]$usedCores, [ref]$usedSmtSets, $smtSetId) {
    $usedCores.Value[$core] = $true
    if ($smtSetId -ne $null) { $usedSmtSets.Value[$smtSetId] = $true }
}

function Get-SmtSetIdForCore($core, $smtSets) {
    if ($null -eq $smtSets -or $smtSets.Count -eq 0) { return $null }
    $setId = [int]([math]::Floor($core / 2))
    foreach ($s in $smtSets) {
        if ($s.Id -eq $setId) { return $setId }
    }
    return $null
}

function Find-FreeSmtSetCore([ref]$usedCoresRef, [ref]$usedSmtRef, $smtSets) {
    $freeSets = $smtSets | Where-Object { -not $usedSmtRef.Value.ContainsKey($_.Id) }
    if (-not $freeSets -or $freeSets.Count -eq 0) { return $null }
    $choice = Get-Random -InputObject $freeSets
    foreach ($c in $choice.Cores) {
        if (-not $usedCoresRef.Value.ContainsKey($c)) {
            return @{ Core = $c; SmtId = $choice.Id }
        }
    }
    return $null
}

function Find-FreePCore([ref]$usedCoresRef, [ref]$usedSmtRef, $pCoreIndices, $smtSets) {
    $res = Find-FreeSmtSetCore -usedCoresRef $usedCoresRef -usedSmtRef $usedSmtRef -smtSets $smtSets
    if ($res) { return $res }
    $free = $pCoreIndices | Where-Object { -not $usedCoresRef.Value.ContainsKey($_) }
    if ($free.Count -gt 0) {
        $core = Get-Random -InputObject $free
        $smtId = Get-SmtSetIdForCore -core $core -smtSets $smtSets
        return @{ Core = $core; SmtId = $smtId }
    }
    return $null
}

function Find-FreeECore([ref]$usedCoresRef, $eCoreIndices) {
    if ($eCoreIndices.Count -eq 0) { return $null }
    $free = $eCoreIndices | Where-Object { -not $usedCoresRef.Value.ContainsKey($_) }
    if ($free.Count -gt 0) { return (Get-Random -InputObject $free) }
    return $null
}

function Find-ShareableCore($preferredSharingPartners, [ref]$usedCoresRef, [ref]$usedSmtRef, $smtSets, [bool]$preferSmt, $assignedMap) {
    foreach ($kv in $assignedMap.GetEnumerator()) {
        $dev = $kv.Key
        $coresAssigned = $kv.Value
        $occupantRoles = Get-AutoOptRoles($dev)
        $ok = $false
        foreach ($r in $occupantRoles) { if ($preferredSharingPartners -contains $r) { $ok = $true; break } }
        if (-not $ok) { continue }

        foreach ($c in $coresAssigned) {
            $smtId = Get-SmtSetIdForCore -core $c -smtSets $smtSets
            if ($preferSmt -and $smtId -ne $null) {
                return @{ Core = $c; SmtId = $smtId; ShareMode = 'SMT' }
            } else {
                return @{ Core = $c; SmtId = $smtId; ShareMode = 'Core' }
            }
        }
    }
    return $null
}

$btnAutoOpt.Add_Click({
    try {
        Write-Host "`n[AutoOpt] Starting Auto-Optimization..." -ForegroundColor Cyan
        $logicalCount = [Environment]::ProcessorCount
        $cpu = Get-WmiObject Win32_Processor | Select-Object -First 1
        $physicalCount = $cpu.NumberOfCores
        $htEnabled = ($logicalCount -gt $physicalCount)
        $pCoreIndices = Get-PCoreIndices
        $eCoreIndices = @()
        for ($i = 0; $i -lt $logicalCount; $i++) {
            if (-not ($pCoreIndices -contains $i)) { $eCoreIndices += $i }
        }
        if ($pCoreIndices.Count -gt 0) {
            $pMin = ($pCoreIndices | Measure-Object -Minimum).Minimum
            $pMax = ($pCoreIndices | Measure-Object -Maximum).Maximum
            $cpuLayoutStr = "Cpu $pMin - cpu $pMax are p-cores, other cores are e-cores"
        } else {
            $cpuLayoutStr = "No P-cores detected"
        }
        Write-Host "[AutoOpt] logical=$logicalCount physical=$physicalCount HT=$htEnabled"
        Write-Host "[AutoOpt] P-cores: $($pCoreIndices -join ', ')"
        Write-Host "[AutoOpt] E-cores: $($eCoreIndices -join ', ')"
        Write-Host "[AutoOpt] Layout: $cpuLayoutStr"

        $targetCores = @(0..($logicalCount - 1))
        $core0SoftAvoid = $false
        if ($script:IsDualCCDCpu) {
            $targetCores = $script:Ccd1Cores
            $pCoreIndices = $pCoreIndices | Where-Object { $targetCores -contains $_ }
            $eCoreIndices = $eCoreIndices | Where-Object { $targetCores -contains $_ }
            Write-Host "[AutoOpt] Dual-CCD CPU detected. Restricting all assignments to CCD1 cores: $($targetCores -join ', ')"
            $core0SoftAvoid = $true
        } else {
            if ($hasAudioDevices) {
                $smtId0 = Get-SmtSetIdForCore -core 0 -smtSets $smtSets
                Reserve-Core 0 ([ref]$usedCores) ([ref]$usedSmtSets) $smtId0
                Write-Host "[AutoOpt] Audio detected -> hard-reserved core 0 and SMT set $smtId0"
            } else {
                $core0SoftAvoid = $true
                Write-Host "[AutoOpt] No audio detected -> soft-avoiding core 0 for allocations"
            }
        }

        if ($htEnabled) {
            $smtSets = Get-SmtSets -logicalCount $logicalCount -pCores $pCoreIndices
        } else {
            $smtSets = @()
        }
        $smtCount = if ($smtSets) { $smtSets.Count } else { 0 }
        Write-Host "[AutoOpt] SMT sets available (count=$smtCount):"
        if ($smtCount -gt 0) {
            foreach ($s in $smtSets) { Write-Host "  Set# $($s.Id) => cores $($s.Cores[0]) & $($s.Cores[1])" }
        }
        $usedCores = @{}
        $usedSmtSets = @{}
        $assignedMap = @{}
        $occupiedCores = @()
        $weakOccupiedCores = @()
        $gpus = $deviceList | Where-Object { $_.Category -eq 'PCI' -and $_.Role -eq 'GPU' }
        $nics = $deviceList | Where-Object { $_.Category -eq 'Network' }
        $usbs = $deviceList | Where-Object { $_.Category -eq 'USB' }
        $ssds = $deviceList | Where-Object { $_.Category -eq 'SSD' }
        $audioPCI = $deviceList | Where-Object { $_.Category -eq 'PCI' -and $_.Role -eq 'Audio' }
        $usbSingleAudio = $usbs | Where-Object {
            $norm = Get-AutoOptRoles $_
            ($norm.Count -eq 1) -and ($norm -contains 'Audio')
        }
        $hasAudioDevices = ($audioPCI.Count -gt 0) -or ($usbSingleAudio.Count -gt 0)

        function Find-FreePCoreLocal([ref]$usedCoresRef, [ref]$usedSmtRef, $pCoreIndicesParam, $smtSetsParam, [bool]$avoidCore0) {
            if ($avoidCore0) {
                $smtSetsNo0 = $smtSetsParam | Where-Object { -not ($_.Cores -contains 0) }
                foreach ($s in $smtSetsNo0) {
                    if (-not $usedSmtRef.Value.ContainsKey($s.Id)) {
                        foreach ($c in $s.Cores) {
                            if (-not $usedCoresRef.Value.ContainsKey($c)) {
                                return @{ Core = $c; SmtId = $s.Id }
                            }
                        }
                    }
                }
                $pNo0 = $pCoreIndicesParam | Where-Object { $_ -ne 0 }
                $free = $pNo0 | Where-Object { -not $usedCoresRef.Value.ContainsKey($_) }
                if ($free.Count -gt 0) {
                    $core = Get-Random -InputObject $free
                    $smtId = Get-SmtSetIdForCore -core $core -smtSets $smtSetsParam
                    return @{ Core = $core; SmtId = $smtId }
                }
            }
            foreach ($s in $smtSetsParam) {
                if (-not $usedSmtRef.Value.ContainsKey($s.Id)) {
                    foreach ($c in $s.Cores) {
                        if (-not $usedCoresRef.Value.ContainsKey($c)) {
                            return @{ Core = $c; SmtId = $s.Id }
                        }
                    }
                }
            }
            $freeAll = $pCoreIndicesParam | Where-Object { -not $usedCoresRef.Value.ContainsKey($_) }
            if ($freeAll.Count -gt 0) {
                $core = Get-Random -InputObject $freeAll
                $smtId = Get-SmtSetIdForCore -core $core -smtSets $smtSetsParam
                return @{ Core = $core; SmtId = $smtId }
            }
            return $null
        }

        foreach ($gpu in $gpus) {
            Write-Host "[AutoOpt][GPU] Picking for GPU: $($gpu.DisplayName)"
            $assigned = @()
            $gpuAvoidCore0 = $core0SoftAvoid
            if ($htEnabled -and $smtSets.Count -ge 2) {
                $availableSets = $smtSets | Where-Object { -not $usedSmtSets.ContainsKey($_.Id) }
                $availableSetsNo0 = $availableSets | Where-Object { -not ($_.Cores -contains 0) }
                if ($availableSetsNo0.Count -ge 2) {
                    $chosen = Get-Random -InputObject $availableSetsNo0 -Count 2
                } elseif ($availableSets.Count -ge 2) {
                    $chosen = Get-Random -InputObject $availableSets -Count 2
                } else {
                    $chosen = @()
                }
                foreach ($cset in $chosen) {
                    $coreChoice = $null
                    foreach ($c in $cset.Cores) {
                        if ($c -ne 0 -and -not $usedCores.ContainsKey($c)) { $coreChoice = $c; break }
                    }
                    if ($coreChoice -eq $null) {
                        foreach ($c in $cset.Cores) { if (-not $usedCores.ContainsKey($c)) { $coreChoice = $c; break } }
                    }
                    if ($coreChoice -eq $null) { $coreChoice = $cset.Cores[0] }
                    $assigned += $coreChoice
                    Reserve-Core $coreChoice ([ref]$usedCores) ([ref]$usedSmtSets) $cset.Id
                }
                if ($assigned.Count -lt 2) {
                    $tries = 0
                    while ($assigned.Count -lt 2 -and $tries -lt 200) {
                        $f = Find-FreePCoreLocal -usedCoresRef ([ref]$usedCores) -usedSmtRef ([ref]$usedSmtSets) -pCoreIndicesParam $pCoreIndices -smtSetsParam $smtSets -avoidCore0 $gpuAvoidCore0
                        if ($f -ne $null) {
                            if (-not ($assigned -contains $f.Core)) {
                                $assigned += $f.Core
                                Reserve-Core $f.Core ([ref]$usedCores) ([ref]$usedSmtSets) $f.SmtId
                            }
                        } else { break }
                        $tries++
                    }
                }
            } else {
                $tries = 0
                while ($assigned.Count -lt 2 -and $tries -lt 200) {
                    $f = Find-FreePCoreLocal -usedCoresRef ([ref]$usedCores) -usedSmtRef ([ref]$usedSmtSets) -pCoreIndicesParam $pCoreIndices -smtSetsParam $smtSets -avoidCore0 $gpuAvoidCore0
                    if ($f -ne $null) {
                        $assigned += $f.Core
                        Reserve-Core $f.Core ([ref]$usedCores) ([ref]$usedSmtSets) $f.SmtId
                    } else { break }
                    $tries++
                }
            }
            $assigned = $assigned | Select-Object -Unique
            if ($assigned.Count -eq 0) {
                Write-Host "[AutoOpt][GPU] WARNING - couldn't assign GPU cores" -ForegroundColor Yellow
                $assignedMap[$gpu] = @()
            } else {
                $assignedMap[$gpu] = $assigned
                $maskInt = 0
                foreach ($c in $assigned) { $maskInt = $maskInt -bor (1 -shl $c) }
                $hexMask = "{0:X16}" -f ([uint64]$maskInt)
                Write-Host "[AutoOpt][GPU] Setting GPU affinity: $($gpu.RegistryPath) -> cores [$($assigned -join ', ')] mask 0x$hexMask"
                $res = Set-DeviceAffinity $gpu.RegistryPath ("0x" + $hexMask)
                Write-Host "[AutoOpt][GPU] Set-DeviceAffinity returned: $res"
                $occupiedCores += $assigned
            }
        }

        foreach ($nic in $nics) {
            Write-Host "[AutoOpt][NIC] Assigning NIC: $($nic.DisplayName) Role=$($nic.Role)"
            $f = Find-FreePCoreLocal -usedCoresRef ([ref]$usedCores) -usedSmtRef ([ref]$usedSmtSets) -pCoreIndicesParam $pCoreIndices -smtSetsParam $smtSets -avoidCore0 $core0SoftAvoid
            $shared = $false
            if ($f -eq $null) {
                $preferred = @('Audio','Keyboard','Mouse')
                $share = Find-ShareableCore -preferredSharingPartners $preferred -usedCoresRef ([ref]$usedCores) -usedSmtRef ([ref]$usedSmtSets) -smtSets $smtSets -preferSmt $true -assignedMap $assignedMap
                if ($share) {
                    $f = @{ Core = $share.Core; SmtId = $share.SmtId; Shared = $true }
                    $shared = $true
                    Write-Host "[AutoOpt][NIC] No free P-core; allowing sharing on core $($f.Core) (mode $($share.ShareMode))"
                }
            }
            if ($f -ne $null) {
                $core = $f.Core
                $smtid = $f.SmtId
                if (-not $f.Shared) { Reserve-Core $core ([ref]$usedCores) ([ref]$usedSmtSets) $smtid }
                $assignedMap[$nic] = @($core)
                if ($nic.Role -eq 'NDIS') {
                    try {
                        $valueToSet = "$core"
                        Set-ItemProperty -Path $nic.RegistryPath -Name "*RssBaseProcNumber" -Value $valueToSet -Type String -ErrorAction Stop
                        Write-Host "[AutoOpt][NIC] Wrote *RssBaseProcNumber to $($nic.RegistryPath) -> $valueToSet"
                    } catch {
                        Write-Host "[AutoOpt][NIC] Failed to write *RssBaseProcNumber to $($nic.RegistryPath): $_" -ForegroundColor Yellow
                    }
                } else {
                    $targetRegistryPath = Get-NetworkAdapterAffinityRegistryPath $nic
                    $mask = "{0:X16}" -f ([uint64](1 -shl $core))
                    Write-Host "[AutoOpt][NIC] Setting affinity via Set-DeviceAffinity at $targetRegistryPath -> core $core mask 0x$mask"
                    $res = Set-DeviceAffinity $targetRegistryPath ("0x" + $mask)
                    Write-Host "[AutoOpt][NIC] Set-DeviceAffinity returned: $res"
                }
                $weakOccupiedCores += @($core)
            } else {
                Write-Host "[AutoOpt][NIC] WARNING - could not allocate NIC a P-core" -ForegroundColor Yellow
                $assignedMap[$nic] = @()
            }
        }

        foreach ($usb in $usbs) {
            $roles = Get-AutoOptRoles $usb
            $isControllerRole = ($roles -contains 'Controller')
            $hasMouse = ($roles -contains 'Mouse')
            $singleAudio = ($roles.Count -eq 1 -and $roles -contains 'Audio')
            $singleKeyboard = ($roles.Count -eq 1 -and $roles -contains 'Keyboard')
            $hasOnlyAudioRole = ($roles.Count -eq 1 -and $roles -contains 'Audio')
            Write-Host "[AutoOpt][USB] $($usb.DisplayName) Roles: $($usb.Roles -join ', ')"
            if ($singleAudio -or $hasOnlyAudioRole) {
                $ecore = Find-FreeECore -usedCoresRef ([ref]$usedCores) -eCoreIndices $eCoreIndices
                if ($ecore -ne $null) {
                    Reserve-Core $ecore ([ref]$usedCores) ([ref]$usedSmtSets) $null
                    $assignedMap[$usb] = @($ecore)
                    $mask = "{0:X16}" -f ([uint64](1 -shl $ecore))
                    Write-Host "[AutoOpt][USB] Single-audio USB assigned E-core $ecore mask 0x$mask"
                    $res = Set-DeviceAffinity $usb.RegistryPath ("0x" + $mask)
                    Write-Host "[AutoOpt][USB] Set-DeviceAffinity returned: $res"
                    $weakOccupiedCores += @($ecore)
                    continue
                } else {
                    if (-not $script:IsDualCCDCpu) {
                        $smtId0 = Get-SmtSetIdForCore -core 0 -smtSets $smtSets
                        $core0Available = (-not $usedCores.ContainsKey(0)) -and ($smtId0 -eq $null -or -not $usedSmtSets.ContainsKey($smtId0))
                        if ($core0Available) {
                            Reserve-Core 0 ([ref]$usedCores) ([ref]$usedSmtSets) $smtId0
                            $assignedMap[$usb] = @(0)
                            $mask = "{0:X16}" -f ([uint64](1 -shl 0))
                            Write-Host "[AutoOpt][USB] No E-core; assigned core 0 mask 0x$mask"
                            $res = Set-DeviceAffinity $usb.RegistryPath ("0x" + $mask)
                            Write-Host "[AutoOpt][USB] Set-DeviceAffinity returned: $res"
                            if ($isControllerRole) { $occupiedCores += @([int]0) }
                            if ($hasMouse) { $occupiedCores += @([int]0) }
                            if ($singleKeyboard) { $weakOccupiedCores += @([int]0) }
                            if ($singleAudio) { $weakOccupiedCores += @([int]0) }
                            continue
                        }
                    }
                    Write-Host "[AutoOpt][USB] No E-core and core-0 unavailable or forbidden; falling back to P-core"
                }
            }
            $f = Find-FreePCoreLocal -usedCoresRef ([ref]$usedCores) -usedSmtRef ([ref]$usedSmtSets) -pCoreIndicesParam $pCoreIndices -smtSetsParam $smtSets -avoidCore0 $core0SoftAvoid
            if ($f -eq $null) {
                $preferred = @('Audio','Keyboard')
                $share = Find-ShareableCore -preferredSharingPartners $preferred -usedCoresRef ([ref]$usedCores) -usedSmtRef ([ref]$usedSmtSets) -smtSets $smtSets -preferSmt $true -assignedMap $assignedMap
                if ($share) {
                    $f = @{ Core = $share.Core; SmtId = $share.SmtId; Shared = $true }
                    Write-Host "[AutoOpt][USB] No free P-core; allowing sharing on core $($f.Core) (mode $($share.ShareMode))"
                }
            }
            if ($f -ne $null) {
                $core = $f.Core
                $smtid = $f.SmtId
                if (-not $f.Shared) { Reserve-Core $core ([ref]$usedCores) ([ref]$usedSmtSets) $smtid }
                $assignedMap[$usb] = @($core)
                $mask = "{0:X16}" -f ([uint64](1 -shl $core))
                Write-Host "[AutoOpt][USB] Setting USB affinity: $($usb.RegistryPath) -> core $core mask 0x$mask"
                $res = Set-DeviceAffinity $usb.RegistryPath ("0x" + $mask)
                Write-Host "[AutoOpt][USB] Set-DeviceAffinity returned: $res"
                if ($isControllerRole) { $occupiedCores += @($core) }
                if ($hasMouse) { $occupiedCores += @($core) }
                if ($singleKeyboard) { $weakOccupiedCores += @($core) }
            } else {
                Write-Host "[AutoOpt][USB] WARNING - could not allocate P-core for USB $($usb.DisplayName)" -ForegroundColor Yellow
                $assignedMap[$usb] = @()
            }
        }

        foreach ($aud in $audioPCI) {
            Write-Host "[AutoOpt][AudioPCI] Assigning: $($aud.DisplayName)"
            $ecore = Find-FreeECore -usedCoresRef ([ref]$usedCores) -eCoreIndices $eCoreIndices
            if ($ecore -ne $null) {
                Reserve-Core $ecore ([ref]$usedCores) ([ref]$usedSmtSets) $null
                $assignedMap[$aud] = @($ecore)
                $mask = "{0:X16}" -f ([uint64](1 -shl $ecore))
                Write-Host "[AutoOpt][AudioPCI] Assigned E-core $ecore mask 0x$mask"
                $res = Set-DeviceAffinity $aud.RegistryPath ("0x" + $mask)
                Write-Host "[AutoOpt][AudioPCI] Set-DeviceAffinity returned: $res"
                $weakOccupiedCores += @($ecore)
            } else {
                if (-not $script:IsDualCCDCpu) {
                    $smtId0 = Get-SmtSetIdForCore -core 0 -smtSets $smtSets
                    $core0Available = (-not $usedCores.ContainsKey(0)) -and ($smtId0 -eq $null -or -not $usedSmtSets.ContainsKey($smtId0))
                    if ($core0Available) {
                        Reserve-Core 0 ([ref]$usedCores) ([ref]$usedSmtSets) $smtId0
                        $assignedMap[$aud] = @(0)
                        $mask = "{0:X16}" -f ([uint64](1 -shl 0))
                        Write-Host "[AutoOpt][AudioPCI] No E-core; assigned core 0 mask 0x$mask"
                        $res = Set-DeviceAffinity $aud.RegistryPath ("0x" + $mask)
                        Write-Host "[AutoOpt][AudioPCI] Set-DeviceAffinity returned: $res"
                        $weakOccupiedCores += @([int]0)
                        continue
                    }
                }
                $f = Find-FreePCoreLocal -usedCoresRef ([ref]$usedCores) -usedSmtRef ([ref]$usedSmtSets) -pCoreIndicesParam $pCoreIndices -smtSetsParam $smtSets -avoidCore0 $core0SoftAvoid
                if ($f -ne $null) {
                    $core = $f.Core
                    Reserve-Core $core ([ref]$usedCores) ([ref]$usedSmtSets) $f.SmtId
                    $assignedMap[$aud] = @($core)
                    $mask = "{0:X16}" -f ([uint64](1 -shl $core))
                    Write-Host "[AutoOpt][AudioPCI] No E-core; assigned P-core $core mask 0x$mask"
                    $res = Set-DeviceAffinity $aud.RegistryPath ("0x" + $mask)
                    Write-Host "[AutoOpt][AudioPCI] Set-DeviceAffinity returned: $res"
                    $weakOccupiedCores += @($core)
                } else {
                    Write-Host "[AutoOpt][AudioPCI] WARNING - could not assign Audio PCI" -ForegroundColor Yellow
                    $assignedMap[$aud] = @()
                }
            }
        }

        foreach ($dev in $deviceList) {
            $msiPath = if ($dev.Category -eq "Network") { Get-NetworkAdapterMSIRegistryPath $dev } else { $dev.RegistryPath }
            if ($dev.Category -eq "Network") {
                Write-Host "[AutoOpt] Skipping MSI changes for NIC: $($dev.DisplayName) at path $msiPath"
                $priRes = Set-DevicePriority $msiPath 3
                Write-Host "[AutoOpt] Set-DevicePriority for NIC $($dev.DisplayName) -> 3 (High): $priRes"
                $msiInfo = Get-CurrentMSI $msiPath
                $msgLimitDebug = if ($msiInfo.MessageLimit -eq "") { "Unlimited" } else { $msiInfo.MessageLimit.ToString() }
                Write-Host "[AutoOpt] NIC MSI status read (no change): MSIEnabled=$($msiInfo.MSIEnabled) MessageLimit=$msgLimitDebug"
                continue
            }
            if ($dev.Category -eq 'SSD') {
                $chosenMsgLimit = ""  
                $msiRes = Set-DeviceMSI $msiPath 1 $chosenMsgLimit
                $msgLimitDebug = if ($chosenMsgLimit -eq "") { "Unlimited" } else { $chosenMsgLimit }
                Write-Host "[AutoOpt] Set-DeviceMSI for SSD $($dev.DisplayName) -> Enabled (MessageLimit=$msgLimitDebug) result: $msiRes"
                $priRes = Set-DevicePriority $msiPath 3
                Write-Host "[AutoOpt] Set-DevicePriority for SSD $($dev.DisplayName) -> 3 (High): $priRes"
                continue
            }
            $chosenMsgLimit = ""  
            $msiRes = Set-DeviceMSI $msiPath 1 $chosenMsgLimit
            $msgLimitDebug = if ($chosenMsgLimit -eq "") { "Unlimited" } else { $chosenMsgLimit }
            Write-Host "[AutoOpt] Set-DeviceMSI for $($dev.DisplayName) at $msiPath -> Enabled (MessageLimit=$msgLimitDebug) result: $msiRes"
            $priRes = Set-DevicePriority $msiPath 3
            Write-Host "[AutoOpt] Set-DevicePriority for $($dev.DisplayName) -> 3 (High): $priRes"
        }

        foreach ($usb in $usbs) {
            $assigned = $assignedMap[$usb]
            if (-not $assigned) { continue }
            if ($usb.Roles -contains 'Controller' -or $usb.Roles -contains 'Mouse') {
                $occupiedCores += $assigned
            }
            $norm = Get-AutoOptRoles $usb
            if (($norm.Count -eq 1) -and ($norm -contains 'Audio')) {
                $weakOccupiedCores += $assigned
            }
        }

        foreach ($usb in $usbs) {
            $assigned = $assignedMap[$usb]
            if (-not $assigned) { continue }
            $normRoles = Get-AutoOptRoles $usb
            $hasAudio = ($normRoles -contains 'Audio')
            $hasKeyboard = ($normRoles -contains 'Keyboard')
            $otherRoles = $normRoles | Where-Object { $_ -ne 'Audio' -and $_ -ne 'Keyboard' }
            if ($hasAudio -and $hasKeyboard -and ($otherRoles.Count -eq 0)) {
                Write-Host "[AutoOpt] Mixed Audio+Keyboard USB -> adding to weakOccupiedCores: $($usb.DisplayName) -> cores [$($assigned -join ', ')]"
                $weakOccupiedCores += $assigned
            }
        }

        foreach ($gpu in $gpus) {
            $assigned = $assignedMap[$gpu]
            if ($assigned) { $occupiedCores += $assigned }
        }

        foreach ($nic in $nics) {
            $assigned = $assignedMap[$nic]
            if ($assigned) { $weakOccupiedCores += $assigned }
        }

        $occupiedCores = ($occupiedCores | Select-Object -Unique) | Sort-Object
        $weakOccupiedCores = ($weakOccupiedCores | Select-Object -Unique) | Sort-Object
        Write-Host "[AutoOpt] Final occupied_cores (strong): $($occupiedCores -join ', ')" -ForegroundColor Green
        Write-Host "[AutoOpt] Final occupied_weak_cores: $($weakOccupiedCores -join ', ')" -ForegroundColor Green

        $scriptPath = $MyInvocation.MyCommand.Path
        $scriptDir = if ($scriptPath) { Split-Path -Parent $scriptPath } else { Get-Location }
        $gamesCfgPath = Join-Path $scriptDir "games_priorities.cfg"
        $systemCfgPath = Join-Path $scriptDir "system_priorities.cfg"

        function Write-ConfigFileEntriesLocal {
            param($path, $coresArr, $weakArr)
            $coresString = ($coresArr -join ',')
            $weakString = ($weakArr -join ',')
            if (-not (Test-Path $path)) { New-Item -Path $path -ItemType File -Force | Out-Null }
            $content = [System.IO.File]::ReadAllText($path, [System.Text.Encoding]::UTF8)
            if ($content -match '(?m)^occupied_affinity_cores=.*$') { $content = $content -replace '(?m)^occupied_affinity_cores=.*$', "occupied_affinity_cores=$coresString" } else { $content += "`r`noccupied_affinity_cores=$coresString" }
            if ($content -match '(?m)^occupied_ideal_processor_cores=.*$') { $content = $content -replace '(?m)^occupied_ideal_processor_cores=.*$', "occupied_ideal_processor_cores=$coresString" } else { $content += "`r`noccupied_ideal_processor_cores=$coresString" }
            if ($content -match '(?m)^occupied_weak_affinity_cores=.*$') { $content = $content -replace '(?m)^occupied_weak_affinity_cores=.*$', "occupied_weak_affinity_cores=$weakString" } else { $content += "`r`noccupied_weak_affinity_cores=$weakString" }
            if ($content -match '(?m)^occupied_weak_ideal_processor_cores=.*$') { $content = $content -replace '(?m)^occupied_weak_ideal_processor_cores=.*$', "occupied_weak_ideal_processor_cores=$weakString" } else { $content += "`r`noccupied_weak_ideal_processor_cores=$weakString" }
            [System.IO.File]::WriteAllText($path, $content.Trim(), [System.Text.UTF8Encoding]::new($false))
            Write-Host "[AutoOpt] Wrote config entries to $path"
        }

        Write-ConfigFileEntriesLocal -path $gamesCfgPath -coresArr $occupiedCores -weakArr $weakOccupiedCores
        Write-ConfigFileEntriesLocal -path $systemCfgPath -coresArr $occupiedCores -weakArr $weakOccupiedCores

        try { Refresh-DeviceUI; Write-Host "[AutoOpt] GUI refreshed" -ForegroundColor Cyan } catch { Write-Host "[AutoOpt] GUI refresh failed: $_" -ForegroundColor Yellow }
        [System.Windows.Forms.MessageBox]::Show("Auto-optimization finished. A system restart may be required.", "Auto-Optimization")
        Write-Host "[AutoOpt] Completed successfully." -ForegroundColor Green
    }
    catch {
        Write-Host "[AutoOpt] Error: $_" -ForegroundColor Red
        [System.Windows.Forms.MessageBox]::Show("Auto-optimization failed: $_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
})

[void]$form.ShowDialog()
