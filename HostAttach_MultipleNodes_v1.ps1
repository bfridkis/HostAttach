## NOTE: To enable WinRM on remote nodes (for using "Invoke-Command / New-PSSession"), the WinRM service must be running,
## and the "Windows Remote Management (HTTP-In)" Inbound Windows (Domain) Firewall rule needs to be enabled. Also, a WinRM 
## listener needs to be established. Enter "winrm quickconfig" in an administrator command prompt on the remote machine to 
## configure these items if needed.

function loadComps {
    param ($_comps)

    do {
        $readFileOrManualEntryOrAllNodes = read-host -prompt "`nHost Input: Read From File (1) or Manual Entry (2) or All Nodes (3) [Default = Manual Entry]"
        if (!$readFileOrManualEntryOrAllNodes) { $readFileOrManualEntryOrAllNodes = 2 }
    } 
    while ($readFileOrManualEntryOrAllNodes -ne 1 -and $readFileOrManualEntryOrAllNodes -ne 2 -and $readFileOrManualEntryOrAllNodes -ne 3 -and
            $readFileOrManualEntryOrAllNodes -ne "Q")

    if ($readFileOrManualEntryOrAllNodes -eq "Q") { exit }

    if ($readFileOrManualEntryOrAllNodes -eq 1) {
        write-output "`n** Remember To Enter Fully Qualified Filenames If Files Are Not In Current Directory **" 
        write-output "`n`tFile must contain one hostname per line.`n"

        do {
            $compsFilePath = read-host -prompt "Hostname Input File"
            if (![string]::IsNullOrEmpty($compsFilePath) -and $compsFilePath -ne "B" -and $compsFilePath -ne "Q") { 
                $fileNotFound = $(!$(test-path $compsFilePath -PathType Leaf))
                if ($fileNotFound) { write-output "`n`tFile '$compsFilePath' Not Found or Path Specified is a Directory!`n" }
            }
        }
        while (([string]::IsNullOrEmpty($compsFilePath) -or $fileNotFound) -and $compsFilePath -ne "Q")
        if ($compsFilePath -eq "Q") { exit }

        $_comps = Get-Content $compsFilePath -ErrorAction Stop
    }
    elseif ($readFileOrManualEntryOrAllNodes -eq 2) {
        $compCount = 0

        write-output "`n`nEnter 'f' once finished. Minimum 1 entry. (Enter 'q' to exit.)`n"
        do {
            $compsInput = read-host -prompt "Hostname ($($compCount + 1))"
            if ($compsInput -ne "F" -and $compsInput -ne "B" -and $compsInput -ne "Q" -and 
                ![string]::IsNullOrEmpty($compsInput)) {
                $_comps.Add($compsInput)
                $compCount++
                }
        }
        while (($compsInput -ne "F" -and $compsInput -ne "Q") -or 
                ($compCount -lt 1))

        if ($compsInput -eq "Q") { exit }
    }
    #elseif ($readFileOrManualEntryOrAllNodes = 3) {
    #    Get-ADObject -LDAPFilter "(objectClass=computer)" | select-object name | Set-Variable -name compsTemp
    #    $compsTemp | ForEach-Object { $_comps.Add($_.Name) }
    #}
}


$WSUS_Server = "10.100.75.13"
if ($WSUS_Server -eq "WSUS_Server") { $WSUS_Server = Read-Host -Prompt "WSUS Server IP Address" }

$WSUS_Server_Port = "8530"
if ($WSUS_Server_Port -eq "WSUS_Server_Port") { $WSUS_Server_Port = Read-Host -Prompt "WSUS Server Port [Default 8530]" }
if (!($WSUS_Server_Port)) { $WSUS_Server_Port = "8530" }

$AUOption = $null
do { 
    $AUOption = Read-Host -Prompt "AU Option - [2] `"Notify For Download & Notify For Install`" or [3] `"Auto Download & Notify for Install`""
}
while ($AUOption -ne 2 -and $AUOption -ne 3 -and $AUOption -ne "q")
if ($AUOption -eq "q") { exit }

$cred = Get-Credential

$comps = New-Object System.Collections.Generic.List[System.Object]
loadComps $comps 

$Global:errorList = New-Object System.Collections.Generic.List[System.Object]
$Global:errorLogPath = ".\"
New-Item -Path $Global:errorLogPath -ItemType "file" -Name "TestingInvokeCommandOutput.txt" *>$null

Write-Output "`nRunning...Please wait...`n"

$comps | ForEach-Object {
    
    $currComp = $_

    Invoke-Command -ComputerName $_ -ScriptBlock {

        $registryPath = "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate"
        if (!(Test-Path $registryPath)) { 
            Try { New-Item -Path $registryPath -Force -ErrorAction Stop | Out-Null }
            Catch { $Global:errorList.Add( @{ 'Hostname' = $currComp ; 'Exception' = $_.Exception.Message } ) }
        }
        $Names_WU = "WUServer", "WUStatusServer"
        $Names_WU | ForEach-Object { 
            Try { 
                New-ItemProperty -Path $registryPath -Name $_ -Value "http://$($Using:WSUS_Server):$($Using:WSUS_Server_Port)" -PropertyType STRING -FORCE | Out-Null
                New-ItemProperty -Path $registryPath -Name "ElevateNonAdmins" -Value 1 -PropertyType DWORD -FORCE | Out-Null
            }
            Catch { <# $Global:errorList.Add( @{ 'Hostname' = $currComp ; 'Exception' = $_.Exception.Message } ) #> }
        }

        $registryPath = "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU"
        if (!(Test-Path $registryPath)) { 
            Try { New-Item -Path $registryPath -Force | Out-Null }
            Catch { <# $Global:errorList.Add( @{ 'Hostname' = $currComp ; 'Exception' = $_.Exception.Message } ) #> }
        }

        $Names_WUAU = "NoAutoUpdate", "AUOptions", "ScheduledInstallDay", "ScheduledInstallTime", "NoAutoRebootWithLoggedOnUsers",
                      "AutoInstallMinorUpdates", "RebootRelaunchTimeoutEnabled", "RebootRelaunchTimeout", "RescheduleWaitTimeEnabled",
                      "RescheduleWaitTime", "DetectionFrequencyEnabled", "RebootWarningTimeoutEnabled", "RebootWarningTimeout", 
                      "UseWUServer", "NoAUShutdownOption", "NoAUAsDefaultShutdownOption"

        $Names_WUAU | ForEach-Object {
            Try {
                switch ($_) {
                    ## Works for Win 10, but not Win 7
                    #{ $_ -in ("NoAutoUpdate", "ScheduledInstallDay", "AutoInstallMinorUpdates", "NoAUShutdownOption", "NoAUAsDeafultShutdownOption") } 
                    { $_ -eq "NoAutoUpdate" -or $_ -eq "ScheduledInstallDay" -or $_ -eq "AutoInstallMinorUpdates" -or $_ -eq "NoAUShutdownOption"-or $_ -eq "NoAUAsDeafultShutdownOption" }
                       { New-ItemProperty -Path $registryPath -Name $_ -Value 0 -PropertyType DWORD -Force | Out-Null }
                    { $_ -eq "AUOptions" }
                        { if ($AUOption -eq 2) 
                            { New-ItemProperty -Path $registryPath -Name $_ -Value 2 -PropertyType DWORD -Force | Out-Null }
                          else
                            { New-ItemProperty -Path $registryPath -Name $_ -Value 3 -PropertyType DWORD -Force | Out-Null }
                        }
                    { $_ -eq "ScheduledInstallTime" }
                        { New-ItemProperty -Path $registryPath -Name $_ -Value 0x0A -PropertyType DWORD -Force | Out-Null }
                    ## Works for Win 10, but not Win 7
                    # { $_ -in ("NoAutoRebootWithLoggedOnUsers", "RebootRelaunchTimeoutEnabled", "RescheduledWaitTimeEnabled", "DetectionFrequencyEnabled",
                    #            "RebootWarningTimeoutEnabled", "UseWUSever") }
                    { $_ -eq "NoAutoRebootWithLoggedOnUsers" -or $_ -eq "RebootRelaunchTimeoutEnabled" -or $_ -eq "RescheduledWaitTimeEnabled" -or $_ -eq "DetectionFrequencyEnabled" -or
                        $_ -eq "RebootWarningTimeoutEnabled" -or $_ -eq "UseWUSever" }
                        { New-ItemProperty -Path $registryPath -Name $_ -Value 1 -PropertyType DWORD -Force | Out-Null }
                    { $_ -eq "RebootRelaunchTimeout" }
                        { New-ItemProperty -Path $registryPath -Name $_ -Value 0x3c -PropertyType DWORD -Force | Out-Null }
                    { $_ -eq "RescheduleWaitTime" } 
                        { New-ItemProperty -Path $registryPath -Name $_ -Value 0x0f -PropertyType DWORD -Force | Out-Null }
                    { $_ -eq "RebootWarningTimeout" }
                        { New-ItemProperty -Path $registryPath -Name $_ -Value 0x1e -PropertyType DWORD -Force | Out-Null }
                }
            }
            Catch { <# $Global:errorList.Add( @{ 'Hostname' = $currComp ; 'Exception' = $_.Exception.Message } ) #> }
        }

        # $Global:errorList.Add( @{ 'Hostname' = $currComp ; 'Exception' = "TEST" } )

        #gpupdate /force
        
        Restart-Service -Name wuauserv

        wuauclt.exe /resetauthorization /detectnow
        Try { C:\windows\system32\usoclient.exe startscan -ErrorAction Stop }
        Catch { }

    } -Credential $Cred
}

<#
if ($errorList.Count -gt 0) {
    if (!$_noConsoleOut) {
        $outputString = "`r`n** Unreachable Nodes **"
        Add-Content -Path $_path -Value $outputString
        $errorList | Select-Object @{ n = 'Unavailable Hosts' ; e = {$_.Hostname}},
                                    @{ n = 'Exceptions Generated' ; e = {$_.Exception}} |
                        Sort-Object "Unavailable Hosts" | Tee-Object Format-Table | ConvertTo-CSV -NoTypeInformation | Add-Content -Path $_path
    }
}
#>

write-host "`n[IF NO ERRORS] WSUS Settings Updated. [IF ERRORS] Check affected nodes. Press enter to exit..." -NoNewLine
$Host.UI.ReadLine()

## References ##

# https://devblogs.microsoft.com/scripting/update-or-add-registry-key-value-with-powershell/
# https://devblogs.microsoft.com/scripting/use-powershell-to-edit-the-registry-on-remote-computers/
# https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/new-itemproperty?view=powershell-7.1
# https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_switch?view=powershell-7.1
# https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/restart-service?view=powershell-7.1
# https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-7.1
# https://stackoverflow.com/questions/36328690/how-do-i-pass-variables-with-the-invoke-command-cmdlet

###### ORIGNIAL BATCH VERSION #####

<#
@echo off
set AuxIP=10.100.75.13:8530
Echo Windows Registry Editor Version 6.00 >> tmp_wsus1.reg

Echo [HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\] >> tmp_wsus1.reg
Echo "WUServer"="http://%AuxIP%" >> tmp_wsus1.reg
Echo "WUStatusServer"="http://%AuxIP%" >> tmp_wsus1.reg
Echo "ElevateNonAdmins"=dword:00000001 >> tmp_wsus1.reg

Echo [HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\] >> tmp_wsus1.reg
Echo "NoAutoUpdate"=dword:00000000 >> tmp_wsus1.reg
Echo "AUOptions"=dword:00000002 >> tmp_wsus1.reg
Echo "ScheduledInstallDay"=dword:00000000 >> tmp_wsus1.reg
Echo "ScheduledInstallTime"=dword:0000000a >> tmp_wsus1.reg
Echo "NoAutoRebootWithLoggedOnUsers"=dword:00000001 >> tmp_wsus1.reg
Echo "AutoInstallMinorUpdates"=dword:00000001 >> tmp_wsus1.reg
Echo "RebootRelaunchTimeoutEnabled"=dword:00000001 >> tmp_wsus1.reg
Echo "RebootRelaunchTimeout"=dword:0000003c >> tmp_wsus1.reg
Echo "RescheduleWaitTimeEnabled"=dword:00000001 >> tmp_wsus1.reg
Echo "RescheduleWaitTime"=dword:0000000f >> tmp_wsus1.reg
Echo "DetectionFrequencyEnabled"=dword:00000001 >> tmp_wsus1.reg
Echo "RebootWarningTimeoutEnabled"=dword:00000001 >> tmp_wsus1.reg
Echo "RebootWarningTimeout"=dword:0000001e >> tmp_wsus1.reg
Echo "UseWUServer"=dword:00000001 >> tmp_wsus1.reg
Echo "NoAUShutdownOption"=dword:00000000 >> tmp_wsus1.reg
Echo "NoAUAsDefaultShutdownOption"=dword:00000000 >> tmp_wsus1.reg

Echo "Stop Automatic Updates service"
net stop wuauserv

Echo "Import WSUS settings into registry"
regedit "tmp_wsus1.reg"

Echo "Start Automatic Updates service"
net start wuauserv

Echo "Detect WSUS Server, this may take up to an hour"
wuauclt.exe /resetauthorization /detectnow
C:\windows\system32\usoclient.exe startscan

del tmp_wsus1.reg

Echo "Your Server will now report to the WSUS server."
Echo "It should appear in the console in the next 10-30 mins"

Pause
#>