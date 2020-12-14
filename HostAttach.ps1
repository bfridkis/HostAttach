## NOTE: To enable WinRM on remote nodes (for using "Invoke-Command / New-PSSession"), the WinRM service must be running,
## and the "Windows Remote Management (HTTP-In)" Inbound Windows (Domain) Firewall rule needs to be enabled. Also, a WinRM 
## listener needs to be established. Enter "winrm quickconfig" in an administrator command prompt on the remote machine to 
## configure these items if needed.

$instructionsOn = $true

function loadComps {
    
    param([Parameter(Mandatory=$true)]$_comps)

    do {
        $readFileOrManualEntryOrAllNodes = read-host -prompt "`nHost Input: Read From File (1) or Manual Entry (2) or All Nodes (3) [Default = LocalHost Only]"
        if (!$readFileOrManualEntryOrAllNodes) { 
            $comps.Add($env:COMPUTERNAME)
            return
        }
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

        Get-Content $compsFilePath -ErrorAction Stop | ForEach-Object { $_comps.Add($_) }
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
    elseif ($readFileOrManualEntryOrAllNodes = 3) {
        Get-ADObject -LDAPFilter "(objectClass=computer)" | select-object name | Set-Variable -name compsTemp
        $compsTemp | ForEach-Object { $_comps.Add($_.Name) }
    }
}

if ($instructionsOn) {

    Clear-Host

    Write-Output "`n`t`t`t`t`t`t`t`t@ # $ % Host Attach % $ # @`n"
    Write-Output "`tThis script will update local group policy settings* to register a node or set of nodes with a"
    Write-Output "`tWSUS server in accordance with Honeywell recommendations. Please note that after updating"
    Write-Output "`tthe group policy settings but before the actual WSUS server registration takes place, the"
    Write-Output "`tgroup policy on each local machine must be updated. This should occur automatically at intervals"
    Write-Output "`tof approximately 90 minutes by default. Accordingly, it may take up to 1.5 hours for registration"
    Write-Output "`tto occur after the policy changes have been made, depending on current settings.`n"

    Write-Output "`tHowever, this script does provide an option to force the update by executing the following commands"
    Write-Output "`ton each target machine (i.e. client node).:`n"
    Write-Output "`t`t* gpupdate /force`n"
    Write-Output "`t`t* Restart-Service -Name wuauserv`n"
    Write-Output "`t`t* wuauclt.exe /resetauthorization /detectnow`n"
    Write-Output "`t`t* C:\windows\system32\usoclient.exe startscan`n"

    Write-Output "`tIf these commands are successfully executed, registration may be expedited (results vary). This"
    Write-Output "`toption requires active Windows Remote Management (WinRM) configuration on the target nodes**. This in"
    Write-Output "`tturn requires that the `"WinRM`" service is running, the `"Windows Remote Management (HTTP-In)`" firewall"
    Write-Output "`trule is enabled, and an active WinRM HTTP listener has been established on each target node."
    Write-Output "`tAll three of these can be accomplished by entering the command 'winrm quickconfig' in an administrator"
    Write-Output "`tcommand prompt on each target node. (This should also enable future centrally managed Powershell scripting"
    Write-Output "`tefforts to take place for each node on which the configuration is applied.) Enter 'Y' when prompted"
    Write-Output "`t'Force gpupdate?' to use this option. (Note if this option is specified and WinRM is not available for any"
    Write-Output "`tgiven node, an error will be logged. However, this does not mean the gp settings were not applied. Without"
    Write-Output "`tfurther intervention, and assuming no other errors occurred, registration should still take place at the"
    Write-Output "`tnext scheduled/automated gpupdate or reboot, whichever comes first.)`n`n"
    
    Write-Output "`t*Domain level group policy settings may override changes to local group policy settings if in place.`n"

    Write-Output "`t**WinRM requirement does not apply when target node is the localhost.`n`n"
              
    Write-Host "Enter q to quit, any other key to continue... " -NoNewLine
    $InstResp = $Host.UI.ReadLine()
    if ($InstResp -eq "q") { exit }

    Clear-Host

    Write-Output "`n`t`t`t`t`t`t`t`t@ # $ % Host Attach % $ # @`n"
    Write-Output "`tThis script requires that the 'PolicyFileEditor' Powershell Module be installed on the calling machine."
    Write-Output "`tThis module is licensed under the Apache 2.0 license. If not installed, perform the following steps:`n"
    Write-Output "`t`t** Note this only applies for the calling machine, NOT the remote machines/clients. **`n"
    Write-Output "`t`t1. Copy 'policyfileeditor.3.0.0.nupkg.zip' from 'Antivirus & Security Patching' TEAMS file share.`n"
    Write-Output "`t`t`t Link: https://phillips66.sharepoint.com/teams/AntivirusSecurityPatching/Shared%20Documents/General/PS%20Module_PolicyFileEditor/policyfileeditor.3.0.0.nupkg.zip`n"
    Write-Output "`t`t2. Extract contents of .zip package to 'C:\Program Files\WindowsPowerShell\Modules\policyfileeditor'*`n"
    Write-Output "`t`t`t Create 'policyfileeditor' directory in  'C:\Program Files\WindowsPowerShell\Modules'* as needed.`n"
    Write-Output "`t`t3. In Administrator Powershell command prompt, enter the following commands:`n"
    Write-Output "`t`t`t a. `$cep = Get-ExecutionPolicy`n"
    Write-Output "`t`t`t b. Set-ExecutionPolicy Bypass`n"
    Write-Output "`t`t`t*c. Import-Module `"C:\Program Files\WindowsPowerShell\Modules\policyfileeditor`"`n"
    Write-Output "`t`t`t d. Set-ExecutionPolicy `$cep`n`n"

    Write-Output "`t*If using Windows 7 or older OS, use C:\Windows\System32\WindowsPowerShell\v1.0\Modules`n`n"

    Write-Host "Enter q to quit, any other key to continue... " -NoNewLine
    $InstResp = $Host.UI.ReadLine()
    if ($InstResp -eq "q") { exit }

    Clear-Host

    Write-Output "`n`t`t`t`t`t`t`t`t@ # $ % Host Attach % $ # @`n"
    Write-Output "`tIf desired, modify the lines '`$WSUS_Server = `"WSUS_Server' and/or '`$WSUS_Server_Port = `"WSUS_Server_Port`""
    Write-Output "`twith site specific data and save, to avoid these prompts on future executions.`n"
    Write-Output "`t`te.g. `$WSUS_Server = `"10.100.75.13`" & `$WSUS_Server_Port = `"8530`"`n"
    Write-Output "`tSimilarly, the instruction/notes can be bypassed for future exections by setting the '`$instructionsOn' variable"
    Write-Output "`tat the top of the script to `$false and saving.`n"
    Write-Output "`t`te.g. `$instructionsOn = `$false`n`n"

    Write-Host "Enter q to quit, any other key to continue... " -NoNewLine
    $InstResp = $Host.UI.ReadLine()
    if ($InstResp -eq "q") { exit }
}

Clear-Host

$WSUS_Server = "10.100.75.13"
if ($WSUS_Server -eq "WSUS_Server") { $WSUS_Server = Read-Host -Prompt "WSUS Server IP Address" }

$WSUS_Server_Port = "8530"
if ($WSUS_Server_Port -eq "WSUS_Server_Port") { $WSUS_Server_Port = Read-Host -Prompt "WSUS Server Port [Default 8530]" }
if (!($WSUS_Server_Port)) { $WSUS_Server_Port = "8530" }

$AUOption = $null
do { 
    $AUOption = Read-Host -Prompt "AU Option? - [2] `"Notify For Download & Notify For Install`" or [3] `"Auto Download & Notify for Install`" [Default=3]"
    if (!$AUOption) { $AUOption = 3 }
}
while ($AUOption -ne 2 -and $AUOption -ne 3 -and $AUOption -ne "q")
if ($AUOption -eq "q") { exit }

$comps = New-Object System.Collections.Generic.List[System.Object]
loadComps $comps

$forceGPUpdate = $null
Write-Output "`n"
do { 
    if ($comps.Count -eq 1 -and $comps[0] -eq $env:COMPUTERNAME) {
        $forceGPUpdate = Read-Host -Prompt "Force gpupdate? (Y or N) [Default=N]"
    }
    else { 
        $forceGPUpdate = Read-Host -Prompt "Force gpupdate? (Y or N - Admin Credentials Required for Y) [Default=N]"
    }
    if (!$forceGPUpdate) { $forceGPUpdate = "N" }
}
while ($forceGPUpdate -ne "Y" -and $forceGPUpdate -ne "N" -and $forceGPUpdate -ne "q")
if ($forceGPUpdate -eq "q") { exit }
if ($forceGPUpdate -eq "Y" -and !($comps.Count -eq 1 -and $comps[0] -eq $env:COMPUTERNAME)) { $cred = Get-Credential }

$errorList = New-Object System.Collections.Generic.List[System.Object]

Write-Output "`nRunning...Please wait...`n"

$comps | ForEach-Object {

    $currComp = $_

    if ($currComp -eq $env:COMPUTERNAME) { $path = "C:\Windows\System32\GroupPolicy\Machine\registry.pol" }
    else { $path = "\\$currComp\c$\Windows\System32\GroupPolicy\Machine\registry.pol" }
      
    # Update Keys in "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" 
    ## WUServer, WUStatusServer, ElevateNonAdmins
    $key = "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    $Names_WU = "WUServer", "WUStatusServer"
    $Names_WU | ForEach-Object { 
        Try { 
            Set-PolicyFileEntry -Path $path -Key $key -ValueName $_ `
                -Data "http://$($WSUS_Server):$($WSUS_Server_Port)" -Type "STRING" -ErrorAction Stop
        }
        Catch { $errorList.Add( @{ 'Hostname_ValueName' = "$($currComp):$($currValueName)" ; 'Exception' = $_.Exception.Message } ) }
    }
    Try {
        Set-PolicyFileEntry -Path $path -Key $key -ValueName ElevateNonAdmins -Data 0 -Type "DWORD" -ErrorAction Stop
    }
    Catch { $errorList.Add( @{ 'Hostname_ValueName' = "$($currComp):$($currValueName)" ; 'Exception' = $_.Exception.Message } ) }

    # Update Keys in "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU"
    ## "NoAutoUpdate", "AUOptions", "ScheduledInstallDay", "ScheduledInstallTime", "NoAutoRebootWithLoggedOnUsers",
    ## "AutoInstallMinorUpdates", "RebootRelaunchTimeoutEnabled", "RebootRelaunchTimeout", "RescheduleWaitTimeEnabled",
    ## "RescheduleWaitTime", "DetectionFrequencyEnabled", "RebootWarningTimeoutEnabled", "RebootWarningTimeout", 
    ## "UseWUServer", "NoAUShutdownOption", "NoAUAsDefaultShutdownOption", UseWUServer

    $key += "\AU"
    
    $Names_WUAU = "NoAutoUpdate", "AUOptions", "ScheduledInstallDay", "ScheduledInstallTime", "NoAutoRebootWithLoggedOnUsers",
                  "AutoInstallMinorUpdates", "RebootRelaunchTimeoutEnabled", "RebootRelaunchTimeout", "RescheduleWaitTimeEnabled",
                  "RescheduleWaitTime", "DetectionFrequencyEnabled", "RebootWarningTimeoutEnabled", "RebootWarningTimeout", 
                  "UseWUServer", "NoAUShutdownOption", "NoAUAsDefaultShutdownOption"

    $Names_WUAU | ForEach-Object {
        $currValueName = $_
        Try {
            switch ($_) {
                ## Works for Win 10, but not Win 7
                #{ $_ -in ("NoAutoUpdate", "ScheduledInstallDay", "AutoInstallMinorUpdates", "NoAUShutdownOption", "NoAUAsDeafultShutdownOption") } 
                { $_ -eq "NoAutoUpdate" -or $_ -eq "ScheduledInstallDay" -or $_ -eq "AutoInstallMinorUpdates" -or $_ -eq "NoAUShutdownOption"-or $_ -eq "NoAUAsDeafultShutdownOption" }
                    { Set-PolicyFileEntry -Path $path -Key $key -ValueName $_ -Data 0 -Type "DWORD" -ErrorAction Stop }
                { $_ -eq "AUOptions" }
                    { if ($AUOption -eq 2) 
                        { Set-PolicyFileEntry -Path $path -Key $key -ValueName $_ -Data 2 -Type "DWORD" -ErrorAction Stop }
                        else
                        { Set-PolicyFileEntry -Path $path -Key $key -ValueName $_ -Data 3 -Type "DWORD" -ErrorAction Stop }
                    }
                { $_ -eq "ScheduledInstallTime" }
                    { Set-PolicyFileEntry -Path $path -Key $key -ValueName $_ -Data 0x0a -Type "DWORD" -ErrorAction Stop }
                ## Works for Win 10, but not Win 7
                # { $_ -in ("NoAutoRebootWithLoggedOnUsers", "RebootRelaunchTimeoutEnabled", "RescheduledWaitTimeEnabled", "DetectionFrequencyEnabled",
                #            "RebootWarningTimeoutEnabled", "UseWUSever") }
                { $_ -eq "NoAutoRebootWithLoggedOnUsers" -or $_ -eq "RebootRelaunchTimeoutEnabled" -or $_ -eq "RescheduledWaitTimeEnabled" -or $_ -eq "DetectionFrequencyEnabled" -or
                    $_ -eq "RebootWarningTimeoutEnabled" -or $_ -eq "UseWUServer" }
                    { Set-PolicyFileEntry -Path $path -Key $key -ValueName $_ -Data 1 -Type "DWORD" -ErrorAction Stop }
                { $_ -eq "RebootRelaunchTimeout" }
                    { Set-PolicyFileEntry -Path $path -Key $key -ValueName $_ -Data 0x3F480 -Type "DWORD" -ErrorAction Stop }
                { $_ -eq "RescheduleWaitTime" } 
                    { Set-PolicyFileEntry -Path $path -Key $key -ValueName $_ -Data 0x0f -Type "DWORD" -ErrorAction Stop }
                { $_ -eq "RebootWarningTimeout" }
                    { Set-PolicyFileEntry -Path $path -Key $key -ValueName $_ -Data 0x1e -Type "DWORD" -ErrorAction Stop }
            }
        }
        Catch { $errorList.Add( @{ 'Hostname_ValueName' = "$($currComp):$($currValueName)" ; 'Exception' = $_.Exception.Message } ) }
    }

    if ($forceGPUpdate -eq "Y") {

        if ($env:COMPUTERNAME -ne $currComp) {
            
            Invoke-Command -ComputerName $currComp -ScriptBlock {

                write-host "`n$($Using:currComp): " -NoNewLine
                gpupdate /force
        
                Restart-Service -Name wuauserv

                wuauclt.exe /resetauthorization /detectnow /updatenow
                Try { C:\windows\system32\usoclient.exe startscan -ErrorAction Stop }
                Catch { }

            } -Credential $Cred
        }
        else {

            write-host "Calling 'gpupdate /force' on $($currComp)..." -NoNewLine
            gpupdate /force
        
            Restart-Service -Name wuauserv

            #cd "C:\Windows\System32"
            wuauclt.exe /resetauthorization /detectnow
            Try { C:\windows\system32\usoclient.exe startscan -ErrorAction Stop }
            Catch { }
        }
    }
}


if ($errorList.Count -gt 0) {
    $errorLogFileName = "HostAttach_MutlipleNodes_ErrorLog-$(Get-Date -Format MMddyyyy_HHmmss).txt"
    New-Item -Path ".\" -ItemType "file" -Name $errorLogFileName | Out-Null
    $outputString = "** Exceptions Generated **`r`n"
    Add-Content -Path ".\$errorLogFileName" -Value $outputString
    $errorList | Select-Object @{ n = 'Hostname:Key_Value' ; e = {$_.Hostname_ValueName}},
                               @{ n = 'Exceptions Generated' ; e = {$_.Exception}} | ConvertTo-CSV -NoTypeInformation | Add-Content -Path ".\$errorLogFileName"

    write-host "`nErrors updating WSUS settings. Check error log [in current directory] and affected nodes. Press enter to exit..."
}
else { write-host "`nWSUS Settings Successfully Updated. Press enter to exit..." }

$Host.UI.ReadLine()

## References ##

# https://devblogs.microsoft.com/scripting/update-or-add-registry-key-value-with-powershell/
# https://devblogs.microsoft.com/scripting/use-powershell-to-edit-the-registry-on-remote-computers/
# https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/new-itemproperty?view=powershell-7.1
# https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_switch?view=powershell-7.1
# https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/restart-service?view=powershell-7.1
# https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-7.1
# https://stackoverflow.com/questions/36328690/how-do-i-pass-variables-with-the-invoke-command-cmdlet
# https://web.archive.org/web/20181018000009/http://brandonpadgett.com/powershell/Local-gpo-powershell/
# https://serverfault.com/questions/848388/how-to-edit-local-group-policy-with-a-script

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