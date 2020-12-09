$WSUS_Server = "WSUS_Server"
if ($WSUS_Server -eq "WSUS_Server") { $WSUS_Server = Read-Host -Prompt "`nWSUS Server IP Address" }

$WSUS_Server_Port = "WSUS_Server_Port"
if ($WSUS_Server_Port -eq "WSUS_Server_Port") { $WSUS_Server_Port = Read-Host -Prompt "WSUS Server Port [Default 8530]" }
if (!($WSUS_Server_Port)) { $WSUS_Server_Port = "8530" }

$registryPath = "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate"
if (!(Test-Path $registryPath)) { New-Item -Path $registryPath -Force | Out-Null }
$Names_WU = "WUServer", "WUStatusServer"
$Names_WU | ForEach-Object { New-ItemProperty -Path $registryPath -Name $_ -Value "http://$($WSUS_Server):$($WSUS_Server_Port)" -PropertyType STRING -FORCE | Out-Null }
New-ItemProperty -Path $registryPath -Name "ElevateNonAdmins" -Value 1 -PropertyType DWORD -FORCE | Out-Null

$registryPath = "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU"
if (!(Test-Path $registryPath)) { New-Item -Path $registryPath -Force | Out-Null }

$Names_WUAU = "NoAutoUpdate", "AUOptions", "ScheduledInstallDay", "ScheduledInstallTime", "NoAutoRebootWithLoggedOnUsers",
                "AutoInstallMinorUpdates", "RebootRelaunchTimeoutEnabled", "RebootRelaunchTimeout", "RescheduleWaitTimeEnabled",
                "RescheduleWaitTime", "DetectionFrequencyEnabled", "RebootWarningTimeoutEnabled", "RebootWarningTimeout", 
                "UseWUServer", "NoAUShutdownOption", "NoAUAsDefaultShutdownOption"

$Names_WUAU | ForEach-Object {
    switch ($_) {
        { $_ -in ("NoAutoUpdate", "ScheduledInstallDay", "AutoInstallMinorUpdates", "NoAUShutdownOption", "NoAUAsDeafultShutdownOption") }
            { New-ItemProperty -Path $registryPath -Name $_ -Value 0 -PropertyType DWORD -Force | Out-Null }
        { $_ -eq "AUOptions" }
            { New-ItemProperty -Path $registryPath -Name $_ -Value 3 -PropertyType DWORD -Force | Out-Null }
        { $_ -eq "ScheduledInstallTime" }
            { New-ItemProperty -Path $registryPath -Name $_ -Value 0x0A -PropertyType DWORD -Force | Out-Null }
        { $_ -in ("NoAutoRebootWithLoggedOnUsers", "RebootRelaunchTimeoutEnabled", "RescheduledWaitTimeEnabled", "DetectionFrequencyEnabled",
                    "RebootWarningTimeoutEnabled", "UseWUSever") }
            { New-ItemProperty -Path $registryPath -Name $_ -Value 1 -PropertyType DWORD -Force | Out-Null }
        { $_ -eq "RebootRelaunchTimeout" }
            { New-ItemProperty -Path $registryPath -Name $_ -Value 0x3c -PropertyType DWORD -Force | Out-Null }
        { $_ -eq "RescheduleWaitTime" } 
            { New-ItemProperty -Path $registryPath -Name $_ -Value 0x0f -PropertyType DWORD -Force | Out-Null }
        { $_ -eq "RebootWarningTimeout" }
            { New-ItemProperty -Path $registryPath -Name $_ -Value 0x1e -PropertyType DWORD -Force | Out-Null }
    }
}

Restart-Service -Name wuauserv

wuauclt.exe /resetauthorization /detectnow
C:\windows\system32\usoclient.exe startscan

write-host "`n[IF NO ERRORS] WSUS Settings Updated. Press enter to exit..." -NoNewLine
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