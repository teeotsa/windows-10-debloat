Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()


# Change `$True` to `$False` to bypass version checking 
$BypassVersionCheck = $True

# Added Dark Mode theme for PowerShell
$Host.UI.RawUI.BackgroundColor = "Black"
Clear-Host

# Added switch to turn on/off version checking
if($BypassVersionCheck -eq $True){
    # Fixed bug where i uncommented out version checking :D
    $WindowsVersion = [System.Environment]::OSVersion.Version.Major
    if (!($WindowsVersion -eq "10")){
        Clear-Host
        Write-Host ("This script is designed to run only on Windows 10. You can always comment out this but its not recommended. 
Script will close in 5 seconds!") -ForegroundColor Yellow -BackgroundColor Black
        Start-Sleep -Seconds 5
        exit
        return;
    }
}
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
	Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
	Exit
}

# Clear-Host

# Added auto importing for modules
$_ModulePath = "$PSScriptRoot\bin\modules";
# Import modules only if modules folder exists
if(Test-Path $_ModulePath){

    $Modules = Get-ChildItem -LiteralPath $_ModulePath -ErrorAction SilentlyContinue #| Out-Null

    $_FoundModuleCount = $Modules.Count;

    #Execute this block of code only when there is more than 1 module found!
    if ($_FoundModuleCount -ge 1){

        foreach($Module in $Modules){
        
            Import-Module $Module -Global -Force -ErrorAction SilentlyContinue | Out-Null
            Write-Host "`"$Module`" found, importing now..." -ForegroundColor Green -BackgroundColor Black
             
        }

    }


}


# Import custom made modules
# Removed this requirement because why not!
<#
$ModuleFolder = "$PSScriptRoot\bin\modules"
if (!(Test-Path "$ModuleFolder\forceRemove.psm1")){
    Write-Warning "Hey, script can't find `"forceRemove.psm1`" module! This module is needed! Script will be closed in 5 seconds!";
    Start-Sleep -Seconds 5
    exit;
}
#>
#Import-Module "$ModuleFolder\forceRemove.psm1" -Global -Force -ErrorAction SilentlyContinue | Out-Null
#Import-Module "$ModuleFolder\showMessage.psm1" -Global -Force -ErrorAction SilentlyContinue | Out-Null


$OtherTweaksLeft = 295
$SystemTweaksLeft = 40

$Form                            = New-Object system.Windows.Forms.Form
$Form.text                       = "Windows 10 Debloater GUI"
$Form.StartPosition              = "CenterScreen"
$Form.TopMost                    = $false
$Form.BackColor                  = [System.Drawing.ColorTranslator]::FromHtml("#b8b8b8")
$Form.AutoScaleDimensions        = '192, 192'
$Form.AutoSize                   = $False
$Form.ClientSize                 = '575, 500'
$Form.FormBorderStyle            = 'FixedSingle'

$Label3                          = New-Object system.Windows.Forms.Label
$Label3.text                     = "System Tweaks"
$Label3.AutoSize                 = $true
$Label3.width                    = 230
$Label3.height                   = 25
$Label3.location                 = New-Object System.Drawing.Point(25,12)
$Label3.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',24)

$essentialtweaks                 = New-Object system.Windows.Forms.Button
$essentialtweaks.text            = "Essential Tweaks"
$essentialtweaks.width           = 204
$essentialtweaks.height          = 30
$essentialtweaks.location        = New-Object System.Drawing.Point($SystemTweaksLeft,56)
$essentialtweaks.Font            = New-Object System.Drawing.Font('Microsoft Sans Serif',12)

$actioncenter                    = New-Object system.Windows.Forms.Button
$actioncenter.text               = "Disable Action Center"
$actioncenter.width              = 203
$actioncenter.height             = 30
$actioncenter.location           = New-Object System.Drawing.Point($SystemTweaksLeft,96)
$actioncenter.Font               = New-Object System.Drawing.Font('Microsoft Sans Serif',12)

$backgroundapps                  = New-Object system.Windows.Forms.Button
$backgroundapps.text             = "Disable Background Apps"
$backgroundapps.width            = 205
$backgroundapps.height           = 30
$backgroundapps.location         = New-Object System.Drawing.Point($SystemTweaksLeft,136)
$backgroundapps.Font             = New-Object System.Drawing.Font('Microsoft Sans Serif',12)

$cortana                         = New-Object system.Windows.Forms.Button
$cortana.text                    = "Disable Cortana (Search)"
$cortana.width                   = 204
$cortana.height                  = 30
$cortana.location                = New-Object System.Drawing.Point($SystemTweaksLeft,176)
$cortana.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',12)

$onedrive                        = New-Object system.Windows.Forms.Button
$onedrive.text                   = "Uninstall OneDrive"
$onedrive.width                  = 204
$onedrive.height                 = 30
$onedrive.location               = New-Object System.Drawing.Point($SystemTweaksLeft,216)
$onedrive.Font                   = New-Object System.Drawing.Font('Microsoft Sans Serif',12)

$darkmode                        = New-Object system.Windows.Forms.Button
$darkmode.text                   = "Dark Mode"
$darkmode.width                  = 204
$darkmode.height                 = 30
$darkmode.location               = New-Object System.Drawing.Point($SystemTweaksLeft,256)
$darkmode.Font                   = New-Object System.Drawing.Font('Microsoft Sans Serif',12)

$lightmode                       = New-Object system.Windows.Forms.Button
$lightmode.text                  = "Light Mode"
$lightmode.width                 = 204
$lightmode.height                = 30
$lightmode.location              = New-Object System.Drawing.Point($SystemTweaksLeft,296)
$lightmode.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',12)

$visualfx                        = New-Object system.Windows.Forms.Button
$visualfx.text                   = "Basic Visual FX"
$visualfx.width                  = 204
$visualfx.height                 = 30
$visualfx.location               = New-Object System.Drawing.Point($SystemTweaksLeft,336)
$visualfx.Font                   = New-Object System.Drawing.Font('Microsoft Sans Serif',12)

$RemoveBloat                     = New-Object system.Windows.Forms.Button
$RemoveBloat.text                = "Uninstall Bloatware"
$RemoveBloat.width               = 204
$RemoveBloat.height              = 30
$RemoveBloat.location            = New-Object System.Drawing.Point($SystemTweaksLeft,376)
$RemoveBloat.Font                = New-Object System.Drawing.Font('Microsoft Sans Serif',12)

$UninstallEdge                   = New-Object system.Windows.Forms.Button
$UninstallEdge.text              = "Uninstall Edge"
$UninstallEdge.width             = 204
$UninstallEdge.height            = 30
$UninstallEdge.location          = New-Object System.Drawing.Point($SystemTweaksLeft,416)
$UninstallEdge.Font              = New-Object System.Drawing.Font('Microsoft Sans Serif',12)

$Label15                         = New-Object system.Windows.Forms.Label
$Label15.text                    = "Other Tweaks"
$Label15.AutoSize                = $true
$Label15.width                   = 25
$Label15.height                  = 10
$Label15.location                = New-Object System.Drawing.Point(315,11)
$Label15.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',24)

$disablewindowsupdate            = New-Object system.Windows.Forms.Button
$disablewindowsupdate.text       = "Disable Windows Update"
$disablewindowsupdate.width      = 250
$disablewindowsupdate.height     = 30
$disablewindowsupdate.location   = New-Object System.Drawing.Point($OtherTweaksLeft,56)
$disablewindowsupdate.Font       = New-Object System.Drawing.Font('Microsoft Sans Serif',14)

$enablewindowsupdate             = New-Object system.Windows.Forms.Button
$enablewindowsupdate.text        = "Enable Windows Update"
$enablewindowsupdate.width       = 250
$enablewindowsupdate.height      = 30
$enablewindowsupdate.location    = New-Object System.Drawing.Point($OtherTweaksLeft,96)
$enablewindowsupdate.Font        = New-Object System.Drawing.Font('Microsoft Sans Serif',14)

$smalltaskbaricons               = New-Object system.Windows.Forms.Button
$smalltaskbaricons.text          = "Use Small Taskbar"
$smalltaskbaricons.width         = 250
$smalltaskbaricons.height        = 30
$smalltaskbaricons.location      = New-Object System.Drawing.Point($OtherTweaksLeft,136)
$smalltaskbaricons.Font          = New-Object System.Drawing.Font('Microsoft Sans Serif',12)

# Update 1 : Removed 'Windows Cleaner' button and replaced it with 'Remove Take Ownership' button!
# * Reason why i removed this was because its useless and also i deleted 'Windows Cleaner' repository
 
$RemoveTakeOwnership             = New-Object system.Windows.Forms.Button
$RemoveTakeOwnership.text        = "Remove Take Ownership"
$RemoveTakeOwnership.width       = 250
$RemoveTakeOwnership.height      = 30
$RemoveTakeOwnership.location    = New-Object System.Drawing.Point($OtherTweaksLeft,176)
$RemoveTakeOwnership.Font        = New-Object System.Drawing.Font('Microsoft Sans Serif',12)

$TakeOwnership                   = New-Object system.Windows.Forms.Button
$TakeOwnership.text              = "Take Ownership"
$TakeOwnership.width             = 250
$TakeOwnership.height            = 30
$TakeOwnership.location          = New-Object System.Drawing.Point($OtherTweaksLeft,216)
$TakeOwnership.Font              = New-Object System.Drawing.Font('Microsoft Sans Serif',12)

$MiscLabel                       = New-Object system.Windows.Forms.Label
$MiscLabel.text                  = "Misc"
$MiscLabel.AutoSize              = $true
$MiscLabel.width                 = 25
$MiscLabel.height                = 10
$MiscLabel.location              = New-Object System.Drawing.Point(375,256)
$MiscLabel.Font                  = New-Object System.Drawing.Font('The Patriot',24)

$EditScript                      = New-Object system.Windows.Forms.Button
$EditScript.text                 = "Edit this Script!"
$EditScript.width                = 250
$EditScript.height               = 30
$EditScript.location             = New-Object System.Drawing.Point($OtherTweaksLeft,305)
$EditScript.Font                 = New-Object System.Drawing.Font('Microsoft Sans Serif',12)

#region Commented-Out-Stuff
<#


$LegacyVolume                    = New-Object System.Windows.Forms.CheckBox
$LegacyVolume.Location           = New-Object System.Drawing.Size(297,340)
$LegacyVolume.Size               = New-Object System.Drawing.Size(110,15)
$LegacyVolume.Text               = "Legacy Volume Control"
$LegacyVolume.Checked            = $False

$LegacyNotifications             = New-Object System.Windows.Forms.CheckBox
$LegacyNotifications.Location    = New-Object System.Drawing.Size(400,340)
$LegacyNotifications.Size        = New-Object System.Drawing.Size(130,15)
$LegacyNotifications.Text        = "Legacy Notifications"
$LegacyNotifications.Checked     = $False

$AdminAccount                    = new-object System.Windows.Forms.checkbox
$AdminAccount.Location           = new-object System.Drawing.Size(42,455)
$AdminAccount.Size               = new-object System.Drawing.Size(100,15)
$AdminAccount.Text               = "Admin Account"
$AdminAccount.Checked            = $False;

#>

<#
#Tick Legacy Volume Control Checkbox if its enabled!
$VolumeControlKey = Get-ItemPropertyValue -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\MTCUVC" -Name "EnableMtcUvc" | Out-Null
if($VolumeControlKey -eq 0){
    $LegacyVolume.Checked = $True;
}

$AdminAcc = Get-LocalUser -Name "Administrator"
if ($AdminAcc.Enabled -eq $True){
    $AdminAccount.Checked = $True;
}

$LegacyNotificationsKey = Get-ItemPropertyValue -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "EnableLegacyBalloonNotifications"
$GetLegacyNotifications = Get-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "EnableLegacyBalloonNotifications" -ErrorAction SilentlyContinue | Out-Null
if(!($GetLegacyNotifications)){
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "EnableLegacyBalloonNotifications" -Type DWord -Value 0
}
if($LegacyNotificationsKey -eq 1){
    $LegacyNotifications.Checked = $True
}
#>
#endregion

# $LegacyNotifications,$LegacyVolume,$AdminAccount
$Form.controls.AddRange(@($MiscLabel,$EditScript,$TakeOwnership,$UninstallEdge,$RemoveBloat,$disablewindowsupdate,$enablewindowsupdate,$smalltaskbaricons,$Label16,$Label17,$Label18,$Label19,$RemoveTakeOwnership,$Panel1,$Panel2,$Label3,$Label15,$Panel4,$PictureBox1,$Label1,$Label4,$Panel3,$essentialtweaks,$backgroundapps,$cortana,$actioncenter,$darkmode,$visualfx,$onedrive,$lightmode))

$essentialtweaks.Add_Click({

    Write-Host "Making Restore Point... Please wait"
    Enable-ComputerRestore -Drive $env:SYSTEMDRIVE
    Checkpoint-Computer -Description "RestorePoint1" -RestorePointType "MODIFY_SETTINGS"

    # OOShutup10 part will remain commented out until i have made a new config. You can just use this program manually
    #Write-Host "Running O&O Shutup with Not Recommended Settings"
    #Import-Module BitsTransfer
    # Update 2 : Fixed O&OSHUTUP10 Config Link.
    #Start-BitsTransfer -Source "https://raw.githubusercontent.com/teeotsa/windows-10-debloat/main/ooshutup10.cfg" -Destination ooshutup10.cfg
    #Start-BitsTransfer -Source "https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe" -Destination OOSU10.exe
    #./OOSU10.exe ooshutup10.cfg /quiet

    Write-Host "Disabling Telemetry..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\ProgramDataUpdater" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Autochk\Proxy" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null
    Write-Host "Disabling Application suggestions..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1
    Write-Host "Disabling Activity History..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0
    Write-Host "Disabling Location Tracking..."
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type String -Value "Deny"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 0
    Write-Host "Disabling automatic Maps updates..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -Type DWord -Value 0
    Write-Host "Disabling Feedback..."
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type DWord -Value 1
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClient" -ErrorAction SilentlyContinue | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" -ErrorAction SilentlyContinue | Out-Null
    Write-Host "Disabling Tailored Experiences..."
    If (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
        New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value 1
    Write-Host "Disabling Advertising ID..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Type DWord -Value 1
    Write-Host "Disabling Error reporting..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 1
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Windows Error Reporting\QueueReporting" | Out-Null
    #Write-Host "Restricting Windows Update P2P only to local network..."
    #If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config")) {
    #    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" | Out-Null
    #}
    #Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type DWord -Value 1
    Write-Host "Stopping and disabling Diagnostics Tracking Service..."
    Stop-Service "DiagTrack" -WarningAction SilentlyContinue
    Set-Service "DiagTrack" -StartupType Disabled
    Write-Host "Stopping and disabling WAP Push Service..."
    Stop-Service "dmwappushservice" -WarningAction SilentlyContinue
    Set-Service "dmwappushservice" -StartupType Disabled
    Write-Host "Enabling F8 boot menu options..."
    bcdedit /set `{current`} bootmenupolicy Legacy | Out-Null
    Write-Host "Stopping and disabling Home Groups services..."
    Stop-Service "HomeGroupListener" -WarningAction SilentlyContinue
    Set-Service "HomeGroupListener" -StartupType Disabled
    Stop-Service "HomeGroupProvider" -WarningAction SilentlyContinue
    Set-Service "HomeGroupProvider" -StartupType Disabled
    Write-Host "Disabling Remote Assistance..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0
    Write-Host "Disabling Storage Sense..."
    Remove-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Recurse -ErrorAction SilentlyContinue
    Write-Host "Stopping and disabling Superfetch service..."
    Stop-Service "SysMain" -WarningAction SilentlyContinue
    Set-Service "SysMain" -StartupType Disabled
    Write-Host "Setting BIOS time to UTC..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" -Name "RealTimeIsUniversal" -Type DWord -Value 1
    Write-Host "Disabling Hibernation..."
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Power" -Name "HibernteEnabled" -Type Dword -Value 0
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowHibernateOption" -Type Dword -Value 0
    Write-Host "Showing task manager details..."
    $taskmgr = Start-Process -WindowStyle Hidden -FilePath taskmgr.exe -PassThru
    Do {
        Start-Sleep -Milliseconds 100
        $preferences = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -ErrorAction SilentlyContinue
    } Until ($preferences)
    Stop-Process $taskmgr
    $preferences.Preferences[28] = 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -Type Binary -Value $preferences.Preferences
    Write-Host "Showing file operations details..."
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -Type DWord -Value 1
    Write-Host "Hiding Task View button..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0
    Write-Host "Hiding People icon..."
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Type DWord -Value 0
    Write-Host "Showing all tray icons..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -Type DWord -Value 0
    Write-Host "Enabling NumLock after startup..."
    If (!(Test-Path "HKU:")) {
        New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
    }
    Set-ItemProperty -Path "HKU:\.DEFAULT\Control Panel\Keyboard" -Name "InitialKeyboardIndicators" -Type DWord -Value 2147483650
    Add-Type -AssemblyName System.Windows.Forms
    If (!([System.Windows.Forms.Control]::IsKeyLocked('NumLock'))) {
        $wsh = New-Object -ComObject WScript.Shell
        $wsh.SendKeys('{NUMLOCK}')
    }

    Write-Host "Changing default Explorer view to This PC..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1
    Write-Host "Hiding 3D Objects icon from This PC..."
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Recurse -ErrorAction SilentlyContinue
	#Network Tweaks
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "IRPStackSize" -Type DWord -Value 20
	#SVCHost Tweak
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "SvcHostSplitThresholdInKB" -Type DWord -Value 4194304
    Write-Host "Disable News and Interests"
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Name "EnableFeeds" -Type DWord -Value 0
    #Remove news and interest from taskbar
    Set-ItemProperty -Path  "HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds" -Name "ShellFeedsTaskbarViewMode" -Type DWord -Value 2
    #Remove meet now button from taskbar
    If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAMeetNow" -Type DWord -Value 1
    Write-Host "Removing AutoLogger file and restricting directory..."
    $autoLoggerDir = "$env:PROGRAMDATA\Microsoft\Diagnosis\ETLLogs\AutoLogger"
    If (Test-Path "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl") {
        Remove-Item "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl"
    }
    icacls $autoLoggerDir /deny SYSTEM:`(OI`)`(CI`)F | Out-Null
    Write-Host "Disabling some services and scheduled tasks"

    $Services = @(
        "XboxNetApiSvc"
        "XblGameSave"
        "XblAuthManager"
        "XboxGipSvc"
        "LanmanWorkstation"
        "workfolderssvc"
        #"WlanSvc" ... WLAN AutoConfig (Needed for Wi-Fi)
        #"W32Time" ... Windows Time (Needed for automatic time syncing)
        "WpnService"
        "icssvc"
        "MixedRealityOpenXRSvc"
        "WMPNetworkSvc"
        "LicenseManager"
        #"wlidsvc" ... Microsoft Account Sign-in Assistant (Needed if you wish to not use Microsoft Accounts)
        "wisvc"
        "Wecsvc"
        "WerSvc"
        "FrameServer"
        #"WbioSrvc" ... Windows Biometric Service (Needed for Fingerprints and Face)
        #"SDRSVC" ... Windows Backup (Needed for Restore Points, Windows Backup features)
        #"WFDSConMgrSvc" ... Wi-Fi Direct Services Connection Manager Service (Might be needed for Wi-Fi)
        "WebClient"
        "TokenBroker"
        "WalletService"
        #"VSS" ... Volume Shadow Copy (Needed for Windows Backup, Restore Points)
        #"vds" ... Virtual Disk (Needed for Disk Managment)
        #"TabletInputService" ... Touch Keyboard and Handwriting Panel Service (Needed for Windows Terminal and other input devices)
        #"StorSvc" ... Storage Service (Needed for Disk Managment and other storage related stuff)
        "SharedRealitySvc"
        "sppsvc"
        "SCPolicySvc"
        "ScDeviceEnum"
        "SCardSvr"
        "LanmanServer"
        "SensorService"
        "SensrSvc"
        "SensorDataService"
        "wscsvc"
        "seclogon"
        "RetailDemo"
        "RemoteRegistry"
        "RasMan"
        "TroubleshootingSvc"
        "SessionEnv"
        "TermService"
        "RmSvc"
        "QWAVE"
        "PcaSvc"
        "wercplsupport"
        "PrintNotify"
        "Spooler"
        "PhoneSvc"
        "WpcMonSvc"
        "SEMgrSvc"
        "defragsvc"
        "CscService"
        "Netlogon"
        "SmsRouter"
        "InstallService"
        "smphost"
        #"swprv" ... Microsoft Software Shadow Copy Provider (Needed for Application Backups)
        "NgcCtnrSvc"
        "NgcSvc"
        "MsKeyboardFilter"
        "MSiSCSI"
        "edgeupdatem"
        "edgeupdate"
        "MicrosoftEdgeElevationService"
        "AppVClient"
        "diagnosticshub.standardcollector.service"
        "iphlpsvc"
        "lfsvc"
        "fhsvc"
        "Fax"
        "embeddedmode"
        "MapsBroker"
        "TrkWks"
        "DispBrokerDesktopSvc"
        "DisplayEnhancementService"
        #"WdiSystemHost" ... Diagnostic System Host (Needed for Diagnostics)
        #"WdiServiceHost" ... Diagnostic Service Host (Needed for Diagnostics)
        #"DPS" ... Diagnostic Policy Service (Needed for Diagnostics)
        #"diagsvc" ... Diagnostic Execution Service (Needed for Diagnostics)
        "DoSvc"
        "DusmSvc"
        "DsSvc"
        "CryptSvc"
        "VaultSvc"
        "DiagTrack"
        "autotimesvc"
        #"bthserv" ... Bluetooth Support Service (Needed for bluetooth)
        #"BTAGService" ... Bluetooth Audio Gateway Service (Needed for bluetooth)
        #"BDESVC" ... BitLocker Drive Encryption Service (Needed for BitLocker)
        #"tzautoupdate" ... Auto Time Zone Updater (Needed for automatic time syncing...)
        #"WinHttpAutoProxySvc" ... WinHTTP Web Proxy Auto-Discovery Service
        #"lmhosts" ... TCP/IP NetBIOS Helper
        #"IKEEXT" ... IKE and AuthIP IPsec Keying Modules
    )

    foreach ($Service in $Services) {
    Get-Service -Name $Service -ErrorAction SilentlyContinue | Set-Service -StartupType Disabled
        $running = Get-Service -Name $Service -ErrorAction SilentlyContinue | Where-Object {$_.Status -eq 'Running'}
        if ($running) { 
            Stop-Service -Name $Service -Force -PassThru | Out-Null
            Write-Host "`"$Service`" was running, stopping it now...";
        }
    }

    Disable-ScheduledTask -TaskName "\Microsoft\XblGameSave\XblGameSaveTask" | Out-Null
    #Disable-ScheduledTask -TaskName "\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" | Out-Null
    #Disable-ScheduledTask -TaskName "\Microsoft\Windows\Windows Defender\Windows Defender Cleanup" | Out-Null
    #Disable-ScheduledTask -TaskName "\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" | Out-Null
    #Disable-ScheduledTask -TaskName "\Microsoft\Windows\Windows Defender\Windows Defender Verification" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\WDI\ResolutionHost" | Out-Null
    #Disable-ScheduledTask -TaskName "\Microsoft\Windows\WCM\WiFiTask" | Out-Null
    #Disable-ScheduledTask -TaskName "\Microsoft\Windows\Time Zone\SynchronizeTimeZone" | Out-Null
    #Disable-ScheduledTask -TaskName "\Microsoft\Windows\Time Synchronization\ForceSynchronizeTime" | Out-Null
    #Disable-ScheduledTask -TaskName "\Microsoft\Windows\Time Synchronization\SynchronizeTime" | Out-Null
    #Disable-ScheduledTask -TaskName "\Microsoft\Windows\SystemRestore\SR" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Sysmain\HybridDriveCachePrepopulate" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Sysmain\HybridDriveCacheRebalance" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Sysmain\ResPriStaticDbSync" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Sysmain\WsSwapAssessmentTask" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Speech\SpeechModelDownloadTask" | Out-Null
    #Disable-ScheduledTask -TaskName "\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTask" | Out-Null
    #Disable-ScheduledTask -TaskName "\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTaskLogon" | Out-Null
    #Disable-ScheduledTask -TaskName "\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTaskNetwork" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Shell\IndexerAutomaticMaintenance" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Setup\SetupCleanupTask" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\SettingSync\NetworkStateChangeTask" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Registry\RegIdleBackup" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Printing\EduPrintProv" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Offline Files\Background Synchronization" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Offline Files\Logon Synchronization" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Maps\MapsToastTask" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Maps\MapsUpdateTask" | Out-Null
    #Disable-ScheduledTask -TaskName "\Microsoft\Windows\Location\WindowsActionDialog" | Out-Null
    #Disable-ScheduledTask -TaskName "\Microsoft\Windows\Location\Notifications" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\InstallService\ScanForUpdates" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\InstallService\ScanForUpdatesAsUser" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\InstallService\SmartRetry" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\InstallService\WakeUpAndContinueUpdates" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\InstallService\WakeUpAndScanForUpdates" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Input\LocalUserSyncDataAvailable" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Input\MouseSyncDataAvailable" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Input\PenSyncDataAvailable" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Input\TouchpadSyncDataAvailable" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\HelloFace\FODCleanupTask" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\FileHistory\File History (maintenance mode)" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\DiskCleanup\SilentCleanup" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\DirectX\DirectXDatabaseUpdater" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Diagnosis\Scheduled" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Defrag\ScheduledDefrag" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\CloudExperienceHost\CreateObjectTask" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Clip\License Validation" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\BrokerInfrastructure\BgTaskRegistrationMaintenanceTask" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Bluetooth\UninstallDeviceTask" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Application Experience\ProgramDataUpdater" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Application Experience\StartupAppTask" | Out-Null

    write-Host "Trying to disable Hibernation..."
    if (!(Test-Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Power")) {
        New-Item -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Power" -Force
    }
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Power" -Name "HibernteEnabled" -Type Dword -Value 0
    if (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Force
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowHibernateOption" -Type Dword -Value 0

    if (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")){
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0
    write-Host "Now, you will see file extensions"
    if (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")){
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1
    if (!(Test-Path "HKCU:\Control Panel\Accessibility\StickyKeys")){
        New-Item -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Type String -Value "506"
    write-Host "Sticky Keys should be disabled now"
    If (!(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\Personalization")) {
 	    New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\Personalization" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreen" -Type DWord -Value 1
    write-Host "Lock Screen has been disabled"
    #if (!(Test-Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System")){
    #    New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Force | Out-Null
    #}
    #Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 0
    #Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 0
    #write-Host "UAC has been disabled"   
    If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo")) {
	New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Type DWord -Value 0
    write-Host "Advertising ID has been disabled"
    if (!(Test-Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer")){
        New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Type String -Value "Off"
    if (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost")){
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -Type DWord -Value 0
    write-Host "SmartScreen has been disabled"
    #write-Host "Trying to disabled Wi-Fi Sense..."
    #If (!(Test-Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting")) {
	#    New-Item -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Force | Out-Null
    #}
    #Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 0
    #if (!(Test-Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots")){
    #    New-Item -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Force | Out-Null
    #}
    #Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 0
    #write-Host "Wi-Fi Sense has been disabled"
    #write-Host "Disabled Windows Firewall"
    #Set-NetFirewallProfile -Profile * -Enabled False
    #if (!(Test-Path "HKLM:\Software\Policies\Microsoft\Windows Defender")){
    #    New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Force | Out-Null
    #}
    #Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Type DWord -Value 1
    #write-Host "Disabled Windows Defender"
    if (!(Test-Path "HKLM:\System\CurrentControlSet\Control\Terminal Server")){
        New-Item -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Type DWord -Value 1
    if (!(Test-Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp")){
        New-Item -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Type DWord -Value 1
    write-Host "Disabled Remote Desktop"
    if (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers")){
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Type DWord -Value 1
    write-Host "Disabled AutoPlay"

    if (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search")){
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0
    write-Host "Disabled Search on taskbar"
    if (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")){
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0
    write-Host "Disabled Task View button on taskbar"

    if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\FileHistory")){
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\FileHistory" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\FileHistory" -Name "Disabled" -Type DWord -Value 1
    if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports")){
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" -Name "PreventHandwritingErrorReports" -Type DWord -Value 1
    #if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors")){
    #    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Force | Out-Null
    #}
    #Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Type DWord -Value 1
    #Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocationScripting" -Type DWord -Value 1
    #Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableSensors" -Type DWord -Value 1
    #Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableWindowsLocationProvider" -Type DWord -Value 1
    if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging")){
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging" -Name "AllowMessageSync" -Type DWord -Value 0
    if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps")){
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps" -Name "AutoDownloadAndUpdateMapData" -Type DWord -Value 0

    if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings")){
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" -Force | Out-Null
    }

    #Disable Notifications
    Get-ChildItem -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" | ForEach {
        Set-ItemProperty -Path $_.PsPath -Name "Enabled" -Type DWord -Value 0
        Set-ItemProperty -Path $_.PsPath -Name "LastNotificationAddedTime" -Type QWord -Value "0"
    }    
    #if (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications")){
    #    New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Force | Out-Null
    #}
    #Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoTileApplicationNotification" -Type DWord -Value 1
    Write-Host "Disable NumLock after startup..."
    Set-ItemProperty -Path "HKU:\.DEFAULT\Control Panel\Keyboard" -Name "InitialKeyboardIndicators" -Type DWord -Value 0
    Add-Type -AssemblyName System.Windows.Forms
    If (([System.Windows.Forms.Control]::IsKeyLocked('NumLock'))) {
        $wsh = New-Object -ComObject WScript.Shell
        $wsh.SendKeys('{NUMLOCK}')
    }
    #if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore")){
    #    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Force | Out-Null
    #}
    #Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "RemoveWindowsStore" -Type DWord -Value 1
    if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds")){
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Name "EnableFeeds" -Type DWord -Value 0
    if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR")){
        New-Path -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Type DWord -Value 0
    #if (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer")){
    #    New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Force | Out-Null
    #}
    #Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "EnableLegacyBalloonNotifications" -Type DWord -Value 1
    #write-Host "Legacy Notifications enabled"

    #if (!(Test-Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\MTCUVC")){
    #    New-Item -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\MTCUVC" -Force | Out-Null
    #}
    #Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\MTCUVC" -Name "EnableMtcUvc" -Type DWord -Value 0
    #write-Host "Legacy Volume control enabled"
    if (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager")){
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0
    }

    #tweaking abit more (less ram usage)
    if((Test-Path -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Control") -ne $true) {  New-Item "HKLM:\SYSTEM\CurrentControlSet\Control" -force -ea SilentlyContinue };
    if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile") -ne $true) {  New-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -force -ea SilentlyContinue };
    if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks") -ne $true) {  New-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks" -force -ea SilentlyContinue };
    if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio") -ne $true) {  New-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" -force -ea SilentlyContinue };
    if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture") -ne $true) {  New-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" -force -ea SilentlyContinue };
    if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing") -ne $true) {  New-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" -force -ea SilentlyContinue };
    if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution") -ne $true) {  New-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" -force -ea SilentlyContinue };
    if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games") -ne $true) {  New-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -force -ea SilentlyContinue };
    if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback") -ne $true) {  New-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" -force -ea SilentlyContinue };
    if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio") -ne $true) {  New-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" -force -ea SilentlyContinue };
    if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager") -ne $true) {  New-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" -force -ea SilentlyContinue };
    if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching") -ne $true) {  New-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -force -ea SilentlyContinue };
    if((Test-Path -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power") -ne $true) {  New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -force -ea SilentlyContinue };
    if((Test-Path -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling") -ne $true) {  New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" -force -ea SilentlyContinue };
    if((Test-Path -LiteralPath "HKCU:\System\GameConfigStore") -ne $true) {  New-Item "HKCU:\System\GameConfigStore" -force -ea SilentlyContinue };
    if((Test-Path -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Control\Power") -ne $true) {  New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -force -ea SilentlyContinue };
    if((Test-Path -LiteralPath "HKCU:\Control Panel\Desktop") -ne $true) {  New-Item "HKCU:\Control Panel\Desktop" -force -ea SilentlyContinue };
    if((Test-Path -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\943c8cb6-6f93-4227-ad87-e9a3feec08d1") -ne $true) {  New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\943c8cb6-6f93-4227-ad87-e9a3feec08d1" -force -ea SilentlyContinue };
    if((Test-Path -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e") -ne $true) {  New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" -force -ea SilentlyContinue };
    if((Test-Path -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c") -ne $true) {  New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" -force -ea SilentlyContinue };
    if((Test-Path -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e") -ne $true) {  New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" -force -ea SilentlyContinue };
    if((Test-Path -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c") -ne $true) {  New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" -force -ea SilentlyContinue };
    if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender") -ne $true) {  New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -force -ea SilentlyContinue };
    New-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control' -Name 'SvcHostSplitThresholdInKB' -Value 67108864 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control' -Name 'WaitToKillServiceTimeout' -Value '2000' -PropertyType String -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile' -Name 'NetworkThrottlingIndex' -Value -1 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile' -Name 'SystemResponsiveness' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio' -Name 'Affinity' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio' -Name 'Background Only' -Value 'True' -PropertyType String -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio' -Name 'Clock Rate' -Value 10000 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio' -Name 'GPU Priority' -Value 8 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio' -Name 'Priority' -Value 6 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio' -Name 'Scheduling Category' -Value 'Medium' -PropertyType String -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio' -Name 'SFIO Priority' -Value 'Normal' -PropertyType String -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture' -Name 'Affinity' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture' -Name 'Background Only' -Value 'True' -PropertyType String -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture' -Name 'Clock Rate' -Value 10000 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture' -Name 'GPU Priority' -Value 8 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture' -Name 'Priority' -Value 5 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture' -Name 'Scheduling Category' -Value 'Medium' -PropertyType String -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture' -Name 'SFIO Priority' -Value 'Normal' -PropertyType String -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing' -Name 'Affinity' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing' -Name 'Background Only' -Value 'True' -PropertyType String -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing' -Name 'BackgroundPriority' -Value 8 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing' -Name 'Clock Rate' -Value 10000 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing' -Name 'GPU Priority' -Value 8 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing' -Name 'Priority' -Value 8 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing' -Name 'Scheduling Category' -Value 'High' -PropertyType String -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing' -Name 'SFIO Priority' -Value 'Normal' -PropertyType String -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution' -Name 'Affinity' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution' -Name 'Background Only' -Value 'True' -PropertyType String -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution' -Name 'Clock Rate' -Value 10000 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution' -Name 'GPU Priority' -Value 8 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution' -Name 'Priority' -Value 4 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution' -Name 'Scheduling Category' -Value 'Medium' -PropertyType String -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution' -Name 'SFIO Priority' -Value 'Normal' -PropertyType String -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games' -Name 'Affinity' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games' -Name 'Background Only' -Value 'False' -PropertyType String -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games' -Name 'Clock Rate' -Value 10000 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games' -Name 'GPU Priority' -Value 8 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games' -Name 'Priority' -Value 6 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games' -Name 'Scheduling Category' -Value 'High' -PropertyType String -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games' -Name 'SFIO Priority' -Value 'High' -PropertyType String -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback' -Name 'Affinity' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback' -Name 'Background Only' -Value 'False' -PropertyType String -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback' -Name 'BackgroundPriority' -Value 4 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback' -Name 'Clock Rate' -Value 10000 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback' -Name 'GPU Priority' -Value 8 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback' -Name 'Priority' -Value 3 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback' -Name 'Scheduling Category' -Value 'Medium' -PropertyType String -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback' -Name 'SFIO Priority' -Value 'Normal' -PropertyType String -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio' -Name 'Affinity' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio' -Name 'Background Only' -Value 'False' -PropertyType String -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio' -Name 'Clock Rate' -Value 10000 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio' -Name 'GPU Priority' -Value 8 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio' -Name 'Priority' -Value 1 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio' -Name 'Scheduling Category' -Value 'High' -PropertyType String -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio' -Name 'SFIO Priority' -Value 'Normal' -PropertyType String -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager' -Name 'Affinity' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager' -Name 'Background Only' -Value 'True' -PropertyType String -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager' -Name 'Clock Rate' -Value 10000 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager' -Name 'GPU Priority' -Value 8 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager' -Name 'Priority' -Value 5 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager' -Name 'Scheduling Category' -Value 'Medium' -PropertyType String -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager' -Name 'SFIO Priority' -Value 'Normal' -PropertyType String -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games' -Name 'Affinity' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games' -Name 'Background Only' -Value 'False' -PropertyType String -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games' -Name 'Clock Rate' -Value 10000 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games' -Name 'GPU Priority' -Value 8 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games' -Name 'Priority' -Value 6 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games' -Name 'Scheduling Category' -Value 'High' -PropertyType String -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games' -Name 'SFIO Priority' -Value 'High' -PropertyType String -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching' -Name 'SearchOrderConfig' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name 'HiberbootEnabled' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling' -Name 'PowerThrottlingOff' -Value 1 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKCU:\System\GameConfigStore' -Name 'GameDVR_Enabled' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKCU:\System\GameConfigStore' -Name 'GameDVR_FSEBehaviorMode' -Value 2 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKCU:\System\GameConfigStore' -Name 'Win32_AutoGameModeDefaultProfile' -Value ([byte[]](0x01,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00)) -PropertyType Binary -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKCU:\System\GameConfigStore' -Name 'Win32_GameModeRelatedProcesses' -Value ([byte[]](0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00)) -PropertyType Binary -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKCU:\System\GameConfigStore' -Name 'GameDVR_HonorUserFSEBehaviorMode' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKCU:\System\GameConfigStore' -Name 'GameDVR_DXGIHonorFSEWindowsCompatible' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKCU:\System\GameConfigStore' -Name 'GameDVR_EFSEFeatureFlags' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' -Name 'HibernateEnabledDefault' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKCU:\Control Panel\Desktop' -Name 'MenuShowDelay' -Value '0' -PropertyType String -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKCU:\Control Panel\Desktop' -Name 'WaitToKillAppTimeout' -Value '5000' -PropertyType String -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKCU:\Control Panel\Desktop' -Name 'HungAppTimeout' -Value '4000' -PropertyType String -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKCU:\Control Panel\Desktop' -Name 'AutoEndTasks' -Value '1' -PropertyType String -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKCU:\Control Panel\Desktop' -Name 'LowLevelHooksTimeout' -Value 4096 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKCU:\Control Panel\Desktop' -Name 'WaitToKillServiceTimeout' -Value 8192 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\943c8cb6-6f93-4227-ad87-e9a3feec08d1' -Name 'Attributes' -Value 2 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e' -Name 'ACSettingIndex' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e' -Name 'DCSettingIndex' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c' -Name 'ACSettingIndex' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e' -Name 'ACSettingIndex' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e' -Name 'DCSettingIndex' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c' -Name 'ACSettingIndex' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue;
    #New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name 'DisableAntiSpyware' -Value 1 -PropertyType DWord -Force -ea SilentlyContinue;

    <#

    write-Host "Tweaking 'Imersive Control Panel' items."

    $List = @(
        "quiethours"
        "tabletmode"
        "multitasking"
        "project"
        "crossdevice"
        "autoplay"
        "mobile-devices"
        "network-mobilehotspot"
        "nfctransactions"
        "datausage"
        "network-proxy"
        "lockscreen"
        "maps"
        "sync"
        "speech"
        "gaming-xboxnetworking"
        "easeofaccess-cursorandpointersize"
        "easeofaccess-closedcaptioning"
        "easeofaccess-speechrecognition"
        "easeofaccess-eyecontrol"
        "cortana-talktocortana"
        "cortana-permissions"
        "cortana-moredetails"
        "privacy;privacy-speech"
        "privacy-speechtyping"
        "privacy-feedback"
        "privacy-activityhistory"
        "privacy-voiceactivation"
        "privacy-eyetracker"
        "privacy-appdiagnostics"
        "delivery-optimization"
    )
    $Lines = "hide:";

    foreach($Item in $List){ $Lines = $Lines + $Item + ";" }
    $ImmersiveControlPanelPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    if (!(Test-Path $ImmersiveControlPanelPath)){
        New-Item -Path $ImmersiveControlPanelPath -Force | Out-Null
    }
    Set-ItemProperty -Path $ImmersiveControlPanelPath -Name "SettingsPageVisibility" -Type String -Value $Lines
    #>

    # Fix automatic time syncing
    Set-Service -Name W32Time -StartupType Automatic
    Start-Service -Name W32Time

    $Trigger = New-ScheduledTaskTrigger -AtLogOn
    $User = "Administrator"
    $Action = New-ScheduledTaskAction -Execute "net start w32time"
    $Description = "This task was made by Teeotsa's script! You can safely delete this task if you wish not to have auto syncing time!"
    Register-ScheduledTask -TaskName "Auto Time Sync" -Trigger $Trigger -User $User -Action $Action -RunLevel Highest -Description $Description

    Start-Sleep -Seconds 1
    Stop-Process -Name explorer -Force -PassThru
    Write-Host "Tweaks are done!"
})

$cortana.Add_Click({
    Write-Host "Disabling Bing Search in Start Menu..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Type DWord -Value 0
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Type DWord -Value 1
    Write-Host "Stopping and disabling Windows Search indexing service..."
    Stop-Service "WSearch" -WarningAction SilentlyContinue
    Set-Service "WSearch" -StartupType Disabled
    Write-Host "Hiding Taskbar Search icon / box..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0
    Write-Host "Search tweaks completed"

    Write-Host "Disabling Cortana..."
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type DWord -Value 0
    Stop-Process -Name "SearchApp" -Force -PassThru -ErrorAction SilentlyContinue
    Stop-Process -Name explorer -Force -PassThru
    Write-Host "Disabled Cortana"
})

$backgroundapps.Add_Click({
    Write-Host "Disabling Background application access..."
    Get-ChildItem -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" | ForEach {
        Set-ItemProperty -Path $_.PsPath -Name "Disabled" -Type DWord -Value 1
        Set-ItemProperty -Path $_.PsPath -Name "DisabledByUser" -Type DWord -Value 1
    }
    if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications")){
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Name "GlobalUserDisabled" -Type DWord -Value 1
    Write-Host "Disabled Background application access"
})

$actioncenter.Add_Click({
    Write-Host "Disabling Action Center..."
    If (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) {
        New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -Type DWord -Value 1
    if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications")){
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -Type DWord -Value 0
    Stop-Process -Name "explorer" -Force -PassThru -ErrorAction SilentlyContinue
    Write-Host "Disabled Action Center"
})

$visualfx.Add_Click({
    Write-Host "Adjusting visual effects for performance..."
    if (!(Test-Path "HKCU:\Control Panel\Desktop")){
        New-Item -Path "HKCU:\Control Panel\Desktop" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "DragFullWindows" -Type String -Value 0
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Type String -Value 200
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -Type Binary -Value ([byte[]](144,18,3,128,16,0,0,0))
    if (!(Test-Path "HKCU:\Control Panel\Desktop\WindowMetrics")){
        New-Item -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Type String -Value 0
    if (!(Test-Path "HKCU:\Control Panel\Keyboard")){
        New-Item -Path "HKCU:\Control Panel\Keyboard" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name "KeyboardDelay" -Type DWord -Value 0
    if (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")){
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewAlphaSelect" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewShadow" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAnimations" -Type DWord -Value 0
    if (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects")){
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Type DWord -Value 3
    if (!(Test-Path "HKCU:\Software\Microsoft\Windows\DWM")){
        New-Item -Path "HKCU:\Software\Microsoft\Windows\DWM" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "EnableAeroPeek" -Type DWord -Value 0
    if (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\TaskbarAnimations")){
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\TaskbarAnimations" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\TaskbarAnimations" -Name "DefaultApplied" -Type DWord -Value 0
    if (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListBoxSmoothScrolling")){
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListBoxSmoothScrolling" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListBoxSmoothScrolling" -Name "DefaultApplied" -Type DWord -Value 0
    if (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DWMAeroPeekEnabled")){
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DWMAeroPeekEnabled" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DWMAeroPeekEnabled" -Name "DefaultApplied" -Type DWord -Value 0
    if (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\MenuAnimation")){
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\MenuAnimation" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\MenuAnimation" -Name "DefaultApplied" -Type DWord -Value 0
    if (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\TooltipAnimation")){
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\TooltipAnimation" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\TooltipAnimation" -Name "DefaultApplied" -Type DWord -Value 0
    if (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ComboBoxAnimation")){
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ComboBoxAnimation" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ComboBoxAnimation" -Name "DefaultApplied" -Type DWord -Value 0
    if (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\CursorShadow")){
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\CursorShadow" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\CursorShadow" -Name "DefaultApplied" -Type DWord -Value 0
    if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize")){
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "EnableTransparency" -Type DWord -Value 0
    Start-Sleep -Seconds 1
    Stop-Process -Name explorer -Force
    Write-Host "Adjusted visual effects for performance"
})

$onedrive.Add_Click({
    Write-Host "Disabling OneDrive..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Type DWord -Value 1
    Write-Host "Uninstalling OneDrive..."
    Stop-Process -Name "OneDrive" -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    $onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
    If (!(Test-Path $onedrive)) {
        $onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
    }
    Start-Process $onedrive "/uninstall" -NoNewWindow -Wait
    Start-Sleep -Seconds 2
    Stop-Process -Name "explorer" -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    Remove-Item -Path "$env:USERPROFILE\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:PROGRAMDATA\Microsoft OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:SYSTEMDRIVE\OneDriveTemp" -Force -Recurse -ErrorAction SilentlyContinue
    If (!(Test-Path "HKCR:")) {
        New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
    }
    Remove-Item -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue
    <#
        foreach ($item in (Get-ChildItem "$env:WinDir\WinSxS\*onedrive*")) {
            Takeown-Folder $item.FullName
            Remove-Item -Recurse -Force $item.FullName
        }
    #>  
    <# This wont work without any special premission. In fact, there is take ownership plugin installed but i don't reccomend
    #  deleting OneDrive stuff. It might break your installation of Windows


        If ((Get-ChildItem "$env:userprofile\OneDrive" -Recurse | Measure-Object).Count -eq 0) {
            Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:userprofile\OneDrive"
        }
    #>
    Write-Host "Disabled OneDrive"
})

$darkmode.Add_Click({
    Write-Host "Enabling Dark Mode"
    if (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes")){
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" -Name "AppsUseLightTheme" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" -Name "SystemUsesLightTheme" -Type DWord -Value 0
    if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes")){
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" -Force | Out-Null
    }
    if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize")){
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Type DWord -Value 0
    reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /f
    reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /f
    reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t "REG_DWORD" /d "0" /f
    reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "SystemUsesLightTheme" /t "REG_DWORD" /d "0" /f
    Stop-Process -Name "explorer" -Force -PassThru -ErrorAction SilentlyContinue
    Write-Host "Enabled Dark Mode"
})

$lightmode.Add_Click({
    Write-Host "Switching Back to Light Mode"
    if (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes")){
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" -Name "AppsUseLightTheme" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" -Name "SystemUsesLightTheme" -Type DWord -Value 1
    if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes")){
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" -Force | Out-Null
    }
    if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize")){
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Type DWord -Value 1
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Type DWord -Value 1
    reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /f
    reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /f
    reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t "REG_DWORD" /d "1" /f
    reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "SystemUsesLightTheme" /t "REG_DWORD" /d "1" /f
    Stop-Process -Name "explorer" -Force -PassThru -ErrorAction SilentlyContinue
    Write-Host "Switched Back to Light Mode"
})

$disablewindowsupdate.Add_Click({
    Get-Service -Name "wuauserv" | Set-Service -StartupType Disabled -ErrorAction SilentlyContinue
    Get-Service -Name "WaaSMedicSvc" | Set-Service -StartupType Disabled -ErrorAction SilentlyContinue
    Get-Service -Name "UsoSvc" | Set-Service -StartupType Disabled -ErrorAction SilentlyContinue
    Stop-Service -Name "wuauserv" -PassThru -ErrorAction SilentlyContinue
    Stop-Service -Name "WaaSMedicSvc" -PassThru -ErrorAction SilentlyContinue
    Stop-Service -Name "UsoSvc" -PassThru -ErrorAction SilentlyContinue
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\WindowsUpdate\Scheduled Start" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\WaaSMedic\PerformRemediation" | Out-Null
    <#
     Those tasks require extra premissions
     Run this script with NSudo to disable those services!
        Disable-ScheduledTask -TaskName "\Microsoft\Windows\UpdateOrchestrator\Report policies" | Out-Null
        Disable-ScheduledTask -TaskName "\Microsoft\Windows\UpdateOrchestrator\Schedule Scan" | Out-Null
        Disable-ScheduledTask -TaskName "\Microsoft\Windows\UpdateOrchestrator\Schedule Scan Static Task" | Out-Null
        Disable-ScheduledTask -TaskName "\Microsoft\Windows\UpdateOrchestrator\UpdateModelTask" | Out-Null
        Disable-ScheduledTask -TaskName "\Microsoft\Windows\UpdateOrchestrator\USO_UxBroker" | Out-Null
    #>
    if (!(Test-Path "HKLM:\Software\Microsoft\WindowsUpdate\UX\Settings")){
        New-Item -Path "HKLM:\Software\Microsoft\WindowsUpdate\UX\Settings" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\WindowsUpdate\UX\Settings" -Name "UxOption" -Type DWord -Value 1
    
    Stop-Process -Name "MoUsoCoreWorker" -Force -PassThru -ErrorAction SilentlyContinue | Out-Null
    Stop-Process -Name "TiWorker" -Force -PassThru -ErrorAction SilentlyContinue | Out-Null

    write-Host "Windows Update has been disabled!"
})

$enablewindowsupdate.Add_Click({
    Get-Service -Name "wuauserv" | Set-Service -StartupType Manual -ErrorAction SilentlyContinue
    Get-Service -Name "WaaSMedicSvc" | Set-Service -StartupType Manual -ErrorAction SilentlyContinue
    Get-Service -Name "UsoSvc" | Set-Service -StartupType Manual -ErrorAction SilentlyContinue
    Start-Service -Name "wuauserv" -PassThru -ErrorAction SilentlyContinue
    Start-Service -Name "WaaSMedicSvc" -PassThru -ErrorAction SilentlyContinue
    Start-Service -Name "UsoSvc" -PassThru -ErrorAction SilentlyContinue
    Enable-ScheduledTask -TaskName "\Microsoft\Windows\WindowsUpdate\Scheduled Start" | Out-Null
    Enable-ScheduledTask -TaskName "\Microsoft\Windows\WaaSMedic\PerformRemediation" | Out-Null

    <#
     Those tasks require extra premissions
     Run this script with NSudo to disable those services!
        Enable-ScheduledTask -TaskName "\Microsoft\Windows\UpdateOrchestrator\Report policies" | Out-Null
        Enable-ScheduledTask -TaskName "\Microsoft\Windows\UpdateOrchestrator\Schedule Scan" | Out-Null
        Enable-ScheduledTask -TaskName "\Microsoft\Windows\UpdateOrchestrator\Schedule Scan Static Task" | Out-Null
        Enable-ScheduledTask -TaskName "\Microsoft\Windows\UpdateOrchestrator\UpdateModelTask" | Out-Null
        Enable-ScheduledTask -TaskName "\Microsoft\Windows\UpdateOrchestrator\USO_UxBroker" | Out-Null
    #>

    if (!(Test-Path "HKLM:\Software\Microsoft\WindowsUpdate\UX\Settings")){
        New-Item -Path "HKLM:\Software\Microsoft\WindowsUpdate\UX\Settings" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\WindowsUpdate\UX\Settings" -Name "UxOption" -Type DWord -Value 0

    write-Host "Windows Update has been enabled!"
})

$smalltaskbaricons.Add_Click({
  
    if (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")){
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons" -Type DWord -Value 1
    Stop-Process -Name "explorer" -Force -PassThru -ErrorAction SilentlyContinue
    write-Host "You should have small taskbar icons now!"

})

$RemoveTakeOwnership.Add_Click({

    # Update 1 : Remove 'Windows Cleaner' code from here!

    if(Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\*\shell\TakeOwnership"){
        Clear-Host
        write-Host "This might take some time to remove! Please wait..."
        if(Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\*\shell\TakeOwnership"){
        Remove-Item -Path "Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\*\shell\TakeOwnership" -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
        }
        if(Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\Directory\shell\TakeOwnership"){
        Remove-Item -Path "Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Directory\shell\TakeOwnership" -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
        }
        write-Host "'Take Ownership' context menu is gone!"
    } else {
        Clear-Host 
        Write-Host "Can't find `"Take Ownership`" registry keys. It might be already removed?" -ForegroundColor Yellow -BackgroundColor Black
    }
})

$RemoveBloat.Add_Click({

    # Update 1 : Removed Holographic registry keys from here! Kinda useless.

        $BloatwareList = @(
        "Microsoft.3DBuilder"
        "Microsoft.Microsoft3DViewer"
        "Microsoft.AppConnector"
        "Microsoft.BingFinance"
        "Microsoft.BingNews"
        "Microsoft.BingSports"
        "Microsoft.BingTranslator"
        "Microsoft.BingWeather"
        "Microsoft.BingFoodAndDrink"
        "Microsoft.BingHealthAndFitness"
        "Microsoft.BingTravel"
        "Microsoft.MinecraftUWP"
        "Microsoft.GamingServices"
        "Microsoft.GetHelp"
        "Microsoft.Getstarted"
        "Microsoft.Messaging"
        "Microsoft.Microsoft3DViewer"
        "Microsoft.MicrosoftSolitaireCollection"
        "Microsoft.NetworkSpeedTest"
        "Microsoft.News"
        "Microsoft.Office.Lens"
        "Microsoft.Office.Sway"
        "Microsoft.Office.OneNote"
        "Microsoft.OneConnect"
        "Microsoft.People"
        "Microsoft.Print3D"
        "Microsoft.SkypeApp"
        "Microsoft.Wallet"
        "Microsoft.Whiteboard"
        "Microsoft.WindowsAlarms"
        "microsoft.windowscommunicationsapps"
        "Microsoft.WindowsFeedbackHub"
        "Microsoft.WindowsMaps"
        "Microsoft.WindowsPhone"
        "Microsoft.WindowsSoundRecorder"
        "Microsoft.XboxApp"
        "Microsoft.ConnectivityStore"
        "Microsoft.CommsPhone"
        # Might be needed for screenshot tool
        #"Microsoft.ScreenSketch"
        "Microsoft.Xbox.TCUI"
        "Microsoft.XboxGameOverlay"
        "Microsoft.XboxGameCallableUI"
        "Microsoft.XboxSpeechToTextOverlay"
        "Microsoft.MixedReality.Portal"
        "Microsoft.XboxIdentityProvider"
        "Microsoft.ZuneMusic"
        "Microsoft.ZuneVideo"
        "Microsoft.YourPhone"
        "Microsoft.Getstarted"
        "Microsoft.MicrosoftOfficeHub"
        "*EclipseManager*"
        "*ActiproSoftwareLLC*"
        "*AdobeSystemsIncorporated.AdobePhotoshopExpress*"
        "*Duolingo-LearnLanguagesforFree*"
        "*PandoraMediaInc*"
        "*CandyCrush*"
        "*BubbleWitch3Saga*"
        "*Wunderlist*"
        "*Flipboard*"
        "*Twitter*"
        "*Facebook*"
        "*Royal Revolt*"
        "*Sway*"
        "*Speed Test*"
        "*Dolby*"
        "*Viber*"
        "*ACGMediaPlayer*"
        "*Netflix*"
        "*OneCalendar*"
        "*LinkedInforWindows*"
        "*HiddenCityMysteryofShadows*"
        "*Hulu*"
        "*HiddenCity*"
        "*AdobePhotoshopExpress*"
        "*Microsoft.Advertising.Xaml*"
        "*Microsoft.MSPaint*"
        "*Microsoft.MicrosoftStickyNotes*"
        "*Microsoft.Windows.Photos*"
        # Update 1 : Commneted out Calculator because some people might need it!
        #"*Microsoft.WindowsCalculator*"ˇ
        # Commented out Windows Store because some people might want to use it
        #"*Microsoft.WindowsStore*"
        )

        foreach ($Bloat in $BloatwareList) {
            Get-AppxPackage -Name $Bloat| Remove-AppxPackage
            Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $Bloat | Remove-AppxProvisionedPackage -Online
            write-Host "Trying to remove $Bloat"
        }

        if(!(Test-Path "HKCR:\")){
            New-PSDrive -PSProvider registry -Root HKEY_CLASSES_ROOT -Name HKCR | Out-Null
        }
        $Keys = @(
            "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
            "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
            "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
            "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
            "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
            "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
            "HKCR:\Extensions\ContractId\Windows.File\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
            "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
            "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
            "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
            "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
            "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
            "HKCR:\Extensions\ContractId\Windows.PreInstalledConfigTask\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
            "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
            "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
            "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
            "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
            "HKCR:\Extensions\ContractId\Windows.ShareTarget\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
        )
        
        #This writes the output of each key it is removing and also removes the keys listed above.
        ForEach ($Key in $Keys) {
            Write-Output "Removing `"$Key`" from registry"
            Remove-Item $Key -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
        }

        write-Host "Bloatware uninstalled!"
 
# Update 1 : Removed ability to permanently remove bloatware applications! Working on it to improve it!
# You can still use it, you just need to commnet out this part and import modules part!

<#

        function removePermanently{
            $AppsFolder = "$env:ProgramFiles\WindowsApps";
            TakeOwnership -Path $AppsFolder
            if (Test-Path $AppsFolder){
                Remove-Item -Path $AppsFolder -Force -Recurse | Out-Null
            }
        }
        $Answer = read-Host "Do you want to permanently remove Bloatware applications?
This will remove `"$AppsFolder`" folder! Press Enter key to skip!
Answer (Y/N):"
        Switch($Answer){
            'y'{ removePermanently };
            'n'{ write-Host "This step will be skipped!"};
        }
#>

})
<#
$AdminAccount.Add_CheckStateChanged({

    $Chk = $AdminAccount
    if ($AdminAccount.Checked){
        write-Host "Administrator account is enabled!"
        Get-LocalUser -Name "Administrator" | Enable-LocalUser
    } else {
        write-Host "Administrator account is disabled!"
        Get-LocalUser -Name "Administrator" | Disable-LocalUser
    }

})
#>
$UninstallEdge.Add_Click({

    #C:\Program Files (x86)\Microsoft\Edge\Application\84.0.522.63\Installer
    #.\setup.exe --uninstall --system-level --verbose-logging --force-uninstall

    # Update 1 : removed $microsoftpath because it wasn't used!
    # $microsoftpath = "C:\Program Files (x86)\Microsoft"


    #Fixed alot of errors and paths... Should uninstall now without any errors

    $edgepath = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\*.*.*.*\Installer";
    $EdgeUninstallArgs = "--uninstall --system-level --verbose-logging --force-uninstall"

    if(Test-Path "C:\Program Files (x86)\Microsoft\Edge\Application"){

        Write-Host "Uninstalling `"Microsoft Edge`"..." -ForegroundColor Red -BackgroundColor Black
        Start-Process -FilePath "$edgepath\setup.exe" -ArgumentList "$EdgeUninstallArgs" -Verb RunAs -Wait

        #Disable Edge's scheduled tasks
        Disable-ScheduledTask -TaskName "\MicrosoftEdgeUpdateTaskMachineUA" | Out-Null
        Disable-ScheduledTask -TaskName "\MicrosoftEdgeUpdateTaskMachineCore" | Out-Null
        $_edgeservices = "edgeupdatem","edgeupdate","MicrosoftEdgeElevationService"
        foreach($edge in $_edgeservices){
            Get-Service $edge | Set-Service -StartupType Disabled -PassThru -ErrorAction SilentlyContinue | Out-Null
        }
        write-Host "Clearing `"Microsoft Edge`" regristry keys..." -ForegroundColor Yellow -BackgroundColor Black
        if(!(Test-Path "HKLM:\SOFTWARE\Microsoft")){
            New-Item -Path "HKLM:\SOFTWARE\Microsoft" -Force | Out-Null
        }
        #Disables automatic edge update
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft" -Name "DoNotUpdateToEdgeWithChromium" -Type DWord -Value 1
        if(Test-Path "HKCU:\SOFTWARE\Microsoft\Edge"){
            Remove-Item -Path "HKCU:\SOFTWARE\Microsoft\Edge" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
        }
        if(Test-Path "HKCU:\SOFTWARE\Microsoft\EdgeUpdate"){
            Remove-Item -Path "HKCU:\SOFTWARE\Microsoft\EdgeUpdate" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
        }
        if(Test-Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Edge"){
            Remove-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Edge" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
        }
        if(Test-Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate"){
            Remove-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
        }
        if(!(Test-Path "HKCR:\")){
            New-PSDrive -PSProvider registry -Root HKEY_CLASSES_ROOT -Name HKCR | Out-Null
        }
        Remove-Item -Path "Microsoft.PowerShell.Core\Registry::HKEY_CLASSES_ROOT\*MicrosoftEdge*" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
        Remove-Item -Path "Microsoft.PowerShell.Core\Registry::HKEY_CLASSES_ROOT\*microsoft-edge*" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
        Remove-Item -Path "Microsoft.PowerShell.Core\Registry::HKEY_CLASSES_ROOT\*edge*" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null

        write-Host "Removing all 'Microsoft Edge' files!"

        #Fixed some errors 
        if(Test-Path 'C:\Program Files (x86)\Microsoft\Edge'){
            $edgechilditems = Get-ChildItem -Path 'C:\Program Files (x86)\Microsoft\Edge' -ErrorAction SilentlyContinue
            if($edgechilditems.Count -ge 1) {
                foreach($item in $edgechilditems){
                    Remove-Item -Path $item.fullname -Force -ErrorAction SilentlyContinue | Out-Null
                }
            }
        }

        if(Test-Path 'C:\Program Files (x86)\Microsoft\EdgeUpdate'){
            $edgeupdatechilditems = Get-ChildItem -Path 'C:\Program Files (x86)\Microsoft\EdgeUpdate' -ErrorAction SilentlyContinue
            if($edgeupdatechilditems.Count -ge 1){
                foreach($updateitem in $edgeupdatechilditems){
                    Remove-Item -Path $updateitem.fullname -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
                }
            }
        }
        
        if(Test-Path 'C:\Program Files (x86)\Microsoft\Temp'){
            $edgetempchilditems = Get-ChildItem -Path 'C:\Program Files (x86)\Microsoft\Temp' -ErrorAction SilentlyContinue
            if($edgetempchilditems.Count -ge 1){
                foreach($temp in $edgetempchilditems){
                    Remove-Item -Path $temp.fullname -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
                }
            }
        }
        
        #Remove Edge Services
        if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\edgeupdate"){
            Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\edgeupdate" -Force -ErrorAction SilentlyContinue | Out-Null
        }
        if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\edgeupdatem"){
            Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\edgeupdatem" -Force -ErrorAction SilentlyContinue | Out-Null
        }
        
        write-Host "'Microsoft Edge' is now removed!" -ForegroundColor Green -BackgroundColor Black

} else {

    Clear-Host;
    write-Host "`"Microsoft Edge`" is not installed!" -ForegroundColor Red -BackgroundColor Black

}

})

$TakeOwnership.Add_Click({

    # Update 1 : Made 'Take Ownership' code part better! Also removed alot of useless parts of the code

    if(!(Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\*\shell\TakeOwnership")){
        write-Host "Adding 'Take Ownership' to context menu!"
        if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\*\shell\TakeOwnership") -ne $true){
        New-Item "HKLM:\SOFTWARE\Classes\*\shell\TakeOwnership" -force -ea SilentlyContinue
        }
        if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\*\shell\TakeOwnership\command") -ne $true){
        New-Item "HKLM:\SOFTWARE\Classes\*\shell\TakeOwnership\command" -force -ea SilentlyContinue
        }
        if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\Directory\shell\TakeOwnership") -ne $true){
        New-Item "HKLM:\SOFTWARE\Classes\Directory\shell\TakeOwnership" -force -ea SilentlyContinue
        }
        if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\Directory\shell\TakeOwnership\command") -ne $true){
        New-Item "HKLM:\SOFTWARE\Classes\Directory\shell\TakeOwnership\command" -force -ea SilentlyContinue
        }
        New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\*\shell\TakeOwnership' -Name '(default)' -Value 'Take Ownership' -PropertyType String -Force -ea SilentlyContinue;
        New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\*\shell\TakeOwnership' -Name 'HasLUAShield' -Value '' -PropertyType String -Force -ea SilentlyContinue;
        New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\*\shell\TakeOwnership' -Name 'NoWorkingDirectory' -Value '' -PropertyType String -Force -ea SilentlyContinue;
        New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\*\shell\TakeOwnership' -Name 'Position' -Value 'middle' -PropertyType String -Force -ea SilentlyContinue;
        New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\*\shell\TakeOwnership\command' -Name '(default)' -Value 'powershell -windowstyle hidden -command "Start-Process cmd -ArgumentList ''/c takeown /f \"%1\" && icacls \"%1\" /grant *S-1-3-4:F /c /l'' -Verb runAs' -PropertyType String -Force -ea SilentlyContinue;
        New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\*\shell\TakeOwnership\command' -Name 'IsolatedCommand' -Value 'powershell -windowstyle hidden -command "Start-Process cmd -ArgumentList ''/c takeown /f \"%1\" && icacls \"%1\" /grant *S-1-3-4:F /c /l'' -Verb runAs' -PropertyType String -Force -ea SilentlyContinue;
        New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\TakeOwnership' -Name '(default)' -Value 'Take Ownership' -PropertyType String -Force -ea SilentlyContinue;
        New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\TakeOwnership' -Name 'AppliesTo' -Value 'NOT (System.ItemPathDisplay:="C:\Users" OR System.ItemPathDisplay:="C:\ProgramData" OR System.ItemPathDisplay:="C:\Windows" OR System.ItemPathDisplay:="C:\Windows\System32" OR System.ItemPathDisplay:="C:\Program Files" OR System.ItemPathDisplay:="C:\Program Files (x86)")' -PropertyType String -Force -ea SilentlyContinue;
        New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\TakeOwnership' -Name 'HasLUAShield' -Value '' -PropertyType String -Force -ea SilentlyContinue;
        New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\TakeOwnership' -Name 'NoWorkingDirectory' -Value '' -PropertyType String -Force -ea SilentlyContinue;
        New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\TakeOwnership' -Name 'Position' -Value 'middle' -PropertyType String -Force -ea SilentlyContinue;
        New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\TakeOwnership\command' -Name '(default)' -Value 'powershell -windowstyle hidden -command "Start-Process cmd -ArgumentList ''/c takeown /f \"%1\" /r /d y && icacls \"%1\" /grant *S-1-3-4:F /c /l /q'' -Verb runAs' -PropertyType String -Force -ea SilentlyContinue;
        New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\TakeOwnership\command' -Name 'IsolatedCommand' -Value 'powershell -windowstyle hidden -command "Start-Process cmd -ArgumentList ''/c takeown /f \"%1\" /r /d y && icacls \"%1\" /grant *S-1-3-4:F /c /l /q'' -Verb runAs' -PropertyType String -Force -ea SilentlyContinue;
        write-Host "'Take Ownership' is added into context menu!"
    } else {
        Clear-Host 
        Write-Host "You already have `"Take Onwership`" added into your context menu!" -ForegroundColor Yellow -BackgroundColor Black
    }

})

# Update 1 : Added button so you can edit this script

$EditScript.Add_Click({
    $DebloaterFile = $PSCommandPath;
    Start-Process -FilePath "powershell_ise.exe" -ArgumentList "`"$DebloaterFile`"";
})
<#
$LegacyVolume.Add_CheckStateChanged({

    if ($LegacyVolume.Checked -eq $True){
        if (!(Test-Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\MTCUVC")){
            New-Item -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\MTCUVC" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\MTCUVC" -Name "EnableMtcUvc" -Type DWord -Value 0
        write-Host "Legacy Volume control enabled!"
        return;
    }
    if (!(Test-Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\MTCUVC")){
        New-Item -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\MTCUVC" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\MTCUVC" -Name "EnableMtcUvc" -Type DWord -Value 1
    write-Host "Legacy Volume Control disabled!"
})

$LegacyNotifications.Add_CheckStateChanged({
    if ($LegacyNotifications.Checked -eq $True){
        if (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer")){
            New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "EnableLegacyBalloonNotifications" -Type DWord -Value 1 
        Write-Host "Legacy Notifications have been enabled!"
        return;
    }
    if (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer")){
        New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "EnableLegacyBalloonNotifications" -Type DWord -Value 0 
    Write-Host "Legacy Notifications has been disabled"
})
#>
[void]$Form.ShowDialog()
