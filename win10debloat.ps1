Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()

$ErrorActionPreference = 'SilentlyContinue'
$wshell = New-Object -ComObject Wscript.Shell
$Button = [System.Windows.MessageBoxButton]::YesNoCancel
$ErrorIco = [System.Windows.MessageBoxImage]::Error
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
	Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
	Exit
}

$Form                            = New-Object system.Windows.Forms.Form
$Form.ClientSize                 = New-Object System.Drawing.Point(1050,700)
$Form.text                       = "Windows 10 Debloater"
$Form.StartPosition              = "CenterScreen"
$Form.TopMost                    = $false
$Form.BackColor                  = [System.Drawing.ColorTranslator]::FromHtml("#b8b8b8")
$Form.AutoScaleDimensions        = '192, 192'
$Form.AutoSize                   = $False
$Form.ClientSize                 = '575, 400'
$Form.FormBorderStyle            = 'Sizable'

#$Panel1                          = New-Object system.Windows.Forms.Panel
#$Panel1.height                   = 639
#$Panel1.width                    = 219
#$Panel1.location                 = New-Object System.Drawing.Point(600,54)

$Panel2                          = New-Object system.Windows.Forms.Panel
$Panel2.height                   = 386
$Panel2.width                    = 211
$Panel2.location                 = New-Object System.Drawing.Point(30,54)

$Label3                          = New-Object system.Windows.Forms.Label
$Label3.text                     = "System Tweaks"
$Label3.AutoSize                 = $true
$Label3.width                    = 230
$Label3.height                   = 25
$Label3.location                 = New-Object System.Drawing.Point(30,12)
$Label3.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',24)

$essentialtweaks                 = New-Object system.Windows.Forms.Button
$essentialtweaks.text            = "Essential Tweaks"
$essentialtweaks.width           = 204
$essentialtweaks.height          = 75
$essentialtweaks.location        = New-Object System.Drawing.Point(4,25)
$essentialtweaks.Font            = New-Object System.Drawing.Font('Microsoft Sans Serif',14)

$backgroundapps                  = New-Object system.Windows.Forms.Button
$backgroundapps.text             = "Disable Background Apps"
$backgroundapps.width            = 205
$backgroundapps.height           = 30
$backgroundapps.location         = New-Object System.Drawing.Point(3,139)
$backgroundapps.Font             = New-Object System.Drawing.Font('Microsoft Sans Serif',12)

$cortana                         = New-Object system.Windows.Forms.Button
$cortana.text                    = "Disable Cortana (Search)"
$cortana.width                   = 204
$cortana.height                  = 30
$cortana.location                = New-Object System.Drawing.Point(4,174)
$cortana.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',12)

$actioncenter                    = New-Object system.Windows.Forms.Button
$actioncenter.text               = "Disable Action Center"
$actioncenter.width              = 203
$actioncenter.height             = 30
$actioncenter.location           = New-Object System.Drawing.Point(4,105)
$actioncenter.Font               = New-Object System.Drawing.Font('Microsoft Sans Serif',12)

$darkmode                        = New-Object system.Windows.Forms.Button
$darkmode.text                   = "Dark Mode"
$darkmode.width                  = 204
$darkmode.height                 = 30
$darkmode.location               = New-Object System.Drawing.Point(4,244)
$darkmode.Font                   = New-Object System.Drawing.Font('Microsoft Sans Serif',12)

$visualfx                        = New-Object system.Windows.Forms.Button
$visualfx.text                   = "Basic Visual FX"
$visualfx.width                  = 204
$visualfx.height                 = 30
$visualfx.location               = New-Object System.Drawing.Point(4,313)
$visualfx.Font                   = New-Object System.Drawing.Font('Microsoft Sans Serif',12)

$onedrive                        = New-Object system.Windows.Forms.Button
$onedrive.text                   = "Uninstall OneDrive"
$onedrive.width                  = 204
$onedrive.height                 = 30
$onedrive.location               = New-Object System.Drawing.Point(4,209)
$onedrive.Font                   = New-Object System.Drawing.Font('Microsoft Sans Serif',12)

$Label15                         = New-Object system.Windows.Forms.Label
$Label15.text                    = "Windows Update"
$Label15.AutoSize                = $true
$Label15.width                   = 25
$Label15.height                  = 10
$Label15.location                = New-Object System.Drawing.Point(290,11)
$Label15.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',24)

$Panel4                          = New-Object system.Windows.Forms.Panel
$Panel4.height                   = 179
$Panel4.width                    = 340
$Panel4.location                 = New-Object System.Drawing.Point(290,55)

$disablewindowsupdate            = New-Object system.Windows.Forms.Button
$disablewindowsupdate.text       = "Disable Windows Update"
$disablewindowsupdate.width      = 250
$disablewindowsupdate.height     = 30
$disablewindowsupdate.location   = New-Object System.Drawing.Point(5,26)
$disablewindowsupdate.Font       = New-Object System.Drawing.Font('Microsoft Sans Serif',14)

$enablewindowsupdate             = New-Object system.Windows.Forms.Button
$enablewindowsupdate.text        = "Enable Windows Update"
$enablewindowsupdate.width       = 250
$enablewindowsupdate.height      = 30
$enablewindowsupdate.location    = New-Object System.Drawing.Point(5,66)
$enablewindowsupdate.Font        = New-Object System.Drawing.Font('Microsoft Sans Serif',14)

$smalltaskbaricons               = New-Object system.Windows.Forms.Button
$smalltaskbaricons.text          = "Use Small Taskbar"
$smalltaskbaricons.width         = 250
$smalltaskbaricons.height        = 30
$smalltaskbaricons.location      = New-Object System.Drawing.Point(5,106)
$smalltaskbaricons.Font          = New-Object System.Drawing.Font('Microsoft Sans Serif',12)

$lightmode                       = New-Object system.Windows.Forms.Button
$lightmode.text                  = "Light Mode"
$lightmode.width                 = 204
$lightmode.height                = 30
$lightmode.location              = New-Object System.Drawing.Point(4,279)
$lightmode.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',12)

$Panel3                          = New-Object system.Windows.Forms.Panel
$Panel3.height                   = 387
$Panel3.width                    = 220
$Panel3.location                 = New-Object System.Drawing.Point(464,54)

$Form.controls.AddRange(@($Panel1,$Panel2,$Label3,$Label15,$Panel4,$PictureBox1,$Label1,$Label4,$Panel3))
$Panel2.controls.AddRange(@($essentialtweaks,$backgroundapps,$cortana,$actioncenter,$darkmode,$visualfx,$onedrive,$lightmode))
$Panel4.controls.AddRange(@($disablewindowsupdate,$enablewindowsupdate,$smalltaskbaricons,$Label16,$Label17,$Label18,$Label19))

$essentialtweaks.Add_Click({
    #No restore points! :)

    #Write-Host "Creating Restore Point incase something bad happens"
    #Enable-ComputerRestore -Drive "C:\"
    #Checkpoint-Computer -Description "RestorePoint1" -RestorePointType "MODIFY_SETTINGS"

    Write-Host "Running O&O Shutup with Recommended Settings"
    Import-Module BitsTransfer
    Start-BitsTransfer -Source "https://raw.githubusercontent.com/teeotsa/win10script/master/ooshutup10.cfg" -Destination ooshutup10.cfg
    Start-BitsTransfer -Source "https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe" -Destination OOSU10.exe
    ./OOSU10.exe ooshutup10.cfg /quiet

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
    Write-Host "Restricting Windows Update P2P only to local network..."
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type DWord -Value 1
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

	# Network Tweaks
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "IRPStackSize" -Type DWord -Value 20

	# SVCHost Tweak
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "SvcHostSplitThresholdInKB" -Type DWord -Value 4194304

    Write-Host "Disable News and Interests"
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Name "EnableFeeds" -Type DWord -Value 0

    Write-Host "Disabling some services and scheduled tasks"

    #   Set-Service -StartupType Disabled ""
    #   Stop-Service -Force -Name ""

    #All XBox Services
    Stop-Service -Force -Name "XboxNetApiSvc"
    Set-Service -StartupType Disabled "XboxNetApiSvc"
    Set-Service -StartupType Disabled "XblGameSave"
    Stop-Service -Force -Name "XblGameSave"
    Set-Service -StartupType Disabled "XblAuthManager"
    Stop-Service -Force -Name "XblAuthManager"
    Set-Service -StartupType Disabled "XboxGipSvc"
    Stop-Service -Force -Name "XboxGipSvc"

    #Other Services 
    #LanmanWorkstation
    #WlanSvc
    #W32Time

    #Disable Workstation Service
    Set-Service -StartupType Disabled "LanmanWorkstation"
    Stop-Service -Force -Name "LanmanWorkstation"

    #Disable Work Folders Service
    Set-Service -StartupType Disabled "workfolderssvc"
    Stop-Service -Force -Name "workfolderssvc"

    #Disable WLAN AutoConfig Service
    Set-Service -StartupType Disabled "WlanSvc"
    Stop-Service -Force -Name "WlanSvc"

    #Disable Windows Time Service
    Set-Service -StartupType Disabled "W32Time"
    Stop-Service -Force -Name "W32Time"

    #Disable Windows Push Notifications System Service
    Set-Service -StartupType Disabled "WpnService"
    Stop-Service -Force -Name "WpnService"

    #Disable Windows Mobile Hotspot Service
    Set-Service -StartupType Disabled "icssvc"
    Stop-Service -Force -Name "icssvc"

    #Disable Windows Mixed Reality OpenXR Service
    Set-Service -StartupType Disabled "MixedRealityOpenXRSvc"
    Stop-Service -Force -Name "MixedRealityOpenXRSvc"

    #Disable Windows Media Player Network Sharing Service
    Set-Service -StartupType Disabled "WMPNetworkSvc"
    Stop-Service -Force -Name "WMPNetworkSvc"

    #Disable Windows License Manager Service
    #Might f*ck up Activation!
    Set-Service -StartupType Disabled "LicenseManager"
    Stop-Service -Force -Name "LicenseManager"

    #Disable Windows Insider Service
    Set-Service -StartupType Disabled "wisvc"
    Stop-Service -Force -Name "wisvc"

    #Disable Windows Event Collector Service
    Set-Service -StartupType Disabled "Wecsvc"
    Stop-Service -Force -Name "Wecsvc"

    #Disable Windows Error Reporting Service
    Set-Service -StartupType Disabled "WerSvc"
    Stop-Service -Force -Name "WerSvc"

    #Disable Windows Defender Firewall Service
    #Wont work without NSudo
    #Run 'disablewindowsdefender.ps1' to disable
    #   Set-Service -StartupType Disabled "mpssvc"
    #   Stop-Service -Force -Name "mpssvc"

    #Disable Windows Defender Advanced Threat Protection Service
    #Wont work without NSudo
    #Run 'disablewindowsdefender.ps1' to disable
    #   Set-Service -StartupType Disabled "Sense"
    #   Stop-Service -Force -Name "Sense"

    #Disable Windows Camera Frame Server Service
    Set-Service -StartupType Disabled "FrameServer"
    Stop-Service -Force -Name "FrameServer"

    #Disable Windows Biometric Service
    Set-Service -StartupType Disabled "WbioSrvc"
    Stop-Service -Force -Name "WbioSrvc"

    #Disable Windows Backup Service
    Set-Service -StartupType Disabled "SDRSVC"
    Stop-Service -Force -Name "SDRSVC"

    #Disable Wi-Fi Direct Services Connection Manager Service
    Set-Service -StartupType Disabled "WFDSConMgrSvc"
    Stop-Service -Force -Name "WFDSConMgrSvc"

    #Disable WebClient Service
    Set-Service -StartupType Disabled "WebClient"
    Stop-Service -Force -Name "WebClient"

    #Disable Web Account Manager Service
    Set-Service -StartupType Disabled "TokenBroker"
    Stop-Service -Force -Name "TokenBroker"

    #Disable WalletService
    Set-Service -StartupType Disabled "WalletService"
    Stop-Service -Force -Name "WalletService"

    #Disable Volume Shadow Copy Service
    Set-Service -StartupType Disabled "VSS"
    Stop-Service -Force -Name "VSS"

    #Disable Virtual Disk Service
    Set-Service -StartupType Disabled "vds"
    Stop-Service -Force -Name "vds"

    #Disable Touch Keyboard and Handwriting Panel Service
    #You can't stop this service, but for some reason you can disable it?!?!
    Set-Service -StartupType Disabled "TabletInputService"
    #   Stop-Service -Force -Name "TabletInputService"

    #Disable Storage Service
    Set-Service -StartupType Disabled "StorSvc"
    Stop-Service -Force -Name "StorSvc"

    #Disable Spatial Data Service
    Set-Service -StartupType Disabled "SharedRealitySvc"
    Stop-Service -Force -Name "SharedRealitySvc"

    #Disable Software Protection Service
    Set-Service -StartupType Disabled "sppsvc"
    Stop-Service -Force -Name "sppsvc"

    #Disable Smart Card Removal Policy Service
    Set-Service -StartupType Disabled "SCPolicySvc"
    Stop-Service -Force -Name "SCPolicySvc"

    #Disable Smart Card Device Enumeration Service
    Set-Service -StartupType Disabled "ScDeviceEnum"
    Stop-Service -Force -Name "ScDeviceEnum"

    #Disable Smart Card Service
    Set-Service -StartupType Disabled "SCardSvr"
    Stop-Service -Force -Name "SCardSvr"

    #Disable Server Service
    Set-Service -StartupType Disabled "LanmanServer"
    Stop-Service -Force -Name "LanmanServer"

    #Disable Sensor Service
    Set-Service -StartupType Disabled "SensorService"
    Stop-Service -Force -Name "SensorService"

    #Disable Sensor Monitoring Service
    Set-Service -StartupType Disabled "SensrSvc"
    Stop-Service -Force -Name "SensrSvc"

    #Disable Sensor Data Service
    Set-Service -StartupType Disabled "SensorDataService"
    Stop-Service -Force -Name "SensorDataService"

    #Disable Security Center Service
    Set-Service -StartupType Disabled "wscsvc"
    Stop-Service -Force -Name "wscsvc"

    #Disable Secondary Logon Service
    Set-Service -StartupType Disabled "seclogon"
    Stop-Service -Force -Name "seclogon"

    #Disable Retail Demo Service
    Set-Service -StartupType Disabled "RetailDemo"
    Stop-Service -Force -Name "RetailDemo"

    #Disable Remote Registry Service
    Set-Service -StartupType Disabled "RemoteRegistry"
    Stop-Service -Force -Name "RemoteRegistry"

    #Disable Remote Access Connection Manager Service
    Set-Service -StartupType Disabled "RasMan"
    Stop-Service -Force -Name "RasMan"

    #Disable Recommended Troubleshooting Service 
    Set-Service -StartupType Disabled "TroubleshootingSvc"
    Stop-Service -Force -Name "TroubleshootingSvc"

    #Disable Remote Desktop Configuration Service
    Set-Service -StartupType Disabled "SessionEnv"
    Stop-Service -Force -Name "SessionEnv"

    #Disable Remote Desktop Service
    Set-Service -StartupType Disabled "TermService"
    Stop-Service -Force -Name "TermService"

    #Disable Radio Management Service
    Set-Service -StartupType Disabled "RmSvc"
    Stop-Service -Force -Name "RmSvc"

    #Disable Quality Windows Audio Video Experience Service
    Set-Service -StartupType Disabled "QWAVE"
    Stop-Service -Force -Name "QWAVE"
    
    #Disable Program Compatibility Assistant Service
    #Comment this out if you want to use program compatibility settings!
    Set-Service -StartupType Disabled "PcaSvc"
    Stop-Service -Force -Name "PcaSvc"

    #Disable Problem Reports Control Panel Support Service
    Set-Service -StartupType Disabled "wercplsupport"
    Stop-Service -Force -Name "wercplsupport"

    #Disable Printer Extensions and Notifications Service
    Set-Service -StartupType Disabled "PrintNotify"
    Stop-Service -Force -Name "PrintNotify"

    #Disable Print Spooler Service
    Set-Service -StartupType Disabled "Spooler"
    Stop-Service -Force -Name "Spooler"

    #Disable Phone Service 
    Set-Service -StartupType Disabled "PhoneSvc"
    Stop-Service -Force -Name "PhoneSvc"

    #Disable Parental Controls Service
    Set-Service -StartupType Disabled "WpcMonSvc"
    Stop-Service -Force -Name "WpcMonSvc"

    #Disable Payments and NFC/SE Manager Service
    Set-Service -StartupType Disabled "SEMgrSvc"
    Stop-Service -Force -Name "SEMgrSvc"

    #Disable Optimize drives Service
    Set-Service -StartupType Disabled "defragsvc"
    Stop-Service -Force -Name "defragsvc"

    #Disable Offline Files Service
    Set-Service -StartupType Disabled "CscService"
    Stop-Service -Force -Name "CscService"

    #Disable Netlogon Service
    Set-Service -StartupType Disabled "Netlogon"
    Stop-Service -Force -Name "Netlogon"

    #Disable Microsoft Windows SMS Router Service
    Set-Service -StartupType Disabled "SmsRouter"
    Stop-Service -Force -Name "SmsRouter"

    #Disable Microsoft Store Install Service
    Set-Service -StartupType Disabled "InstallService"
    Stop-Service -Force -Name "InstallService"

    #Disable Microsoft Storage Spaces SMP Service
    Set-Service -StartupType Disabled "smphost"
    Stop-Service -Force -Name "smphost"

    #Disable Microsoft Software Shadow Copy Provider Service
    Set-Service -StartupType Disabled "swprv"
    Stop-Service -Force -Name "swprv"

    #Disable Microsoft Passport Container Service
    Set-Service -StartupType Disabled "NgcCtnrSvc"
    Stop-Service -Force -Name "NgcCtnrSvc"

    #Disable Microsoft Passport Service
    Set-Service -StartupType Disabled "NgcSvc"
    Stop-Service -Force -Name "NgcSvc"

    #Disable Microsoft Keyboard Filter Service
    Set-Service -StartupType Disabled "MsKeyboardFilter"
    Stop-Service -Force -Name "MsKeyboardFilter"

    #Disable Microsoft iSCSI Initiator Service
    Set-Service -StartupType Disabled "MSiSCSI"
    Stop-Service -Force -Name "MSiSCSI"

    #Disable Microsoft Edge Update Service
    Set-Service -StartupType Disabled "edgeupdatem"
    Stop-Service -Force -Name "edgeupdatem"

    #Disable Microsoft Edge Update Service
    Set-Service -StartupType Disabled "edgeupdate"
    Stop-Service -Force -Name "edgeupdate"

    #Disable Microsoft Edge Elevation Service 
    Set-Service -StartupType Disabled "MicrosoftEdgeElevationService"
    Stop-Service -Force -Name "MicrosoftEdgeElevationService"

    #Disable Microsoft App-V Client Service
    Set-Service -StartupType Disabled "AppVClient"
    Stop-Service -Force -Name "AppVClient"

    #Disable Microsoft Account Sign-in Assistant Service
    Set-Service -StartupType Disabled "wlidsvc"
    Stop-Service -Force -Name "wlidsvc"

    #Disable Microsoft (R) Diagnostics Hub Standard Collector Service
    Set-Service -StartupType Disabled "diagnosticshub.standardcollector.service"
    Stop-Service -Force -Name "diagnosticshub.standardcollector.service"

    #Disable IP Helper Service
    Set-Service -StartupType Disabled "iphlpsvc"
    Stop-Service -Force -Name "iphlpsvc"

    #Disable Geolocation Service
    Set-Service -StartupType Disabled "lfsvc"
    Stop-Service -Force -Name "lfsvc"

    #Disable File History Service
    Set-Service -StartupType Disabled "fhsvc"
    Stop-Service -Force -Name "fhsvc"

    #Disable Fax Service
    Set-Service -StartupType Disabled "Fax"
    Stop-Service -Force -Name "Fax"

    #Disable Embedded Mode Service
    Set-Service -StartupType Disabled "embeddedmode"
    Stop-Service -Force -Name "embeddedmode"

    #Disable Downloaded Maps Manager Service
    Set-Service -StartupType Disabled "MapsBroker"
    Stop-Service -Force -Name "MapsBroker"

    #Disable Distributed Link Tracking Client Service
    Set-Service -StartupType Disabled "TrkWks"
    Stop-Service -Force -Name "TrkWks"

    #Disable Display Policy Service
    #Can f*ck something up with laptops
    Set-Service -StartupType Disabled "DispBrokerDesktopSvc"
    Stop-Service -Force -Name "DispBrokerDesktopSvc"

    #Disable Display Enhancement Service
    #Can f*ck something up with laptops
    Set-Service -StartupType Disabled "DisplayEnhancementService"
    Stop-Service -Force -Name "DisplayEnhancementService"

    #Disable Diagnostic System Host Service
    Set-Service -StartupType Disabled "WdiSystemHost"
    Stop-Service -Force -Name "WdiSystemHost"

    #Disable Diagnostic Service Host Service
    Set-Service -StartupType Disabled "WdiServiceHost"
    Stop-Service -Force -Name "WdiServiceHost"

    #Disable Diagnostic Policy Service 
    Set-Service -StartupType Disabled "DPS"
    Stop-Service -Force -Name "DPS"

    #Disable Diagnostic Execution Service
    Set-Service -StartupType Disabled "diagsvc"
    Stop-Service -Force -Name "diagsvc"

    #Disable Delivery Optimization Service
    Set-Service -StartupType Disabled "DoSvc"
    Stop-Service -Force -Name "DoSvc"

    #Disable Data Usage Service
    Set-Service -StartupType Disabled "DusmSvc"
    Stop-Service -Force -Name "DusmSvc"

    #Disable Data Sharing Service
    Set-Service -StartupType Disabled "DsSvc"
    Stop-Service -Force -Name "DsSvc"

    #Disable Cryptographic Service
    Set-Service -StartupType Disabled "CryptSvc"
    Stop-Service -Force -Name "CryptSvc"

    #Disable Credential Manager Service
    Set-Service -StartupType Disabled "VaultSvc"
    Stop-Service -Force -Name "VaultSvc"
     
    #Disable Connected User Experiences and Telemetry Service
    Set-Service -StartupType Disabled "DiagTrack"
    Stop-Service -Force -Name "DiagTrack"

    #Disable Cellular Time Service
    Set-Service -StartupType Disabled "autotimesvc"
    Stop-Service -Force -Name "autotimesvc"

    #Disable Bluetooth Support Service
    Set-Service -StartupType Disabled "bthserv"
    Stop-Service -Force -Name "bthserv"

    #Disable Bluetooth Audio Gateway Service
    Set-Service -StartupType Disabled "BTAGService"
    Stop-Service -Force -Name "BTAGService"

    #Disable BitLocker Drive Encryption Service
    Set-Service -StartupType Disabled "BDESVC"
    Stop-Service -Force -Name "BDESVC"

    #Disable Auto Time Zone Updater Service
    Set-Service -StartupType Disabled "tzautoupdate"
    Stop-Service -Force -Name "tzautoupdate"

    #Now some tasks
    #   Disable-ScheduledTask -TaskName "Path" | Out-Null

    Disable-ScheduledTask -TaskName "\Microsoft\XblGameSave\XblGameSaveTask" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Windows Defender\Windows Defender Cleanup" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Windows Defender\Windows Defender Verification" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\WDI\ResolutionHost" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\WCM\WiFiTask" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Time Zone\SynchronizeTimeZone" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Time Synchronization\ForceSynchronizeTime" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Time Synchronization\SynchronizeTime" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\SystemRestore\SR" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Sysmain\HybridDriveCachePrepopulate" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Sysmain\HybridDriveCacheRebalance" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Sysmain\ResPriStaticDbSync" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Sysmain\WsSwapAssessmentTask" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Speech\SpeechModelDownloadTask" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTask" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTaskLogon" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTaskNetwork" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Shell\IndexerAutomaticMaintenance" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Setup\SetupCleanupTask" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\SettingSync\BackgroundUploadTask" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\SettingSync\NetworkStateChangeTask" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Registry\RegIdleBackup" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Printing\EduPrintProv" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Offline Files\Background Synchronization" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Offline Files\Logon Synchronization" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Maps\MapsToastTask" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Maps\MapsUpdateTask" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Location\WindowsActionDialog" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Location\Notifications" | Out-Null
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
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\BitLocker\BitLocker MDM policy Refresh" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\BitLocker\BitLocker Encrypt All Drives" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Application Experience\ProgramDataUpdater" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\Application Experience\StartupAppTask" | Out-Null
    Disable-ScheduledTask -TaskName "\MicrosoftEdgeUpdateTaskMachineUA" | Out-Null
    Disable-ScheduledTask -TaskName "\MicrosoftEdgeUpdateTaskMachineCore" | Out-Null

    #Disable Hibernation
    writeHost "Disabled Hibernation"
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Power" -Name "HibernteEnabled" -Type Dword -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowHibernateOption" -Type Dword -Value 0

    #Uninstall all Metro applications!
    writeHost "Now uninstalling all Metro applications"
    Get-AppxPackage -AllUsers | Remove-AppxPackage
    Get-AppxPackage | Remove-AppxPackage
    write-Host "Metro applications should be gone now"
    
    write-Host "More registry tweaking..."

    #2020-DeCrapify.ps1#########################################################################################################################################
    
        #Show File Extensions
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0
        write-Host "Now, you will see file extensions"

        #Explorer launches to My Computer
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1

        #Disable Sticky Keys
        Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Type String -Value "506"
        write-Host "Sticky Keys should be disabled now"

        #Disable Lock Screen!
        If (!(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\Personalization")) {
 	        New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\Personalization" | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreen" -Type DWord -Value 1
        write-Host "Lock Screen has been disabled"

        #Disable UAC
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 0
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 0
        write-Host "UAC has been disabled"
        
        #Disable Advertising ID
        If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo")) {
	        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" | Out-Null
        }
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Type DWord -Value 0
        write-Host "Advertising ID has been disabled"

        #Disable SmartScreen
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Type String -Value "Off"
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -Type DWord -Value 0
        write-Host "SmartScreen has been disabled"

        #Disable WiFi Sense
        write-Host "Trying to disabled Wi-Fi Sense..."
        If (!(Test-Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting")) {
	    New-Item -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 0
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 0
        write-Host "Wi-Fi Sense has been disabled"

        #Disable Firewall
        write-Host "Disabled Windows Defender"
        Set-NetFirewallProfile -Profile * -Enabled False

        #Disable Windows Defender
        write-Host "Disabled Windows Defender"
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Type DWord -Value 1

        #Disable Remote Desktop
        write-Host "Disabled Remote Desktop"
        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Type DWord -Value 1
        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Type DWord -Value 1

        #Disable AutoPlay
        write-Host "Disabled AutoPlay"
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Type DWord -Value 1

        #Taskbar Tweaks
            #Search Icon - Disable
            write-Host "Disabled Search on taskbar"
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0

            #Task View Icon - Disable
            write-Host "Disabled Task View button on taskbar"
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0

            #Taskbar Show Small Icons - Enable
            #   Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons" -Type DWord -Value 1

        #2020-DeCrapify.ps1#########################################################################################################################################

        #Disable Transparency Effects
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "EnableTransparency" -Type DWord -Value 0
        write-Host "Transparency Effects has been turned off"

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
    Stop-Process -Name "SearchApp" -ErrorAction SilentlyContinue
    Write-Host "Disabled Cortana"
})

$backgroundapps.Add_Click({
    Write-Host "Disabling Background application access..."
    Get-ChildItem -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Exclude "Microsoft.Windows.Cortana*" | ForEach {
        Set-ItemProperty -Path $_.PsPath -Name "Disabled" -Type DWord -Value 1
        Set-ItemProperty -Path $_.PsPath -Name "DisabledByUser" -Type DWord -Value 1
    }
    Write-Host "Disabled Background application access"
})

$actioncenter.Add_Click({
    Write-Host "Disabling Action Center..."
    If (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) {
        New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -Type DWord -Value 1
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -Type DWord -Value 0
    Write-Host "Disabled Action Center"
})

$visualfx.Add_Click({
    Write-Host "Adjusting visual effects for performance..."
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "DragFullWindows" -Type String -Value 0
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Type String -Value 200
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -Type Binary -Value ([byte[]](144,18,3,128,16,0,0,0))
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Type String -Value 0
    Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name "KeyboardDelay" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewAlphaSelect" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewShadow" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAnimations" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Type DWord -Value 3
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "EnableAeroPeek" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\TaskbarAnimations" -Name "DefaultApplied" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListBoxSmoothScrolling" -Name "DefaultApplied" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DWMAeroPeekEnabled" -Name "DefaultApplied" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\MenuAnimation" -Name "DefaultApplied" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\TooltipAnimation" -Name "DefaultApplied" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ComboBoxAnimation" -Name "DefaultApplied" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\CursorShadow" -Name "DefaultApplied" -Type DWord -Value 0
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
    Start-Sleep -s 2
    $onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
    If (!(Test-Path $onedrive)) {
        $onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
    }
    Start-Process $onedrive "/uninstall" -NoNewWindow -Wait
    Start-Sleep -s 2
    Stop-Process -Name "explorer" -ErrorAction SilentlyContinue
    Start-Sleep -s 2
    Remove-Item -Path "$env:USERPROFILE\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:PROGRAMDATA\Microsoft OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:SYSTEMDRIVE\OneDriveTemp" -Force -Recurse -ErrorAction SilentlyContinue
    If (!(Test-Path "HKCR:")) {
        New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
    }
    Remove-Item -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue

    #2020-DeCrapify.ps1#######################################
        foreach ($item in (Get-ChildItem "$env:WinDir\WinSxS\*onedrive*")) {
        Takeown-Folder $item.FullName
        Remove-Item -Recurse -Force $item.FullName
        }
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:localappdata\Microsoft\OneDrive"
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:programdata\Microsoft OneDrive"
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:systemdrive\OneDriveTemp"
        If ((Get-ChildItem "$env:userprofile\OneDrive" -Recurse | Measure-Object).Count -eq 0) {
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:userprofile\OneDrive"
        }
    #2020-DeCrapify.ps1#######################################
    Write-Host "Disabled OneDrive"
})

$darkmode.Add_Click({
    #Dark Mode
    Write-Host "Enabling Dark Mode"
    Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize -Name AppsUseLightTheme -Value 0
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /v "AppsUseLightTheme" /t "REG_DWORD" /d "0" /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /v "SystemUsesLightTheme" /t "REG_DWORD" /d "0" /f
    reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /f
    reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /f
    reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t "REG_DWORD" /d "0" /f
    reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "SystemUsesLightTheme" /t "REG_DWORD" /d "0" /f
    reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /f
    reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /f
    reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t "REG_DWORD" /d "0" /f
    reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "SystemUsesLightTheme" /t "REG_DWORD" /d "0" /f
    Write-Host "Enabled Dark Mode"
})

$lightmode.Add_Click({
    #Light Mode
    Write-Host "Switching Back to Light Mode"
    Remove-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize -Name AppsUseLightTheme
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /v "AppsUseLightTheme" /t "REG_DWORD" /d "1" /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /v "SystemUsesLightTheme" /t "REG_DWORD" /d "1" /f
    reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /f
    reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /f
    reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t "REG_DWORD" /d "1" /f
    reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "SystemUsesLightTheme" /t "REG_DWORD" /d "1" /f
    reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /f
    reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /f
    reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t "REG_DWORD" /d "1" /f
    reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "SystemUsesLightTheme" /t "REG_DWORD" /d "1" /f
    Write-Host "Switched Back to Light Mode"
})

$DisableNumLock.Add_Click({
    Write-Host "Disable NumLock after startup..."
    Set-ItemProperty -Path "HKU:\.DEFAULT\Control Panel\Keyboard" -Name "InitialKeyboardIndicators" -Type DWord -Value 0
    Add-Type -AssemblyName System.Windows.Forms
    If (([System.Windows.Forms.Control]::IsKeyLocked('NumLock'))) {
        $wsh = New-Object -ComObject WScript.Shell
        $wsh.SendKeys('{NUMLOCK}')
    }
})

$disablewindowsupdate.Add_Click({
    #Disable Windows Update Services
    Stop-Service -Force -Name "wuauserv"
    Stop-Service -Force -Name "UsoSvc"
    Stop-Service -Force -Name "wisvc"
    Set-Service "wuauserv" -StartupType Disabled
    Set-Service "WaaSMedicSvc" -StartupType Disabled
    Set-Service "UsoSvc" -StartupType Disabled
    Set-Service "wisvc" -StartupType Disabled
    
    
    #Disable Windows Update Scheduled Tasks
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\WindowsUpdate\Scheduled Start" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\WaaSMedic\PerformRemediation" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\UpdateOrchestrator\Report policies" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\UpdateOrchestrator\Schedule Scan" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\UpdateOrchestrator\Schedule Scan Static Task" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\UpdateOrchestrator\UpdateModelTask" | Out-Null
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\UpdateOrchestrator\USO_UxBroker" | Out-Null

    #Disable automatic Windows Update restart
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\WindowsUpdate\UX\Settings" -Name "UxOption" -Type DWord -Value 1

    write-Host "Windows Update has been disabled!"
})

$enablewindowsupdate.Add_Click({
    #Enable Windows Update Services
    Set-Service "wuauserv" -StartupType Manual
    Set-Service "wisvc" -StartupType Manual
    Set-Service "WaaSMedicSvc" -StartupType Manual
    Set-Service "UsoSvc" -StartupType Manual
    Start-Service -Name "wuauserv"
    Start-Service -Name "UsoSvc"
    Start-Service -Name "wisvc"

    #Enable Windows Update Scheduled Tasks
    Enable-ScheduledTask -TaskName "\Microsoft\Windows\WindowsUpdate\Scheduled Start" | Out-Null
    Enable-ScheduledTask -TaskName "\Microsoft\Windows\WaaSMedic\PerformRemediation" | Out-Null
    Enable-ScheduledTask -TaskName "\Microsoft\Windows\UpdateOrchestrator\Report policies" | Out-Null
    Enable-ScheduledTask -TaskName "\Microsoft\Windows\UpdateOrchestrator\Schedule Scan" | Out-Null
    Enable-ScheduledTask -TaskName "\Microsoft\Windows\UpdateOrchestrator\Schedule Scan Static Task" | Out-Null
    Enable-ScheduledTask -TaskName "\Microsoft\Windows\UpdateOrchestrator\UpdateModelTask" | Out-Null
    Enable-ScheduledTask -TaskName "\Microsoft\Windows\UpdateOrchestrator\USO_UxBroker" | Out-Null

    #Enable automatic Windows Update restart
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\WindowsUpdate\UX\Settings" -Name "UxOption" -Type DWord -Value 0

    write-Host "Windows Update has been enabled!"
})

$smalltaskbaricons.Add_Click({

    #Use Small Taskbar Icons    
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons" -Type DWord -Value 1
    Stop-Process -Name "explorer" -ErrorAction SilentlyContinue
    write-Host "You should have small taskbar icons now!"

})

[void]$Form.ShowDialog()
