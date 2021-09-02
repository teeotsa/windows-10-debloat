$CurrentLocation = $PWD.Path
$NSudoFolder = "$CurrentLocation\x64"

function DisableWindowsDefender{

    Clear-Host
    write-Host "Starting to disable Windows Defender!"
    .\x64\NSudoLG.exe -U:T -P:E -ShowWindowMode:Hide powershell "Set-Service -StartupType Disabled 'WinDefend' -ErrorAction SilentlyContinue"
    .\x64\NSudoLG.exe -U:T -P:E -ShowWindowMode:Hide powershell "Stop-Service -Force -Name 'WinDefend' -ErrorAction SilentlyContinue"
    .\x64\NSudoLG.exe -U:T -P:E -ShowWindowMode:Hide powershell "Set-Service -StartupType Disabled 'WdNisSvc' -ErrorAction SilentlyContinue"
    .\x64\NSudoLG.exe -U:T -P:E -ShowWindowMode:Hide powershell "Stop-Service -Force -Name 'WdNisSvc' -ErrorAction SilentlyContinue"
    .\x64\NSudoLG.exe -U:T -P:E -ShowWindowMode:Hide powershell "Set-Service -StartupType Disabled 'mpssvc' -ErrorAction SilentlyContinue"
    .\x64\NSudoLG.exe -U:T -P:E -ShowWindowMode:Hide powershell "Stop-Service -Force -Name 'mpssvc' -ErrorAction SilentlyContinue"
    .\x64\NSudoLG.exe -U:T -P:E -ShowWindowMode:Hide powershell "Set-Service -StartupType Disabled 'Sense' -ErrorAction SilentlyContinue"
    .\x64\NSudoLG.exe -U:T -P:E -ShowWindowMode:Hide powershell "Stop-Service -Force -Name 'Sense' -ErrorAction SilentlyContinue"
    RestartExplorer
    write-Host "Done, you can close this script now!"
    pause
    exit

}

function ThrowNSudoError{

    Clear-Host
    write-Host "'NSudo' folder or 'NSudo' executable not found! Please make sure its there and run this script again..."
    write-Host "Please close this script manually"
    pause
    exit

}

function ThrowError{

    Clear-Host
    write-Host "Something went wrong! Script will close in 5 seconds"
    Start-Sleep -Seconds 5
    exit

}

function RestartExplorer{

    Clear-Host
    write-Host "Restarting Explorer..."
    Stop-Process -Name "explorer" -PassThru -Force -ErrorAction SilentlyContinue | Out-Null

}

if(Get-Item -Path "$NSudoFolder\NSudoLG.exe"){
    DisableWindowsDefender
} else {
    ThrowNSudoError
}

pause



<#
Old method 

if (Test-Path ".\x64"){
	
	write-Host "NSudo folder found! Script will start now!"
	    .\x64\NSudoLG.exe -U:T -P:E -ShowWindowMode:Hide powershell "Set-Service -StartupType Disabled 'WinDefend' -ErrorAction SilentlyContinue"
        .\x64\NSudoLG.exe -U:T -P:E -ShowWindowMode:Hide powershell "Stop-Service -Force -Name 'WinDefend' -ErrorAction SilentlyContinue"
        .\x64\NSudoLG.exe -U:T -P:E -ShowWindowMode:Hide powershell "Set-Service -StartupType Disabled 'WdNisSvc' -ErrorAction SilentlyContinue"
        .\x64\NSudoLG.exe -U:T -P:E -ShowWindowMode:Hide powershell "Stop-Service -Force -Name 'WdNisSvc' -ErrorAction SilentlyContinue"
        .\x64\NSudoLG.exe -U:T -P:E -ShowWindowMode:Hide powershell "Set-Service -StartupType Disabled 'mpssvc' -ErrorAction SilentlyContinue"
        .\x64\NSudoLG.exe -U:T -P:E -ShowWindowMode:Hide powershell "Stop-Service -Force -Name 'mpssvc' -ErrorAction SilentlyContinue"
        .\x64\NSudoLG.exe -U:T -P:E -ShowWindowMode:Hide powershell "Set-Service -StartupType Disabled 'Sense' -ErrorAction SilentlyContinue"
        .\x64\NSudoLG.exe -U:T -P:E -ShowWindowMode:Hide powershell "Stop-Service -Force -Name 'Sense' -ErrorAction SilentlyContinue"
    Clear-Host
    write-Host "Done, script will close in 3 seconds"
    Start-Sleep -Seconds 3
    exit
	
} else {
	
	write-Host "NSudo folder not found! Script will close in 3 seconds"
	Start-Sleep -Seconds 3
    exit
	
}
#>
