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
