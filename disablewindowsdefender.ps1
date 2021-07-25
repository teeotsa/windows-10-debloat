.\x64\NSudoLG.exe -U:T -P:E -ShowWindowMode:Hide powershell.exe Set-Service -StartupType Disabled "WinDefend"
.\x64\NSudoLG.exe -U:T -P:E -ShowWindowMode:Hide powershell.exe Stop-Service -Force -Name "WinDefend"
.\x64\NSudoLG.exe -U:T -P:E -ShowWindowMode:Hide powershell.exe Set-Service -StartupType Disabled "WdNisSvc"
.\x64\NSudoLG.exe -U:T -P:E -ShowWindowMode:Hide powershell.exe Stop-Service -Force -Name "WdNisSvc"
.\x64\NSudoLG.exe -U:T -P:E -ShowWindowMode:Hide powershell.exe Set-Service -StartupType Disabled "mpssvc"
.\x64\NSudoLG.exe -U:T -P:E -ShowWindowMode:Hide powershell.exe Stop-Service -Force -Name "mpssvc"
.\x64\NSudoLG.exe -U:T -P:E -ShowWindowMode:Hide powershell.exe Set-Service -StartupType Disabled "Sense"
.\x64\NSudoLG.exe -U:T -P:E -ShowWindowMode:Hide powershell.exe Stop-Service -Force -Name "Sense"
exit