If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
	Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
	Exit
}
if (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer")){
New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "EnableLegacyBalloonNotifications" -Type DWord -Value 0
if (!(Test-Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\MTCUVC")){
New-Item -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\MTCUVC" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\MTCUVC" -Name "EnableMtcUvc" -Type DWord -Value 1
exit