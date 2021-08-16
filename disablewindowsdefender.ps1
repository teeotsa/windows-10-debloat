$Path = Get-Location
$Cmds = @(
    "powershell.exe Set-Service -StartupType Disabled 'WinDefend' -ErrorAction SilentlyContinue"
    "powershell.exe Stop-Service -Force -Name 'WinDefend' -ErrorAction SilentlyContinue"
    "powershell.exe Set-Service -StartupType Disabled 'WdNisSvc' -ErrorAction SilentlyContinue"
    "powershell.exe Stop-Service -Force -Name 'WdNisSvc' -ErrorAction SilentlyContinue"
    "powershell.exe Set-Service -StartupType Disabled 'mpssvc' -ErrorAction SilentlyContinue"
    "powershell.exe Stop-Service -Force -Name 'mpssvc' -ErrorAction SilentlyContinue"
    "powershell.exe Set-Service -StartupType Disabled 'Sense' -ErrorAction SilentlyContinue"
    "powershell.exe Stop-Service -Force -Name 'Sense' -ErrorAction SilentlyContinue"
)

if(Test-Path "$Path\x64"){
    foreach ($Cmds in $Cmds) {
        .\x64\NSudoLG.exe -U:T -P:E -ShowWindowMode:Hide $Cmds 
    }
    exit
} else {
    write-Host "NSudo folder not found! Please make sure you have 'x64' folder in your debloater folder!"
    timeout 5
    exit
}
