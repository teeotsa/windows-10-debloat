# Windows 10 Debloater

Note: Script should work with Windows 11 aswell but you have to comment out following lines : 
![comment out](https://user-images.githubusercontent.com/78772453/131884458-0b623b2e-999b-4b72-9831-6a19530d12f0.PNG)


This script is based of Chris Titus Tech's script! Original : https://github.com/ChrisTitusTech/win10script
 
You can now restore your settings with restore point. If you have restore point and you want to revert back with it, you should enable **'Windows Backup'** and **'Volume Shadow Copy'** service! Run these lines of codes with PowerShell!
- Line of code to enable *Windows Backup* `Set-Service -DisplayName "Windows Backup" -StartupType Manual | Out-Null`
- Line of code to enable *Volume Shadow Copy* `Set-Service -Name "VSS" -StartupType Manual | Out-Null` 

**Also, there is restore scripts now! You can run those restore scritps to restore some of the settings! NOTE: this wont restore everything, best way to restore all of your settings is to use restore point script created!**

This script will remove following:
- *Action Center*
- *Cortana*
- *Uninstall OneDrive*
- *Uninstall/Remove all bloatware*
- *Disable/Enable Windows Update*
- *Windows Cleaner (My Project : https://github.com/teeotsa/windows-cleaner)*
- *Small Taskbar (Currently no toggle option)*
- *Dark/Light mode*
- *Uninstall Edge*
- *Disable Services*
- *Disable Scheduled Tasks*
- *Registry Tweaks*
- *Enable/Disable built-in Administrator account*
- *Disable Windows Defender and Windows Firewall*

**Preview of GUI (Dont mind Windows 8.1, i was lazy to bootup Windows 10)**
![newgui](https://user-images.githubusercontent.com/78772453/131883890-441a831a-d1c3-402f-9d8b-d3a3e0a9e65f.PNG)


