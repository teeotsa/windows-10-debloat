@echo off
:s
cls
title !!!   CAUTION   !!!
color 4
echo This script will remove some functionality of Windows! Like gamemode, xbox features, activation
echo Type OK to continue!
echo Type EXIT to exit our script!


set /p input=Your choice?
if %input% == OK goto start
if %input% == ok goto start
if %input% == Ok goto start
if %input% == oK goto start
if %input% == EXIT goto exi
if %input% == exit goto exi
if %input% == Exit goto exi
if %input% == eXit goto exi
if %input% == exIt goto exi
if %input% == exiT goto exi
goto s
:exi
exit

:start
cls
color 0a
echo Starting...
echo If you get errors like 'Access denied' then just use NSudo!

::Goto System32 Folder!
cd %WINDIR%\System32

taskkill /f /im backgroundTaskHost.exe /t
del /q backgroundTaskHost.exe
del /q AzureSettingSyncProvider.dll
taskkill /f /im SearchIndexer.exe /t
del /q SearchIndexer.exe
taskkill /f /im SearchFilterHost.exe /t
del /q SearchFilterHost.exe
del /q SearchFolder.dll
taskkill /f /im SearchProtocolHost.exe /t
del /q SearchProtocolHost.exe
taskkill /f /im SecurityHealthSystray.exe /t
del /q SecurityHealthSystray.exe
del /q SecurityHealthSSO.dll
taskkill /f /im SecurityHealthService.exe /t
del /q SecurityHealthService.exe
del /q SecurityHealthProxyStub.dll
taskkill /f /im SecurityHealthHost.exe /t
del /q SecurityHealthAgent.dll
del /q SecurityCenterBrokerPS.dll
del /q SecurityCenterBroker.dll
del /q security.dll
taskkill /f /im SensorDataService.exe /t
del /q SensorDataService.exe
taskkill /f /im ctfmon.exe /t
del /q ctfmon.exe
del /q XblAuthManager.dll
del /q XblAuthManagerProxy.dll
del /q XblAuthTokenBrokerExt.dll
del /q XblGameSave.dll
del /q XblGameSaveExt.dll
del /qXblGameSaveProxy.dll
taskkill /f /im XblGameSaveTask.exe /t
del /q XblGameSaveTask.exe
del /q XboxGipRadioManager.dll
del /q xboxgipsvc.dll
del /q xboxgipsynthetic.dll
del /q XboxNetApiSvc.dll
del /q tabcal.exe
del /q TabletPC.cpl
del /q Firewall.cpl
del /q fingerprintcredential.dll
taskkill /f /im FileHistory.exe /t
del /q FileHistory.exe
del /q BingMaps.dll
del /q StartTileData.dll
del /q Windows.UI.Input.Inking.dll
del /q AppXDeploymentServer.dll
del /q Windows.UI.PicturePassword.dll
del /q Windows.UI.Search.dll
del /q Windows.Gaming.UI.GameBar.dll
del /q gameux.dll
taskkill /f /im GamePanel.exe /t 
del /q GamePanel.exe
taskkill /f /im GameBarPresenceWriter.exe /t
del /q GameBarPresenceWriter.exe
del /q GameInput.dll
del /q GameChatTranscription.dll
del /q GameChatOverlayExt.dll
del /q GamePanelExternalHook.dll
del /q GameBarPresenceWriter.proxy.dll
del /q gamemode.dll
del /q gamestreamingext.dll
del /q Windows.Gaming.XboxLive.Storage.dll
del /q SettingsHandlers_Gaming.dll

cd %WINDIR%\SysWOW64
del /q WalletBackgroundServiceProxy.dll
del /q WalletProxy.dll
del /q Windows.Devices.SmartCards.dll
del /q Windows.Devices.SmartCards.Phone.dll
del /q Windows.Gaming.Input.dll
del /q Windows.Gaming.Preview.dll
del /q Windows.Gaming.UI.GameBar.dll
del /q Windows.Gaming.XboxLive.Storage.dll
del /q Windows.Graphics.Printing.3D.dll
del /q Windows.Graphics.Printing.dll
del /q Windows.Graphics.Printing.Workflow.dll
del /q Windows.Graphics.Printing.Workflow.Native.dll
del /q Windows.UI.Search.dll
del /q BingMaps.dll
del /q BingOnlineServices.dll
taskkill /f /im mobsync.exe /t
del /q mobsync.exe
del /q FirewallControlPanel.dll
del /q fingerprintcredential.dll
taskkill /f /im ctfmon.exe /t
del /q ctfmon.exe
del /q AzureSettingSyncProvider.dll
taskkill /f /im backgroundTaskHost.exe /t
del /q backgroundTaskHost.exe

::Remove Edge
cd \Program Files (x86)\Microsoft
rmdir /s Edge /q
rmdir /s EdgeUpdate /q
rmdir /s Temp /q

::Remove More Stuff
cd \Program Files (x86)
rmdir /s "Windows Mail" /q
rmdir /s "Windows Defender" /q
rmdir /s "Windows Media Player" /q
rmdir /s "Internet Explorer" /q

cd \Program Files
rmdir /s "Internet Explorer" /q
rmdir /s "Windows Defender" /q
rmdir /s "Windows Defender Advanced Threat Protection" /q
rmdir /s "Windows Mail" /q
rmdir /s "Windows Media Player" /q  

::This will f*ck up Windows Explorer
::cd \Program Files\WindowsApps
::del /f/q/s *

::Delete Windows Update Folder
cd %WINDIR%
rmdir /s "SoftwareDistribution" /q

::Clear Prefetch Folder
cd %WINDIR%\Prefetch
del * /q

::Clear Temp Folders
cd %WINDIR%\Temp
del /f/q/s *

cd %TEMP%
del /f/q/s *

echo Done! Script will close in 5 seconds
timeout 5
exit
pause
