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

cd C:\Windows\System32
del /q GameBarPresenceWriter.exe
del /q GamePanel.exe
del /q MicrosoftEdgeBCHost.exe
del /q MicrosoftEdgeCP.exe
del /q MicrosoftEdgeDevTools.exe
del /q mobsync.exe
del /q MicrosoftEdgeSH.exe
del /q quickassist.exe
del /q SecurityHealthSystray.exe
del /q SecurityHealthService.exe
del /q SecurityHealthHost.exe
del /q slui.exe
del /q smartscreen.exe
del /q spoolsv.exe
del /q WSCollect.exe
del /q WSReset.exe
del /q XblGameSaveTask.exe
del /q XblAuthManager.dll
del /q XblAuthManagerProxy.dll
del /q XblAuthTokenBrokerExt.dll
del /q XblGameSave.dll
del /q XblGameSaveExt.dll
del /q XblGameSaveProxy.dll
del /q XboxGipRadioManager.dll
del /q xboxgipsvc.dll
del /q xboxgipsynthetic.dll
del /q XboxNetApiSvc.dll
del /q GameBarPresenceWriter.proxy.dll
del /q GameChatOverlayExt.dll
del /q GameChatTranscription.dll
del /q GameInput.dll
del /q gamemode.dll
del /q GamePanelExternalHook.dll
del /q gamestreamingext.dll
del /q gameux.dll
del /q gamingtcui.dll
del /q SearchFilterHost.exe
del /q SearchIndexer.exe
del /q SearchProtocolHost.exe
del /q SecurityCenterBroker.dll
del /q SecurityCenterBrokerPS.dll
del /q SecurityHealthAgent.dll
del /q SecurityHealthProxyStub.dll
del /q SecurityHealthSSO.dll

cd C:\Windows\SysWOW64
del /q GameBarPresenceWriter.exe
del /q GameBarPresenceWriter.proxy.dll
del /q GameChatOverlayExt.dll
del /q GameChatTranscription.dll
del /q GameInput.dll
del /q gamemode.dll
del /q GamePanel.exe
del /q GamePanelExternalHook.dll
del /q gameux.dll
del /q gamingtcui.dll
del /q smartscreenps.dll
del /q XblAuthManagerProxy.dll
del /q XblAuthTokenBrokerExt.dll
del /q XblGameSaveProxy.dll
del /q xboxgipsynthetic.dll

cd C:\Program Files\Windows Defender
del /F/Q/S *.*

cd C:\Program Files\Windows Mail
del /F/Q/S *.*

cd C:\Program Files\Windows Defender Advanced Threat Protection
del /F/Q/S *.*

cd C:\Program Files\Windows Security
del /F/Q/S *.*

echo Done! Script will close in 5 seconds
timeout 5
exit
pause