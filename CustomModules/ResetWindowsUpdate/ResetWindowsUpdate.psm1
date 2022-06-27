﻿#Requires -RunAsAdministrator

if (!${bootupState}) { New-Variable -Name bootupState -Value (gwmi win32_computersystem -Property BootupState).BootupState | Out-Null }

if (${bootupState} -ne "Fail-safe boot")
{
    Write-Error "The system is required to be running in safe-mode to execute this script."
    Write-Host -NoNewLine 'Press any key to continue...';
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
    Exit 1
}

function ResetWindowsUpdate
{
    try
    {
        net stop bits
        net stop wuauserv
        net stop appidsvc
        net stop cryptsvc

        del "%ALLUSERSPROFILE%\Application Data\Microsoft\Network\Downloader\*.*"

        rmdir %systemroot%\SoftwareDistribution /S /Q
        rmdir %systemroot%\system32\catroot2 /S /Q

        sc.exe "sdset bits D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;PU)"
        sc.exe "sc.exe sdset wuauserv D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;PU)"

        cd /d %windir%\system32

        regsvr32.exe /s atl.dll
        regsvr32.exe /s urlmon.dll
        regsvr32.exe /s mshtml.dll
        regsvr32.exe /s shdocvw.dll
        regsvr32.exe /s browseui.dll
        regsvr32.exe /s jscript.dll
        regsvr32.exe /s vbscript.dll
        regsvr32.exe /s scrrun.dll
        regsvr32.exe /s msxml.dll
        regsvr32.exe /s msxml3.dll
        regsvr32.exe /s msxml6.dll
        regsvr32.exe /s actxprxy.dll
        regsvr32.exe /s softpub.dll
        regsvr32.exe /s wintrust.dll
        regsvr32.exe /s dssenh.dll
        regsvr32.exe /s rsaenh.dll
        regsvr32.exe /s gpkcsp.dll
        regsvr32.exe /s sccbase.dll
        regsvr32.exe /s slbcsp.dll
        regsvr32.exe /s cryptdlg.dll
        regsvr32.exe /s oleaut32.dll
        regsvr32.exe /s ole32.dll
        regsvr32.exe /s shell32.dll
        regsvr32.exe /s initpki.dll
        regsvr32.exe /s wuapi.dll
        regsvr32.exe /s wuaueng.dll
        regsvr32.exe /s wuaueng1.dll
        regsvr32.exe /s wucltui.dll
        regsvr32.exe /s wups.dll
        regsvr32.exe /s wups2.dll
        regsvr32.exe /s wuweb.dll
        regsvr32.exe /s qmgr.dll
        regsvr32.exe /s qmgrprxy.dll
        regsvr32.exe /s wucltux.dll
        regsvr32.exe /s muweb.dll
        regsvr32.exe /s wuwebv.dll

        netsh winsock reset
        netsh winsock reset proxy

        net start bits
        net start wuauserv
        net start appidsvc
        net start cryptsvc

        Write-Host -NoNewLine 'Press any key to continue...'
        $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    }
    catch
    {
        $_.Message.Exception
        Write-Host -NoNewLine 'Press any key to continue...'
        $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    }
}

Export-ModuleMember -Function ResetWindowsUpdate
