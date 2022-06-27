<#
    .Description
    Applies and enforces group policies to the system to reduce the user's footprint.
#>

#Requires -RunAsAdministrator

function SystemReadinessLite
{
    try
    {
        Import-Module BitsTransfer 2>&1
        Write-Host "==> Downloading O&O ShutUp10..."
        cd $env:TEMP
        Start-BitsTransfer -Source "https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe" -Destination OOSU10.exe -ErrorAction SilentlyContinue | Out-Null
    
        Write-Host "    --> Downloading mrkenhoo's O&O ShutUp10 recommended configuration file..."
        Start-BitsTransfer -Source "https://raw.githubusercontent.com/mrkenhoo/PowerShell-Modules/sunvalley-srw/telemetry_policies/recommended/ooshutup10.cfg" -Destination ooshutup10.cfg -ErrorAction SilentlyContinue | Out-Null

        Write-Host "    --> Applying policies from O&O ShutUp10 configuration file..."
        .\OOSU10.exe ooshutup10.cfg /quiet
        cd $PSScriptRoot
        Remove-Module BitsTransfer

        Write-Host -NoNewLine 'Press any key to continue...'
        $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    }
    catch
    {
        throw $_.Message.Exception
        Write-Host -NoNewLine 'Press any key to continue...'
        $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    }
}

Export-ModuleMember -Function SystemReadinessLite