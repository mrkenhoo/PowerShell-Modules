<#
    .Description
    Reinstalls all UWP apps found on the system, if any.
#>

#Requires -RunAsAdministrator

function ReinstallUwpApps
{
    try
    {
        ${UwpAppsInstallLocation} = (Get-AppxPackage -AllUsers).InstallLocation
        Write-Host '==> ' + ((Get-AppxPackage -AllUsers).InstallLocation).Count + ' UWP app(s) will be reinstalled on this system'
        Write-Host "==> Reinstalling UWP apps..."
        ${UwpAppsInstallLocation} | ForEach
        {
            Add-AppxPackage -Path $_ -Register -Confirm -DisableDevelopmentMode | Out-Null
        }

        Write-Host -NoNewLine 'Press any key to continue...'
        $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    }
    catch
    {
        $_.Exception.Message
        Write-Host -NoNewLine 'Press any key to continue...'
        $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    }
}

Export-ModuleMember -Function ReinstallAllUwpApps
