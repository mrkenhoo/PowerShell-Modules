<#
    .Description
    Removes all non-critical UWP apps from the system
#>

#Requires -RunAsAdministrator

${UwpWhitelistedApps} = @(
    "Microsoft.WindowsStore"
    "AppUp.IntelGraphicsExperience"
    "NVIDIACorp.NVIDIAControlPanel"
    "RealtekSemiconductorCorp.RealtekAudioControl"
    "Microsoft.VCLibs.140.00.UWPDesktop"
    "Microsoft.Winget.Source"
    "Microsoft.DesktopAppInstaller"
    "Microsoft.WindowsTerminal"
)

${UwpApps} = (Get-AppxPackage -AllUsers).Name

function RemoveAllNonCriticalUwpApps
{
    foreach ($App in ${UwpApps})
    {
        try
        {
            if ($App -notin ${UwpWhitelistedApps})
            {
                Write-Host "==> Removing UWP app ${App}..."
                Remove-AppPackage -AllUsers -Package $UwpApp | Out-Null
            }

            Write-Host -NoNewLine 'Press any key to continue...'
            $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
        }
        catch
        {
            throw $_.Exception.Message
            Write-Host -NoNewLine 'Press any key to continue...'
            $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
        }
    }
}

Export-ModuleMember -Function RemoveAllNonCriticalUwpApps
