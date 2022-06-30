<#
    .Description
    Removes all non-critical UWP apps from the system
#>

#Requires -RunAsAdministrator

${UwpWhitelistedApps} = @(
    "Microsoft.WindowsStore_22205.1401.10.0_x64__8wekyb3d8bbwe"
    "AppUp.IntelGraphicsExperience_1.100.3408.0_x64__8j3eq9eme6ctt"
    "NVIDIACorp.NVIDIAControlPanel_8.1.962.0_x64__56jybvy8sckqj"
    "RealtekSemiconductorCorp.RealtekAudioControl_1.1.137.0_x64__dt26b99r8h8gj"
    "Microsoft.VCLibs.140.00.UWPDesktop_~_x86__8wekyb3d8bbwe"
    "Microsoft.Winget.Source_2022.630.1623.785_neutral__8wekyb3d8bbwe"
    "Microsoft.DesktopAppInstaller_1.17.11601.0_x64__8wekyb3d8bbwe"
    "Microsoft.WindowsTerminal_~_x64__8wekyb3d8bbwe"
)

function RemoveAllNonCriticalUwpApps
{
    ForEach (${App} in (Get-AppxPackage -AllUsers).PackageFullName)
    {
        if (${App} -notin ${UwpWhitelistedApps})
        {
            try
            {
                Write-Host "==> Removing UWP app ${App}..."
                Remove-AppPackage -AllUsers -Package ${App} | Out-Null
            }
            catch
            {
                Write-Error -Message "An error has occurred" -Category NotSpecified
            }
        }
    }
    Write-Host -NoNewLine 'Press any key to continue...'
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
}

Export-ModuleMember -Function RemoveAllNonCriticalUwpApps
