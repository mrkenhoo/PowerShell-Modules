<#
    .Description
    Removes all UWP apps from the system
#>

#Requires -RunAsAdministrator

function RemoveAllUwpApps
{
    ForEach (${UwpApp} in (Get-AppxPackage -AllUsers).PackageFullName)
    {
        Write-Host "==> Removing UWP app ${UwpApp}..."
        Remove-AppxPackage -Package ${UwpApp} -AllUsers | Out-Null
    }
}

Export-ModuleMember -Function RemoveAllUwpApps
