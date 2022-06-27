<#
    .Description
    Removes all UWP apps from the system
#>

#Requires -RunAsAdministrator

function RemoveAllUwpApps
{
    ForEach (${UwpApp} in (Get-AppxPackage -AllUsers).Name)
    {
        try
        {
            Write-Host "==> Removing UWP app ${UwpApp}..."
            Remove-AppxPackage -Package ${UwpApp} -AllUsers -Confirm -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null

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

Export-ModuleMember -Function RemoveAllUwpApps
