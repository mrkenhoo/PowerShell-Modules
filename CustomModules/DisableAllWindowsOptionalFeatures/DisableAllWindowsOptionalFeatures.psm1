<#
  .Description
   Creates a shortcut in the user's desktop directory of the specified program
#>

#Requires -RunAsAdministrator

function DisableAllWindowsOptionalFeatures
{
    try
    {
        ${wof} = (Get-WindowsOptionalFeature -FeatureName '*' -Online).FeatureName
        Write-Host ('==> ' + ${wof}.Count + ' Windows optional feature(s) will be disabled from this system')
        ${wof} | ForEach-Object
        {
            Write-Host "    -> Disabling optional feature: $_..."
            Disable-WindowsOptionalFeature -FeatureName $_ -Online -NoRestart -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null
        }

        Write-Host -NoNewLine 'Press any key to continue...'
        $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    }
    catch
    {
        throw $_.Message.Exception
    }
}

Export-ModuleMember -Function DisableAllWindowsOptionalFeatures
