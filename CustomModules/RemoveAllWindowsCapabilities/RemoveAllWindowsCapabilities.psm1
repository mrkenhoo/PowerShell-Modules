<#
  .Description
   Removes all OS capabilities from compatible Windows versions
#>

#Requires -RunAsAdministrator

if (!${validatedOsVersion}) { New-Variable -Name validatedOsVersion -Value "10.0.22000" 2>&1 }

if (!${OsVersion}) { New-Variable -Name osVersion -Value (gwmi win32_operatingsystem).version 2>&1 }

function RemoveAllWindowsCapabilities
{
    if (${OsVersion} -ge ${validatedOsVersion})
    {
        Write-Error -Message "Please use Windows 10 (21H2) v10.0.19044 instead to avoid breaking the system."
        Write-Host -NoNewLine 'Press any key to continue...'
        $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
        Exit 1
    }
    ${wc} = (Get-WindowsCapability -Online).Name
    Write-Host ('==> ' + ${wc}.Count + ' Windows capabilities(s) will be removed from this system')
    ${wc} | ForEach-Object {
        Write-Host "    -> Disabling optional feature: $_..."
        Remove-WindowsCapability -Name $_ -Online -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null
    }

    Write-Host -NoNewLine 'Press any key to continue...'
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
}

Export-ModuleMember -Function RemoveAllWindowsCapabilities
