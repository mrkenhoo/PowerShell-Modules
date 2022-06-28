#Requires -RunAsAdministrator
param
(
    [Parameter(Mandatory=$true)]
    [String]${SourcePath},
    [Parameter(Mandatory=$true)]
    [String]${DestinationPath},
    [Parameter(Mandatory=$true)]
    [ValidateSet('Deploy','Removal')]
    [String]${InstallationType}
)

process
{
    try
    {
        if (${InstallationType} -eq "Deploy")
        {
            ForEach (${Module} in @(Get-ChildItem -Directory "${SourcePath}"))
            {
                Copy-Item -LiteralPath "${SourcePath}\${Module}" -Confirm -Destination "${DestinationPath}" -Force -Recurse | Out-Null
                Import-Module -Name ${Module}
            }

            Write-Host -NoNewLine 'Press any key to continue...'
            $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
        }
        if (${InstallationType} -eq "Removal")
        {
            ForEach (${Module} in @(Get-ChildItem -Directory "${SourcePath}"))
            {
                if (${Module} -in @(Get-ChildItem -Directory "${env:SystemRoot}\System32\WindowsPowerShell\v1.0\Modules\${Module}"))
                {
                    if (Test-Path -Path "${env:SystemRoot}\System32\WindowsPowerShell\v1.0\Modules\${Module}")
                    {
                        Remove-Item -Path "${env:SystemRoot}\System32\WindowsPowerShell\v1.0\Modules\${Module}" -Confirm -Force -Recurse | Out-Null
                        Remove-Module -Name "${Module}"
                    }
                    else
                    {
                        Write-Warning -Message "The module '${Module}' is not installed"
                    }
                }
            }

            Write-Host -NoNewLine 'Press any key to continue...'
            $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
        }
    }
    catch
    {
        $_.Message.Exception
        Write-Host -NoNewLine 'Press any key to continue...'
        $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    }
}
