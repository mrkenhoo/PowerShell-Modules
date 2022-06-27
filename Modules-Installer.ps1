#Requires -RunAsAdministrator
param
(
    [Parameter(Mandatory=$true)]
    [bool]${Install}
)

process
{
    try
    {
        if (${Install})
        {
            ForEach (${Module} in @(Get-ChildItem -Directory .\CustomModules))
            {
                Copy-Item -LiteralPath ".\CustomModules\${Module}" -Confirm -Destination "${env:SystemRoot}\System32\WindowsPowerShell\v1.0\Modules" -Force -Recurse | Out-Null
                Import-Module -Name ${Module}
            }

            Write-Host -NoNewLine 'Press any key to continue...'
            $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
        }
        else
        {
            ForEach (${Module} in @(Get-ChildItem -Directory ".\CustomModules"))
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
