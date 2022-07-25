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
                if (-not(Test-Path -Path ${env:SystemRoot}\System32\WindowsPowerShell\v1.0\Modules\${Module}))
                {
                    Write-Host "Installing module ${Module} to ${DestinationPath}"
                    Copy-Item -LiteralPath "${SourcePath}\${Module}" -Destination "${DestinationPath}" -Recurse | Out-Null
                    Import-Module -Name "${Module}" -Global -Scope Global
                }
                else
                {
                    Write-Host "Updating module ${Module} located at ${DestinationPath}"
                    Copy-Item -LiteralPath "${SourcePath}\${Module}" -Destination "${DestinationPath}" -Force -Recurse | Out-Null
                    Import-Module -Name "${Module}" -Force -Global -Scope Global
                }
            }
            Write-Host -NoNewLine 'Press any key to continue...'
            $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
        }
        if (${InstallationType} -eq "Removal")
        {
            ForEach (${Module} in @(Get-ChildItem -Directory "${SourcePath}"))
            {
                if (Test-Path -Path "${env:SystemRoot}\System32\WindowsPowerShell\v1.0\Modules\${Module}")
                {
                    Write-Host "Removing module ${Module} from ${DestinationPath}"
                    Remove-Item -Path "${env:SystemRoot}\System32\WindowsPowerShell\v1.0\Modules\${Module}" -Force -Recurse | Out-Null
                    Remove-Module -Name "${Module}" -Force
                }
                else
                {
                    Write-Error -Message "The module '${Module}' is not installed" -Category NotInstalled
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
