#Requires -RunAsAdministrator

${ModulesPath} = "${env:SystemRoot}\System32\WindowsPowerShell\v1.0\Modules"

ForEach (${Module} in @(Get-ChildItem -Directory .\CustomModules))
{
    Copy-Item -LiteralPath .\CustomModules\${Module} -Confirm -Destination ${ModulesPath} -Force -Recurse | Out-Null
    Import-Module -Name ${Module}
}

Write-Host -NoNewLine 'Press any key to continue...'
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
