#Requires -RunAsAdministrator

${ModulesList} = @(Get-ChildItem -Directory .\CustomModules)

${ModulesPath} = "${env:SystemRoot}\System32\WindowsPowerShell\v1.0\Modules"

ForEach (${Module} in ${ModulesList})
{
    Copy-Item -LiteralPath .\CustomModules\${Module} -Confirm -Destination ${ModulesPath} -Force -Recurse | Out-Null
    Import-Module -Name ${Module}
}
