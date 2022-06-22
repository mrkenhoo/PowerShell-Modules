<#
  .Description
   Creates a shortcut in the user's desktop directory of the specified program
#>

function Create-Shortcut
{
    param
    (
        [string]${ProgramName},
        [string]${ShortcutPath},
        [string]${TargetPath}
    )

    try
    {
        ${WSScriptObj} = New-Object -ComObject ("WScript.Shell")
        ${Shortcut} = ${WSScriptObj}.CreateShortcut(${ShortcutPath})
        ${Shortcut}.TargetPath = "${TargetPath}\chrome-win\chrome.exe"
        ${Shortcut}.Save()
    }
    catch
    {
        throw $_.Exception.Message
    }
}

Export-ModuleMember -Function Create-Shortcut
