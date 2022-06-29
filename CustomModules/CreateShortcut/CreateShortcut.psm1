<#
  .Description
   Creates a shortcut in the user's desktop directory of the specified program
#>

function CreateShortcut
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
        ${Shortcut}.TargetPath = "${TargetPath}"
        ${Shortcut}.Save()
    }
    catch
    {
        throw $_.Exception.Message
    }
}

Export-ModuleMember -Function CreateShortcut
