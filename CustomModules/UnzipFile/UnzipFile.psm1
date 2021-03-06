<#
  .Description
   Extracts the specified file to a directory
#>

Add-Type -AssemblyName System.IO.Compression.FileSystem

function UnzipFile
{
    #
    # Function source:
    # 'https://stackoverflow.com/questions/27768303/how-to-unzip-a-file-in-powershell'
    #
    param
    (
        [string]${SourceFile},
        [string]${DestinationPath}
    )

    [System.IO.Compression.ZipFile]::ExtractToDirectory(${SourceFile}, ${DestinationPath})
}

Export-ModuleMember -Function UnzipFile
