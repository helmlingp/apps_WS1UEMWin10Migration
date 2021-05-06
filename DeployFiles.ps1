<#	
  .Synopsis
      This powershell script copies the WS1 Win10 Migration script and AirwatchAgent.msi files to C:\Temp\WS1Win10Migration & executes WS1Win10Migration.ps1
  .NOTES
      Created:   	February, 2021
      Created by:	Phil Helmling, @philhelmling
      Organization: VMware, Inc.
      Filename:     DeployFiles.ps1
  .DESCRIPTION
      This powershell script copies the WS1 Win10 Migration script and AirwatchAgent.msi files to C:\Temp\WS1Win10Migration & executes WS1Win10Migration.ps1
  .REQUIREMENTS
      AirwatchAgent.msi must be included in package
  .EXAMPLE
      Install Command
      powershell.exe -ep bypass -file .\DeployFiles.ps1 -scriptname WS1Win10Migration.ps1 -username USERNAME -password PASSWORD -Server DESTINATION_SERVER_URL -OGName DESTINATION_OG_NAME

      Uninstall Command
      .

      When to Call Install Complete
      File Exists: C:\Temp\WS1Win10Migration\WS1Win10Migration.ps1
#>
param (
  [Parameter(Mandatory=$true)]
  [string]$scriptname=$script:scriptname,
  [Parameter(Mandatory=$true)]
  [string]$username=$script:Username,
  [Parameter(Mandatory=$true)]
  [string]$password=$script:password,
  [Parameter(Mandatory=$true)]
  [string]$OGName=$script:OGName,
  [Parameter(Mandatory=$true)]
  [string]$Server=$script:Server
)

$current_path = $PSScriptRoot;
if($PSScriptRoot -eq ""){
    #PSScriptRoot only popuates if the script is being run.  Default to default location if empty
    $current_path = "C:\Temp";
}

$1 = (Get-Item "$current_path\$script:scriptname").BaseName
$deploypath = "C:\Temp\$1"

If(!(test-path $deploypath)){
	New-Item -ItemType Directory -Force -Path $deploypath
}
Copy-Item -Path "$current_path\*.*" -Destination $deploypath -Force -Recurse

#Call Migration Script with parameters
& "powershell.exe" -ep bypass -file `"$deploypath\$script:scriptname`" -username `"$script:username`" -password `"$script:password`" -Server `"$script:Server`" -OGName `"$script:OGName`"
