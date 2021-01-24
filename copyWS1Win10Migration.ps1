<#
.Synopsis
    This Powershell script copies the WS1Win10Migration.ps1 script and AirWatchAgent.msi files to C:\Temp\WS1Win10Migration folder and executes WS1Win10Migration.ps1
 .NOTES
    Created:   	    January, 2021
    Created by:	    Phil Helmling, @philhelmling
    Organization:   VMware, Inc.
    Filename:       copyWS1Win10Migration.ps1
    GitHub:         https://github.com/helmlingp/apps_WS1UEMWin10Migration
.DESCRIPTION
    Copies the WS1Win10Migration.ps1 script and AirWatchAgent.msi files to C:\Temp\WS1Win10Migration folder
    Calls WS1Win10Migration.ps1 using parameters passed to this script to prevent credentials being leaked
    
    WS1Win10Migration.ps1 unenrols and then enrols a Windows 10 device into a new instance whilst preserving 
    all WS1 UEM managed applications from being uninstalled upon unenrol.
    Requires AirWatchAgent.msi in the current folder

.EXAMPLE
  .\copyWS1Win10Migration.ps1 -username USERNAME -password PASSWORD -Server DESTINATION_SERVER_URL -OGName DESTINATION_OG_NAME
#>
param (
    [Parameter(Mandatory=$true)]
    [string]$username=$script:username,
    [Parameter(Mandatory=$true)]
    [string]$password=$script:password,
    [Parameter(Mandatory=$true)]
    [string]$OGName=$script:OGName,
    [Parameter(Mandatory=$true)]
    [string]$Server=$script:Server
)

$current_path = $PSScriptRoot
$dest_path = "C:\Temp\WS1Win10Migration"
New-Item -Path $dest_path -ItemType Directory
Copy-Item -Path "$current_path\*" -Destination $dest_path -Recurse

& "$dest_path\WS1Win10Migration.ps1" -username $script:username -password $script:password -Server $script:Server -OGName $script:OGName
