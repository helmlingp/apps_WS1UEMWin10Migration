# apps_WS1UEMWin10Migration
This package deploys a script and the AirwatchAgent.msi to a temporary directory, creates a Scheduled Task that executes the WS1Win10Migration.ps1 script after 5 minutes, unenrolling the device from the existing Workspace ONE UEM environment, then enrolling the device into the specified Workspace ONE UEM environment. The process uses command line staging enrolment flow, and assigns the device to the currently logged in Windows User. 
The process unenrols and then enrols a Windows 10 device into a new instance whilst preserving all WS1 UEM managed applications from being uninstalled upon unenrolment.

The package can be used to migrate Windows 10+ devices from one Workspace ONE UEM environment to another and resolve enrolment issues such as a device not switching to the logged in user.

Usage
Include DeployFiles.ps1, WS1Win10Migration.ps1 and AirwatchAgent.msi into ZIP file and upload to Workspace ONE UEM. Utilise the following Application parameters.
Install Command:
powershell.exe -ep bypass -file .\DeployFiles.ps1 -scriptname WS1Win10Migration.ps1 -username USERNAME -password PASSWORD -Server DESTINATION_SERVER_FQDN -OGName DESTINATION_GROUPID
Uninstall Command:
.
When to Call Install Complete:
File Exists: C:\Temp\WS1Win10Migration\WS1Win10Migration.ps1

DeployFiles.ps1 copies WS1Win10Migration.ps1 & AirwatchAgent.msi files to a C:\Temp subfolder, creates a Scheduled Task
The Scheduled Task executes "C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe" with the following arguments: 
-ExecutionPolicy Bypass -File .\WS1Win10Migration.ps1 -username USERNAME -password PASSWORD -Server DESTINATION_SERVER_FQDN -OGName DESTINATION_GROUPID

The Scheduled Task runs with SYSTEM privileges after a delay of 5 minutes from the time of deployment.

Requirements
1. Requires AirWatchAgent.msi in the current folder > goto https://getwsone.com to download or goto https://<DS_FQDN>/agents/ProtectionAgent_AutoSeed/AirwatchAgent.msi to download it, substituting <DS_FQDN> with the FQDN for the Device Services Server.
2. staging username, password, Device Services server and GroupID

Phil Helmling, @philhelmling
Updated January, 2022
