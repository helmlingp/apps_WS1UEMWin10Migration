## apps_WS1UEMWin10Migration
A group of scripts to migration from another MDM to WS1 UEM.

This package deploys a script and the AirwatchAgent.msi to a temporary directory, creates a Scheduled Task that executes the selected script (WS1toWS1Win10Migration.ps1 or IntunetoWS1Win10Migration.ps1) after 5 minutes, unenrolling the device from the existing MDM, then enrolling the device into the specified Workspace ONE UEM environment. The process uses command line staging enrolment flow, and assigns the device to the currently logged in Windows User. 
If migration from one WS1 env to another, the process preserves all WS1 UEM managed applications from being uninstalled upon unenrolment.

The package can be used to migrate Windows 10+ devices from one Workspace ONE UEM environment to another or resolve enrolment issues such as a device not switching to the logged in user.

**Usage**
Intune to WS1 Migration
Include DeployFiles.ps1, IntunetoWS1Win10Migration.ps1 and AirwatchAgent.msi into ZIP file and upload to Intune. Utilise the following Application parameters to input into the Intune Win32App.
Install Command:  powershell.exe -ep bypass -file .\DeployFiles.ps1 -scriptname WS1Win10Migration.ps1 -username USERNAME -password PASSWORD -Server DESTINATION_SERVER_FQDN -OGName DESTINATION_GROUPID
Uninstall Command:  .
Install Behaviour:  System
Device restart behavior:  No specific action

WS1 to WS1 Migration
Include DeployFiles.ps1, WS1Win10Migration.ps1 and AirwatchAgent.msi into ZIP file and upload to Workspace ONE UEM. Utilise the following Application parameters.
Install Command:  powershell.exe -ep bypass -file .\DeployFiles.ps1 -scriptname WS1Win10Migration.ps1 -username USERNAME -password PASSWORD -Server DESTINATION_SERVER_FQDN -OGName DESTINATION_GROUPID
Uninstall Command:  .
Install Context:  Device
Admin Rights: Yes
When to Call Install Complete:  File Exists: C:\Temp\WS1Win10Migration\WS1Win10Migration.ps1

DeployFiles.ps1 copies the specified script (SCRIPT) & AirwatchAgent.msi files to a C:\Temp subfolder, and creates a Scheduled Task.
The Scheduled Task executes "C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe" with the following arguments: 
-ExecutionPolicy Bypass -File .\SCRIPT.ps1 -username USERNAME -password PASSWORD -Server DESTINATION_SERVER_FQDN -OGName DESTINATION_GROUPID

The Scheduled Task runs with SYSTEM privileges after a delay of 5 minutes from the time of deployment.

Requirements
1. Requires AirWatchAgent.msi in the current folder > goto https://getwsone.com to download or goto https://<DS_FQDN>/agents/ProtectionAgent_AutoSeed/AirwatchAgent.msi to download it, substituting <DS_FQDN> with the FQDN for the Device Services Server.
2. staging username, password, Device Services server and GroupID

Phil Helmling, @philhelmling
Updated July, 2022
