## apps_WS1UEMWin10Migration
A group of scripts to migration from another MDM to WS1 UEM.

This package creates a script and downloads or copies the AirwatchAgent.msi to C:\Recovery\OEM directory, creates a Scheduled Task that executes the selected script after 5 minutes, unenrolling the device from the existing MDM, then enrolling the device into the specified Workspace ONE UEM environment. The process uses command line staging enrolment flow, and assigns the device to the currently logged in Windows User. 
If migration from one WS1 env to another, the process preserves all WS1 UEM managed applications from being uninstalled upon unenrolment.

The package can be used to migrate Windows 10+ devices from one Workspace ONE UEM environment to another or resolve enrolment issues such as a device not switching to the logged in user, or UPN issues.

**Usage**
Intune to WS1 Migration
Include IntunetoWS1Win10Migration.ps1 and AirwatchAgent.msi into ZIP file and upload to Intune OR just deploy IntunetoWS1Win10Migration.ps1 as a script from Intune directly. Utilise the following Application parameters to input into the Intune Win32App or run as script command.
Install Command:  powershell.exe -ep bypass -file .\IntunetoWS1Win10Migration.ps1 -username USERNAME -password PASSWORD -Server DESTINATION_SERVER_FQDN -OGName DESTINATION_GROUPID -Download
Uninstall Command:  .
Install Behaviour:  System
Device restart behavior:  No specific action

WS1 to WS1 Migration
Include WS1toWS1Win10Migration.ps1 and AirwatchAgent.msi into ZIP file and upload to Workspace ONE UEM OR just deploy WS1toWS1Win10Migration.ps1 as a script from WS1 Scripts function. Utilise the following Application parameters to input into the WS1 Application or run as a script command.
Install Command:  powershell.exe -ep bypass -file .\WS1toWS1Win10Migration.ps1 -username USERNAME -password PASSWORD -Server DESTINATION_SERVER_FQDN -OGName DESTINATION_GROUPID -Download
Uninstall Command:  .
Install Context:  Device
Admin Rights: Yes
When to Call Install Complete:  File Exists: C:\Recovery\OEM\WS1toWS1Win10Migration\WS1WinWS1toWS1Win10Migration10Migration.ps1

The Scheduled Task runs with SYSTEM privileges after a delay of 5 minutes from the time of deployment.

Requirements
1. AirWatchAgent.msi in the current folder > goto https://getwsone.com to download or goto https://<DS_FQDN>/agents/ProtectionAgent_AutoSeed/AirwatchAgent.msi to download it, substituting <DS_FQDN> with the FQDN for the Device Services Server
OR use the -Download parameter
2. Staging username / password, 
3. Device Services server FQDN / URL 
4. GroupID Name (OG) to enrol into

Phil Helmling, @philhelmling
Updated October, 2022
