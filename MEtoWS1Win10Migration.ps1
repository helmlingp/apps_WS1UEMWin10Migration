<#
  .Synopsis
    This powershell script copies downloads or copies AirwatchAgent.msi files to a C:\Recovery\OEM subfolder, creates a Scheduled Task and a script to be run by the Scheduled Task to migrate a device to WS1 from Manage Engine
    
  .NOTES
    Created:   	    April, 2022
    Created by:	    Phil Helmling, @philhelmling
    Organization:   VMware, Inc.
    Filename:       MEtoWS1Win10Migration.ps1
    Updated:        October, 2022
    Github:         https://github.com/helmlingp/apps_WS1UEMWin10Migration
  .DESCRIPTION
    Unenrols Win10+ device from ManageEngine and then enrols into WS1 UEM. 
    Maintains Azure AD join status. Does not delete device records from ManageEngine.

    This Powershell script:
    1. Unenrols a device from ManageEngine
    2. Uninstalls the ManageEngine Agent
    3. Installs AirwatchAgent.msi from C:\Recovery\OEM directory in staging enrolment flow to the target WS1 UEM instance using username and password

  .REQUIREMENTS
    Requires AirWatchAgent.msi in the C:\Recovery\OEM folder
    Goto https://getwsone.com to download or goto https://<DS_FQDN>/agents/ProtectionAgent_AutoSeed/AirwatchAgent.msi to download it, substituting <DS_FQDN> with the FQDN for the Device Services Server.
    
  .EXAMPLE
    .\MEetoWS1Win10Migration.ps1 -username USERNAME -password PASSWORD -Server DESTINATION_SERVER_FQDN -OGName DESTINATION_GROUPID
#>
param (
  [Parameter(Mandatory=$true)][string]$username=$Username,
  [Parameter(Mandatory=$true)][string]$password=$password,
  [Parameter(Mandatory=$true)][string]$OGName=$OGName,
  [Parameter(Mandatory=$true)][string]$Server=$Server,
  [switch]$Download
)

#Enable Debug Logging
$Debug = $false

$current_path = $PSScriptRoot;
if($PSScriptRoot -eq ""){
    #PSScriptRoot only popuates if the script is being run.  Default to default location if empty
    $current_path = Get-Location
} 
if($IsMacOS -or $IsLinux){$delimiter = "/"}elseif($IsWindows){$delimiter = "\"}
$DateNow = Get-Date -Format "yyyyMMdd_hhmm"
$scriptName = $MyInvocation.MyCommand.Name
$scriptBaseName = (Get-Item $scriptName).Basename
$logLocation = "$current_path"+"$delimiter"+"$scriptBaseName"+"_$DateNow.log"

if($Debug){
  write-host "Current Path: $current_path"
  write-host "LogLocation: $LogLocation"
}

$deploypath = "C:\Recovery\OEM\$scriptBaseName"
$deploypathscriptBaseName = "$deploypath"+"$delimiter"+"$scriptBaseName"
$agentpath = "C:\Recovery\OEM"
$agent = "AirwatchAgent.msi"

function Write-Log2{
    [CmdletBinding()]
    Param(
      [string]$Message,
      [Alias('LogPath')][Alias('LogLocation')][string]$Path=$Local:Path,
      [Parameter(Mandatory=$false)][ValidateSet("Success","Error","Warn","Info")][string]$Level="Info"
    )
  
    $ColorMap = @{"Success"="Green";"Error"="Red";"Warn"="Yellow"};
    $FontColor = "White";
    If($ColorMap.ContainsKey($Level)){$FontColor = $ColorMap[$Level];}
    $DateNow = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $Path -Value ("$DateNow`t($Level)`t$Message")
    Write-Host "$DateNow::$Level`t$Message" -ForegroundColor $FontColor;
}

function Invoke-CreateTask{
    #Get Current time to set Scheduled Task to run powershell
    $DateTime = (Get-Date).AddMinutes(5).ToString("HH:mm")
    $arg = "-ep Bypass -File $deploypathscriptName -username $username -password $password -Server $Server -OGName $OGName"
    
    $TaskName = "$scriptBaseName"
    Try{
        $A = New-ScheduledTaskAction -Execute "C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe" -Argument $arg 
        $T = New-ScheduledTaskTrigger -Once -RandomDelay "00:05" -At $DateTime
        $P = New-ScheduledTaskPrincipal "System" -RunLevel Highest
        $S = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -StartWhenAvailable -Priority 5
        $S.CimInstanceProperties['MultipleInstances'].Value=3
        $D = New-ScheduledTask -Action $A -Principal $P -Trigger $T -Settings $S

        Register-ScheduledTask -InputObject $D -TaskName $Taskname -Force -ErrorAction Stop
        Write-Log2 -Path "$logLocation" -Message "Create Task $Taskname" -Level Info
    } Catch {
        #$e = $_.Exception.Message;
        #Write-Host "Error: Job creation failed.  Validate user rights."
        Write-Log2 -Path "$logLocation" -Message "Error: Job creation failed.  Validate user rights." -Level Info
    }
}
function Build-MigrationScript {
    $MigrationScript = @'
<#
  .Synopsis
    This powershell script copies downloads or copies AirwatchAgent.msi files to a C:\Recovery\OEM subfolder, creates a Scheduled Task and a script to be run by the Scheduled Task to migrate a device to WS1 from Manage Engine
    
  .NOTES
    Created:   	    April, 2022
    Created by:	    Phil Helmling, @philhelmling
    Organization:   VMware, Inc.
    Filename:       MEtoWS1Win10Migration.ps1
    Updated:        October, 2022
    Github:         https://github.com/helmlingp/apps_WS1UEMWin10Migration
  .DESCRIPTION
    Unenrols Win10+ device from ManageEngine and then enrols into WS1 UEM. 
    Maintains Azure AD join status. Does not delete device records from ManageEngine.

    This Powershell script:
    1. Unenrols a device from ManageEngine
    2. Uninstalls the ManageEngine Agent
    3. Installs AirwatchAgent.msi from C:\Recovery\OEM directory in staging enrolment flow to the target WS1 UEM instance using username and password

  .REQUIREMENTS
    Requires AirWatchAgent.msi in the C:\Recovery\OEM folder
    Goto https://getwsone.com to download or goto https://<DS_FQDN>/agents/ProtectionAgent_AutoSeed/AirwatchAgent.msi to download it, substituting <DS_FQDN> with the FQDN for the Device Services Server.
    
  .EXAMPLE
    .\MEetoWS1Win10Migration.ps1 -username USERNAME -password PASSWORD -Server DESTINATION_SERVER_FQDN -OGName DESTINATION_GROUPID
#>
param (
    [Parameter(Mandatory=$true)][string]$username=$script:Username,
    [Parameter(Mandatory=$true)][string]$password=$script:password,
    [Parameter(Mandatory=$true)][string]$OGName=$script:OGName,
    [Parameter(Mandatory=$true)][string]$Server=$script:Server
)

#Enable Debug Logging
$Debug = $false

$current_path = $PSScriptRoot;
if($PSScriptRoot -eq ""){
    #PSScriptRoot only popuates if the script is being run.  Default to default location if empty
    $current_path = Get-Location
} 
if($IsMacOS -or $IsLinux){$delimiter = "/"}elseif($IsWindows){$delimiter = "\"}
$DateNow = Get-Date -Format "yyyyMMdd_hhmm"
$scriptName = $MyInvocation.MyCommand.Name
$scriptBaseName = (Get-Item $scriptName).Basename
$logLocation = "$current_path"+"$delimiter"+"$scriptBaseName"+"_$DateNow.log"

if($Debug){
  write-host "Current Path: $current_path"
  write-host "LogLocation: $LogLocation"
}

$deploypath = "C:\Recovery\OEM\$scriptBaseName"
$deploypathscriptName = "$deploypath"+"$delimiter"+"$scriptName"
$agentpath = "C:\Recovery\OEM"
$agent = "AirwatchAgent.msi"

function Get-OMADMAccount {
    $OMADMPath = "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts\*"
    $Account = (Get-ItemProperty -Path $OMADMPath -ErrorAction SilentlyContinue).PSChildname
    
    return $Account
}

function Get-MEEnrollmentStatus {
    $output = $true
    
    $EnrollmentPath = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Enrollments\$Account"
    $EnrollmentUPN = (Get-ItemProperty -Path $EnrollmentPath -ErrorAction SilentlyContinue).UPN
    $ProviderID = (Get-ItemProperty -Path $EnrollmentPath -ErrorAction SilentlyContinue).ProviderID

    if(!($EnrollmentUPN) -or $ProviderID -ne "MEMDM") {
        $output = $false
    }

    return $output
}

function Invoke-UnenrolME {
    #Delete Task Schedule tasks
    Get-ScheduledTask -TaskPath "\Microsoft\Windows\EnterpriseMgmt\$Account\*" | Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue

    #Delete reg keys
    Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Enrollments\$Account" -Recurse -Force -ErrorAction SilentlyContinue
	Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Enrollments\Status\$Account" -Recurse -Force -ErrorAction SilentlyContinue
	Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\EnterpriseResourceManager\Tracked\$Account" -Recurse -Force -ErrorAction SilentlyContinue
	Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\AdmxInstalled\$Account" -Recurse -Force -ErrorAction SilentlyContinue
	Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\Providers\$Account" -Recurse -Force -ErrorAction SilentlyContinue
	Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts\$Account" -Recurse -Force -ErrorAction SilentlyContinue
	Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Provisioning\OMADM\Logger\$Account" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Provisioning\OMADM\Sessions\$Account" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\AdventNet\*" -Recurse -Force -ErrorAction SilentlyContinue

    #Delete Enrolment Certificates
<#     $UserCerts = get-childitem cert:"CurrentUser" -Recurse
    $MECerts = $UserCerts | Where-Object {$_.Issuer -eq "CN=????"}
    foreach ($Cert in $MECerts) {
        $cert | Remove-Item -Force
    }
    $DeviceCerts = get-childitem cert:"LocalMachine" -Recurse
    $MECerts = $DeviceCerts | Where-Object {$_.Issuer -eq "CN=????" -OR $_.Issuer -eq "CN=????"}
    foreach ($Cert in $MECerts) {
        $cert | Remove-Item -Force -ErrorAction SilentlyContinue
    } #>

    #Uninstall MEDC app - requires manual delete of device object in console
    $b = Get-WmiObject Win32_Product | Where-Object { $_.name -eq "ManageEngine Desktop Central - Agent" }
    $b.Uninstall()
}

function enable-notifications {
    Remove-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.DeviceEnrollmentActivity" -Name "Enabled" -ErrorAction SilentlyContinue -Force

    Remove-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\AirWatchLLC.WorkspaceONEIntelligentHub_htcwkw4rx2gx4!App" -Name "Enabled" -ErrorAction SilentlyContinue -Force

    Remove-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\com.airwatch.windowsprotectionagent" -Name "Enabled" -ErrorAction SilentlyContinue -Force

    Remove-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Workspace ONE Intelligent Hub" -Name "Enabled" -ErrorAction SilentlyContinue -Force

    Write-Log2 -Path "$logLocation" -Message "Toast Notifications for DeviceEnrollmentActivity, WS1 iHub, Protection Agent, and Hub App enabled" -Level Info
}

function Invoke-Cleanup {
    #Remove Task that started the migration
    Unregister-ScheduledTask -TaskName "WS1Win10Migration" -Confirm:$false
    #Remove folder containing scripts and agent file
    Remove-Item -Path $current_path -Recurse -Force
}

function disable-notifications {
    New-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.DeviceEnrollmentActivity" -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.DeviceEnrollmentActivity" -Name "Enabled" -Type DWord -Value 0 -Force

    New-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\AirWatchLLC.WorkspaceONEIntelligentHub_htcwkw4rx2gx4!App" -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\AirWatchLLC.WorkspaceONEIntelligentHub_htcwkw4rx2gx4!App" -Name "Enabled" -Type DWord -Value 0 -Force

    New-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\com.airwatch.windowsprotectionagent" -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\com.airwatch.windowsprotectionagent" -Name "Enabled" -Type DWord -Value 0 -Force

    New-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Workspace ONE Intelligent Hub" -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Workspace ONE Intelligent Hub" -Name "Enabled" -Type DWord -Value 0 -Force

    Write-Log2 -Path "$logLocation" -Message "Toast Notifications for DeviceEnrollmentActivity, WS1 iHub, Protection Agent, and Hub App disabled" -Level Info
}

function Get-EnrollmentStatus {
    $output = $true;

    $EnrollmentPath = "HKLM:\SOFTWARE\Microsoft\Enrollments\$Account"
    $EnrollmentUPN = (Get-ItemProperty -Path $EnrollmentPath -ErrorAction SilentlyContinue).UPN
    $AWMDMES = (Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\AIRWATCH\EnrollmentStatus").Status

    if(!($EnrollmentUPN) -or $AWMDMES -ne "Completed" -or $AWMDMES -eq $NULL) {
        $output = $false
    }

    return $output
}

function Invoke-DownloadAirwatchAgent {
    try {
        [Net.ServicePointManager]::SecurityProtocol = 'Tls11,Tls12'
        $url = "https://packages.vmware.com/wsone/AirwatchAgent.msi"
        $output = "$current_path\$agent"
        $Response = Invoke-WebRequest -Uri $url -OutFile $output
        # This will only execute if the Invoke-WebRequest is successful.
        $StatusCode = $Response.StatusCode
    } catch {
        $StatusCode = $_.Exception.Response.StatusCode.value__
        Write-Log2 -Path "$logLocation" -Message "Failed to download AirwatchAgent.msi with StatusCode $StatusCode" -Level Error
    }
}

function Invoke-EnrollDevice {
    Write-Log2 -Path "$logLocation" -Message "Enrolling device into $SERVER" -Level Info
    Try
	{
		Start-Process msiexec.exe -ArgumentList "/i","$agentpath\$agent","/qn","ENROLL=Y","DOWNLOADWSBUNDLE=false","SERVER=$Server","LGNAME=$OGName","USERNAME=$username","PASSWORD=$password","ASSIGNTOLOGGEDINUSER=Y","/log $agentpath\AWAgent.log";
    }
	catch
	{
        Write-Log2 -Path "$logLocation" -Message $_.Exception -Level Info
	}
}

function Get-AppsInstalledStatus {
    [bool]$appsareinstalled = $true
    $appsinstalledsearchpath = "HKEY_LOCAL_MACHINE\SOFTWARE\AirWatchMDM\AppDeploymentAgent\S-1*\*"

    foreach ($app in $appsinstalledsearchpath){
        $isinstalled = (Get-ItemProperty -Path "Registry::$app").IsInstalled
        
        if($isinstalled -eq $false){
            $appname = (Get-ItemProperty -Path "Registry::$app").Name
            $appsareinstalled = $false
            break
        }
    }

    return $appsareinstalled
}

function Invoke-Migration {

    Write-Log2 -Path "$logLocation" -Message "Beginning Migration Process" -Level Info
    Start-Sleep -Seconds 1

    # Disable Toast notifications
    Write-Log2 -Path "$logLocation" -Message "Disabling Toast Notifications" -Level Info
    disable-notifications

    #Suspend BitLocker so the device doesn't waste time unencrypting and re-encrypting. Device Remains encrypted, see:
    #https://docs.microsoft.com/en-us/powershell/module/bitlocker/suspend-bitlocker?view=win10-ps
    Write-Log2 -Path "$logLocation" -Message "Suspending BitLocker" -Level Info
    Get-BitLockerVolume | Suspend-BitLocker

    #Get OMADM Account
    $Account = Get-OMADMAccount
    Write-Log2 -Path "$logLocation" -Message "OMA-DM Account: $Account" -Level Info

    #Check Enrollment Status
    $enrolled = Get-MEEnrollmentStatus
    Write-Log2 -Path "$logLocation" -Message "Checking Device Enrollment Status. Unenrol if already enrolled" -Level Info
    Start-Sleep -Seconds 1

    if($enrolled) {
        Write-Log2 -Path "$logLocation" -Message "Device is enrolled" -Level Info
        Start-Sleep -Seconds 1

        #Unenrol from ManageEngine
        Start-Sleep -Seconds 1
        Write-Log2 -Path "$logLocation" -Message "Begin Unenrollment" -Level Info
        Invoke-UnenrolME
        
        # Sleep for 10 seconds before checking
        Start-Sleep -Seconds 10
        Write-Log2 -Path "$logLocation" -Message "Checking Enrollment Status" -Level Info
        Start-Sleep -Seconds 1
        # Wait till complete
        while($enrolled) { 
            $status = Get-MEEnrollmentStatus
            if($status -eq $false) {
                Write-Log2 -Path "$logLocation" -Message "Device is no longer enrolled into the Source environment" -Level Info
                #$StatusMessageLabel.Text = "Device is no longer enrolled into the Source environment"
                Start-Sleep -Seconds 1
                $enrolled = $false
            }
            Start-Sleep -Seconds 5
        }
    }

    # Once unenrolled, enrol using Staging flow with ASSIGNTOLOGGEDINUSER=Y
    Write-Log2 -Path "$logLocation" -Message "Running Enrollment process" -Level Info
    Start-Sleep -Seconds 1

    Invoke-EnrollDevice

    $enrolled = $false

    while($enrolled -eq $false) {
        #Get OMADM Account
        $Account = Get-OMADMAccount
        Write-Log2 -Path "$logLocation" -Message "OMA-DM Account: $Account" -Level Info
        
        $status = Get-WS1EnrollmentStatus
        if($status -eq $true) {
            $enrolled = $status
            Write-Log2 -Path "$logLocation" -Message "Device Enrollment is complete" -Level Info
            Start-Sleep -Seconds 1
        } else {
            Write-Log2 -Path "$logLocation" -Message "Waiting for enrollment to complete" -Level Info
            Start-Sleep -Seconds 10
        }
    }

    #Enable BitLocker
    Write-Log2 -Path "$logLocation" -Message "Resuming Bitlocker" -Level Info
    Get-BitLockerVolume | Resume-BitLocker

    #Enable Toast notifications once all apps are installed
    $appsinstalled = $false
    $appsinstalledstatus = Get-AppsInstalledStatus
    while($appsinstalled -eq $false) {
        if($appsinstalledstatus -eq $true) {
            $appsinstalled = $appsinstalledstatus
            Write-Log2 -Path "$logLocation" -Message "Applications all installed, enable Toast Notifications" -Level Info
            Start-Sleep -Seconds 1
            enable-notifications
        } else {
            Write-Log2 -Path "$logLocation" -Message "Waiting for Applications to install" -Level Info
            Start-Sleep -Seconds 60
        }
    }

    #Cleanup
    Write-Log2 -Path "$logLocation" -Message "Beginning cleanup" -Level Info
    Invoke-Cleanup
}

function Write-Log2{
    [CmdletBinding()]
    Param(
      [string]$Message,
      [Alias('LogPath')][Alias('LogLocation')][string]$Path=$Local:Path,
      [Parameter(Mandatory=$false)][ValidateSet("Success","Error","Warn","Info")][string]$Level="Info"
    )
  
    $ColorMap = @{"Success"="Green";"Error"="Red";"Warn"="Yellow"};
    $FontColor = "White";
    If($ColorMap.ContainsKey($Level)){$FontColor = $ColorMap[$Level];}
    $DateNow = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $Path -Value ("$DateNow     ($Level)     $Message")
    Write-Host "$DateNow::$Level`t$Message" -ForegroundColor $FontColor;
  }

function Main {

    If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
    {
        # Relaunch as an elevated process:
        Start-Process powershell.exe "-File",('"{0}"' -f $MyInvocation.MyCommand.Path) -Verb RunAs
        exit
    }

    #Test connectivity to destination server, if available, then proceed with unenrol and enrol
    Write-Log2 -Path "$logLocation" -Message "Checking connectivity to Destination Server" -Level Info
    Start-Sleep -Seconds 1
    if($SERVER.StartsWith("https://")){
        $fqdn = ($SERVER).substring(8)
    } else {
        $fqdn = $SERVER
    }
    
    $connectionStatus = Test-NetConnection -ComputerName $fqdn -Port 443 -InformationLevel Quiet -ErrorAction Stop

    if($connectionStatus -eq $true) {
        Write-Log2 -Path "$logLocation" -Message "Running Device Migration in the background" -Level Info
        Invoke-Migration
    } else {
        Write-Log2 -Path "$logLocation" -Message "Not connected to Wifi, showing UI notification to continue once reconnected" -Level Info
        Start-Sleep -Seconds 1
    }

}

Main
'@
    return $MigrationScript
}

function Invoke-DownloadAirwatchAgent {
    try {
        [Net.ServicePointManager]::SecurityProtocol = 'Tls11,Tls12'
        $url = "https://packages.vmware.com/wsone/AirwatchAgent.msi"
        $output = "$current_path\$agent"
        $Response = Invoke-WebRequest -Uri $url -OutFile $output
        # This will only execute if the Invoke-WebRequest is successful.
        $StatusCode = $Response.StatusCode
    } catch {
        $StatusCode = $_.Exception.Response.StatusCode.value__
        Write-Log2 -Path "$logLocation" -Message "Failed to download AirwatchAgent.msi with StatusCode $StatusCode" -Level Error
    }
}
  
function Main {
    #Setup Logging
    Write-Log2 -Path "$logLocation" -Message "S" -Level Success

    if (!(Test-Path -LiteralPath $deploypath)) {
        try {
        New-Item -Path $deploypath -ItemType Directory -ErrorAction Stop | Out-Null #-Force
        }
        catch {
        Write-Error -Message "Unable to create directory '$deploypath'. Error was: $_" -ErrorAction Stop
        }
        "Successfully created directory '$deploypath'."
    }

    #Download latest AirwatchAgent.msi
    if($Download){
        #Download AirwatchAgent.msi if -Download switch used, otherwise requires AirwatchAgent.msi to be deployed in the ZIP.
        Invoke-DownloadAirwatchAgent
        Start-Sleep -Seconds 10
    } 
    Copy-Item -Path "$current_path\$agent" -Destination "$agentpath\$agent" -Force
    Write-Log2 -Path "$logLocation" -Message "Copied Agent $agent" -Level Info

    #Create migration script to be run by Scheduled Task
    $MigrationScript = Build-MigrationScript
	New-Item -Path $deploypathscriptName -ItemType "file" -Value $MigrationScript -Force -Confirm:$false
	Write-Log2 -Path "$logLocation" -Message "Created script $deploypathscriptName" -Level Info

    #Create Scheduled Task to run the main program
    Invoke-CreateTask
    Write-Log2 -Path "$logLocation" -Message "Created Task set to run at approx $DateTime" -Level Info
}
#Call Main function
Main