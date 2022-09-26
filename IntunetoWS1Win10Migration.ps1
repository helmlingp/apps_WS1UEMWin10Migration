<#
.Synopsis
    This Powershell script:
    1. Unenrols a device from Intune
    2. Uninstalls the Intune Company Portal App
    3. Installs AirwatchAgent.msi from current directory in staging enrolment flow to the target WS1 UEM instance using username and password

    This script is deployed using DeployFiles.ps1 included in the repository
    
 .NOTES
    Created:   	    April, 2022
    Created by:	    Phil Helmling, @philhelmling
    Organization:   VMware, Inc.
    Filename:       IntunetoWS1Win10Migration.ps1
    Updated:        August, 2022
    Github:         https://github.com/helmlingp/apps_WS1UEMWin10Migration
.DESCRIPTION
    Unenrols Win10+ device from Intune and then enrols into WS1 UEM. Maintains Azure AD join status. Does not delete device records from Intune.
    Requires AirWatchAgent.msi in the current folder or specify the -Download switch
        - goto https://getwsone.com to download or goto https://<DS_FQDN>/agents/ProtectionAgent_AutoSeed/AirwatchAgent.msi to download it, substituting <DS_FQDN> with the FQDN for the Device Services Server.
    
.EXAMPLE
  .\IntunetoWS1Win10Migration.ps1 -username USERNAME -password PASSWORD -Server DESTINATION_SERVER_FQDN -OGName DESTINATION_GROUPID -Download
#>
param (
    [Parameter(Mandatory=$true)]
    [string]$username=$script:Username,
    [Parameter(Mandatory=$true)]
    [string]$password=$script:password,
    [Parameter(Mandatory=$true)]
    [string]$OGName=$script:OGName,
    [Parameter(Mandatory=$true)]
    [string]$Server=$script:Server,
    [switch]$Download
)

#Enable Debug Logging
$Debug = $false;

$current_path = $PSScriptRoot;
if($PSScriptRoot -eq ""){
    #PSScriptRoot only popuates if the script is being run.  Default to default location if empty
    $current_path = "C:\Temp";
} 
$DateNow = Get-Date -Format "yyyyMMdd_hhmm";
$LogLocation = "$current_path\IntunetoWS1W10Migration_$DateNow.log";
if($Debug){
  write-host "Path: $Path"
  write-host "LogLocation: $LogLocation"
}

$Global:ProgressPreference = 'SilentlyContinue'

function Get-OMADMAccount {
    $OMADMPath = "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts\*"
    $Account = (Get-ItemProperty -Path $OMADMPath -ErrorAction SilentlyContinue).PSChildname
    
    return $Account
}

function Get-IntuneEnrollmentStatus {
    $output = $true

    $EnrollmentPath = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Enrollments\$Account"
    $EnrollmentUPN = (Get-ItemProperty -Path $EnrollmentPath -ErrorAction SilentlyContinue).UPN
    $ProviderID = (Get-ItemProperty -Path $EnrollmentPath -ErrorAction SilentlyContinue).ProviderID

    if(!($EnrollmentUPN) -or $ProviderID -ne "MS DM Server") {
        $output = $false
    }

    return $output
}

function Invoke-UnenrolIntune {
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
    
    #Delete Enrolment Certificates
    $UserCerts = get-childitem cert:"CurrentUser" -Recurse
    $IntuneCerts = $UserCerts | Where-Object {$_.Issuer -eq "CN=SC_Online_Issuing"}
    foreach ($Cert in $IntuneCerts) {
        $cert | Remove-Item -Force
    }
    $DeviceCerts = get-childitem cert:"LocalMachine" -Recurse
    $IntuneCerts = $DeviceCerts | Where-Object {$_.Issuer -eq "CN=Microsoft Intune Root Certification Authority" -OR $_.Issuer -eq "CN=Microsoft Intune MDM Device CA"}
    foreach ($Cert in $IntuneCerts) {
        $cert | Remove-Item -Force -ErrorAction SilentlyContinue
    }

    #Delete Intune Company Portal App
    Get-AppxPackage -AllUsers -Name "Microsoft.CompanyPortal" | Remove-AppxPackage -Confirm:$false
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
    $AWMDMES = (Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\AIRWATCH\EnrollmentStatus" -ErrorAction SilentlyContinue).Status

    if(!($EnrollmentUPN) -or $AWMDMES -ne "Completed" -or $AWMDMES -eq $NULL) {
        $output = $false
    }

    return $output
}

Function Invoke-DownloadAirwatchAgent {
    try
    {
        [Net.ServicePointManager]::SecurityProtocol = 'Tls11,Tls12'
        $url = "https://packages.vmware.com/wsone/AirwatchAgent.msi"
        $output = "$current_path\AirwatchAgent.msi"
        $Response = Invoke-WebRequest -Uri $url -OutFile $output
        # This will only execute if the Invoke-WebRequest is successful.
        $StatusCode = $Response.StatusCode
    } catch {
        $StatusCode = $_.Exception.Response.StatusCode.value__
        Write-Log2 -Path "$logLocation" -Message "Failed to download AirwatchAgent.msi with StatusCode $StatusCode" -Level Error
    }
}

Function Invoke-EnrollDevice {
    Write-Log2 -Path "$logLocation" -Message "Enrolling device into $SERVER" -Level Info
    Try
	{
		Start-Process msiexec.exe -ArgumentList "/i","$current_path\AirwatchAgent.msi","/qn","ENROLL=Y","DOWNLOADWSBUNDLE=false","SERVER=$Server","LGNAME=$OGName","USERNAME=$username","PASSWORD=$password","ASSIGNTOLOGGEDINUSER=Y","/log $current_path\AWAgent.log";
    }
	catch
	{
        Write-Log2 -Path "$logLocation" -Message $_.Exception -Level Error
	}
}

function Get-AppsInstalledStatus {
    [bool]$appsareinstalled = $true
    $appsinstalledsearchpath = "HKEY_LOCAL_MACHINE\SOFTWARE\AirWatchMDM\AppDeploymentAgent\S-1*\*"

    foreach ($app in $appsinstalledsearchpath){
        $isinstalled = (Get-ItemProperty -Path "Registry::$app").IsInstalled
        
        if($isinstalled -eq $false){
            $appname = (Get-ItemProperty -Path "Registry::$app").Name
            Write-Log2 -Path "$logLocation" -Message "$appname is not installed" -Level Info
            $appsareinstalled = $false
            break
        }
    }

    return $appsareinstalled
}

Function Invoke-Migration {

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
    $enrolled = Get-IntuneEnrollmentStatus
    Write-Log2 -Path "$logLocation" -Message "Checking Device Enrollment Status. Unenrol if already enrolled" -Level Info
    Start-Sleep -Seconds 1

    if($enrolled) {
        Write-Log2 -Path "$logLocation" -Message "Device is enrolled" -Level Info
        Start-Sleep -Seconds 1

        #Unenrol from Intune
        Start-Sleep -Seconds 1
        Write-Log2 -Path "$logLocation" -Message "Begin Unenrollment" -Level Info
        Invoke-UnenrolIntune
        
        # Sleep for 10 seconds before checking
        Start-Sleep -Seconds 10
        Write-Log2 -Path "$logLocation" -Message "Checking Enrollment Status" -Level Info
        Start-Sleep -Seconds 1
        # Wait till complete
        while($enrolled) { 
            $status = Get-IntuneEnrollmentStatus
            if($status -eq $false) {
                Write-Log2 -Path "$logLocation" -Message "Device is no longer enrolled into the Source environment" -Level Success
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
    if($Download){
        #Download AirwatchAgent.msi if -Download switch used, otherwise requires AirwatchAgent.msi to be deployed in the ZIP.
        Invoke-DownloadAirwatchAgent
        Start-Sleep -Seconds 10
    }

    Invoke-EnrollDevice

    $enrolled = $false

    while($enrolled -eq $false) {
        #Get OMADM Account
        $Account = Get-OMADMAccount
        Write-Log2 -Path "$logLocation" -Message "OMA-DM Account: $Account" -Level Info
        
        $status = Get-WS1EnrollmentStatus
        if($status -eq $true) {
            $enrolled = $status
            Write-Log2 -Path "$logLocation" -Message "Device Enrollment is complete" -Level Success
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
            Write-Log2 -Path "$logLocation" -Message "Applications all installed, enable Toast Notifications" -Level Success
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
        [Alias('LogPath')]
        [Alias('LogLocation')]
        [string]$Path=$Local:Path,
        [Parameter(Mandatory=$false)]
        [ValidateSet("Success","Error","Warn","Info")]
        [string]$Level="Info"
    )

    $ColorMap = @{"Success"="Green";"Error"="Red";"Warn"="Yellow"};
    $FontColor = "White";
    If($ColorMap.ContainsKey($Level)){$FontColor = $ColorMap[$Level];}
    $DateNow = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $Path -Value ("$DateNow     ($Level)     $Message")
    Write-Host "$DateNow::$Level`t$Message" -ForegroundColor $FontColor;
}

Function Main {

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
        Write-Log2 -Path "$logLocation" -Message "Not connected to Wifi, showing UI notification to continue once reconnected" -Level Error
        Start-Sleep -Seconds 1
    }

}

Main
