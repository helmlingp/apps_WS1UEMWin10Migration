<#
.Synopsis
    This Powershell script:
    1. Downloads the latest Workspace ONE Intelligent Hub App (AirwatchAgent.msi)
    2. Installs AirwatchAgent.msi from current directory in staging enrolment flow to the target WS1 UEM instance using username and password
    3. Tests if device is already enrolled and waits for the device to report 'Registered Mode'
    
    This script can be deployed using existing PCLM tool.
    
 .NOTES
    Created:   	    April, 2021
    Created by:	    Phil Helmling, @philhelmling
    Modified by:    Pete Lindley, @tbwfdu
    Organization:   VMware, Inc.
    Filename:       InstallWS1Win10CoMgmt.ps1
    Updated:        October, 2022
.DESCRIPTION
    Downloads the latest Workspace ONE Intelligent Hub application (AirwatchAgent.msi) and registers the device against the Workspace ONE UEM environment in Registered Mode.
    Allows the device to remain enrolled in Intune and maintains Azure AD registration, while enabling co-management with Workspace ONE UEM to additional capabilities.
    
.EXAMPLE
  .\InstallWS1Win10CoMgmt.ps1 -username USERNAME -password PASSWORD -Server DESTINATION_SERVER_FQDN -OGName DESTINATION_GROUPID
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
$DateNow = Get-Date -Format "yyyyMMdd_hhmm"
$scriptName = $MyInvocation.MyCommand.Name
$logLocation = "$current_path\$scriptName_$DateNow.log"

if($Debug){
  write-host "Current Path: $current_path"
  write-host "LogLocation: $LogLocation"
}

$agentpath = "C:\Recovery\OEM"
$agent = "AirwatchAgent.msi"

$Global:ProgressPreference = 'SilentlyContinue'

function Get-OMADMAccount {
  $OMADMPath = "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts\*"
  $Account = (Get-ItemProperty -Path $OMADMPath -ErrorAction SilentlyContinue).PSChildname
  
  return $Account
}

function Get-WS1EnrollmentStatus {
  $output = $true;
  #Get OMADM Account
  $Account = Get-OMADMAccount
  Write-Log2 -Path "$logLocation" -Message "OMA-DM Account: $Account" -Level Info

  $EnrollmentPath = "HKLM:\SOFTWARE\Microsoft\Enrollments\$Account"
  $EnrollmentUPN = (Get-ItemProperty -Path $EnrollmentPath -ErrorAction SilentlyContinue).UPN
  $AWMDMES = (Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\AIRWATCH\EnrollmentStatus" -ErrorAction SilentlyContinue).Status

  if(!($EnrollmentUPN) -or $AWMDMES -ne "Completed" -or !($AWMDMES)) {
      $output = $false
  }

  return $output
}

function Get-WS1EnrollmentMode {
    $registeredMode = $false;
    $mode = (Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\AIRWATCH\Feature" -ErrorAction SilentlyContinue).RegisteredMode 
    if($mode) {
        $registeredMode = $true
    }
    return $registeredMode
  }

function Invoke-EnrollDevice {
    Write-Log2 -Path "$logLocation" -Message "Enrolling device into $SERVER" -Level Info
    Try
	{
		Start-Process msiexec.exe -Wait -ArgumentList "/i $current_path\$agent /qn ENROLL=Y DOWNLOADWSBUNDLE=false SERVER=$script:Server LGNAME=$script:OGName USERNAME=$script:username PASSWORD=$script:password ASSIGNTOLOGGEDINUSER=Y /log $current_path\AWAgent.log"
	}
	catch
	{
    Write-Log2 -Path "$logLocation" -Message $_.Exception -Level Error
	}
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

function Invoke-Registration {

    Write-Log2 -Path "$logLocation" -Message "Beginning Enrollment Process" -Level Info
    Start-Sleep -Seconds 1

    #Enrol using Staging flow with ASSIGNTOLOGGEDINUSER=Y
    Write-Log2 -Path "$logLocation" -Message "Running Enrollment process" -Level Info
    Start-Sleep -Seconds 1
    Invoke-EnrollDevice

    $isRegistered = $false

    while($isRegistered -eq $false) {
        $status = Get-WS1EnrollmentMode
        if($status -eq $true) {
            $isRegistered = $status
            Write-Log2 -Path "$logLocation" -Message "Device Registration is complete" -Level Success
            Start-Sleep -Seconds 1
        } else {
            Write-Log2 -Path "$logLocation" -Message "Waiting for registration to complete" -Level Info
            Start-Sleep -Seconds 10
        }
    }

    #Cleanup
    #Invoke-Cleanup
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
  Add-Content -Path $Path -Value ("$DateNow`t($Level)`t$Message")
  Write-Host "$DateNow::$Level`t$Message" -ForegroundColor $FontColor;
}

function Main {

    If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
    {
        # Relaunch as an elevated process:
        Start-Process powershell.exe "-File",('"{0}"' -f $MyInvocation.MyCommand.Path) -Verb RunAs
        exit
    }

    #Check if enrolled already
    $enrolled = Get-WS1EnrollmentStatus

    if(!$enrolled){
        #Initial Device Registration Checks
        Write-Log2 -Path "$logLocation" -Message "Running Initial Device Registration Checks" -Level Info

        $status = Get-WS1EnrollmentMode

        if($status -eq $true) {
            Write-Log2 -Path "$logLocation" -Message "Device already registered. Exiting." -Level Warn
            Start-Sleep -Seconds 1
            exit
        } else {
            Write-Log2 -Path "$logLocation" -Message "Device not registered with Workspace ONE. Continuing." -Level Info
            Start-Sleep -Seconds 1
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
        
            #Download latest AirwatchAgent.msi
            Invoke-DownloadAirwatchAgent

            Invoke-Registration
        } else {
            Write-Log2 -Path "$logLocation" -Message "Not connected to Wifi, showing UI notification to continue once reconnected" -Level Error
            Start-Sleep -Seconds 1
        }
    } else {
      Write-Log2 -Path "$logLocation" -Message "Device already registered. Stopping process." -Level Error
    }

}
#Call Main function
Main