<#
.Synopsis
    This Powershell script:
    1. Downloads the latest Workspace ONE Intelligent Hub App (AirwatchAgent.msi)
    2. Installs AirwatchAgent.msi from current directory in staging enrolment flow to the target WS1 UEM instance using username and password
    3. Registers the device in 'Registered Mode' for Co-Management with Intune and Workspace ONE UEM

    This script is deployed using DeployFiles.ps1 included in the repository
    
 .NOTES
    Created:   	    April, 2021
    Created by:	    Phil Helmling, @philhelmling
    Modified by:    Pete Lindley, @tbwfdu
    Organization:   VMware, Inc.
    Filename:       IntunetoWS1Win10CoMgmt.ps1
    Updated:        June, 2022

.DESCRIPTION
    Downloads the latest Workspace ONE Intelligent Hub application (AirwatchAgent.msi) and registers the device against the Workspace ONE UEM environment in Registered Mode.
    Allows the device to remain enrolled in Intune and maintains Azure AD registration, while enabling co-management with Workspace ONE UEM to additional capabilities.
    
.EXAMPLE
  .\IntunetoWS1Win10CoMgmt.ps1 -username USERNAME -password PASSWORD -Server DESTINATION_SERVER_FQDN -OGName DESTINATION_GROUPID
#>
param (
    [Parameter(Mandatory=$true)]
    [string]$username=$script:Username,
    [Parameter(Mandatory=$true)]
    [string]$password=$script:password,
    [Parameter(Mandatory=$true)]
    [string]$OGName=$script:OGName,
    [Parameter(Mandatory=$true)]
    [string]$Server=$script:Server
)

#Enable Debug Logging
$Debug = $false;

$current_path = $PSScriptRoot;
if($PSScriptRoot -eq ""){
    #PSScriptRoot only popuates if the script is being run.  Default to default location if empty
    $current_path = "C:\Temp";
} 
$DateNow = Get-Date -Format "yyyyMMdd_hhmm";
$pathfile = "$current_path\IntunetoWS1Win10CoMgmt_$DateNow";
$Script:logLocation = "$pathfile.log";
$Script:Path = $logLocation;
if($Debug){
  write-host "Path: $Path"
  write-host "LogLocation: $LogLocation"
}

$Global:ProgressPreference = 'SilentlyContinue'

function Copy-TargetResource {
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$File,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$FiletoCopy
    )

    if (!(Test-Path -LiteralPath $Path)) {
        try {
        New-Item -Path $Path -ItemType Directory -ErrorAction Stop | Out-Null #-Force
        }
        catch {
        Write-Error -Message "Unable to create directory '$Path'. Error was: $_" -ErrorAction Stop
        }
        "Successfully created directory '$Path'."
    }
    Write-Host "Copying $FiletoCopy to $Path\$File"
    Copy-Item -Path $FiletoCopy -Destination "$Path\$File" -Force
    #Test if the necessary files exist
    $FileExists = Test-Path -Path "$Path\$File" -PathType Leaf
}

function Get-WS1EnrollmentStatus {
  $output = $true;

  $EnrollmentPath = "HKLM:\SOFTWARE\Microsoft\Enrollments\$Account"
  $EnrollmentUPN = (Get-ItemProperty -Path $EnrollmentPath -ErrorAction SilentlyContinue).UPN
  $AWMDMES = (Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\AIRWATCH\EnrollmentStatus").Status
  
  if(!($EnrollmentUPN) -or $AWMDMES -ne "Completed" -or !($AWMDMES)) {
      $output = $false
  }

  return $output
}

function Get-WS1EnrollmentMode {
    $registeredMode = $false;
    $mode = (Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\AIRWATCH\Feature").RegisteredMode 
    if($mode) {
        $registeredMode = $true
    }
    return $registeredMode
  }

function Invoke-Cleanup {

    Unregister-ScheduledTask -TaskName "WS1Win10CoMgmt" -Confirm:$false

    Remove-Item -Path $current_path -Recurse -Force
}


function Get-WS1AgentInstalled {
    $agentInstalled = $false;
    $path = (Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\AIRWATCH")
    if($path) {
        $agentInstalled = $true
    }
    return $agentInstalled
}

Function Invoke-EnrollDevice {
    Write-Log2 -Path "$logLocation" -Message "Enrolling device into $SERVER" -Level Info
    Try
	{
		Start-Process msiexec.exe -Wait -ArgumentList "/i $current_path\AirwatchAgent.msi /qn ENROLL=Y DOWNLOADWSBUNDLE=false SERVER=$script:Server LGNAME=$script:OGName USERNAME=$script:username PASSWORD=$script:password ASSIGNTOLOGGEDINUSER=Y /log $current_path\AWAgent.log"
	}
	catch
	{
        Write-Log2 -Path "$logLocation" -Message $_.Exception -Level Info
	}
}

Function Invoke-Registration {

    Write-Log2 -Path "$logLocation" -Message "Beginning Enrollment Process" -Level Info
    Start-Sleep -Seconds 1
    
    #Download latest AirwatchAgent.msi
    wget "https://packages.vmware.com/wsone/AirwatchAgent.msi" -outfile "AirwatchAgent.msi"
    
    #Enrol using Staging flow with ASSIGNTOLOGGEDINUSER=Y
    Write-Log2 -Path "$logLocation" -Message "Running Enrollment process" -Level Info
    Start-Sleep -Seconds 1
    Invoke-EnrollDevice

    $isRegistered = $false

    while($isRegistered -eq $false) {
        $status = Get-WS1EnrollmentMode
        if($status -eq $true) {
            $isRegistered = $status
            Write-Log2 -Path "$logLocation" -Message "Device Registration is complete" -Level Info
            Start-Sleep -Seconds 1
        } else {
            Write-Log2 -Path "$logLocation" -Message "Waiting for registration to complete" -Level Info
            Start-Sleep -Seconds 10
        }
    }

    #Cleanup
    #Invoke-Cleanup
}

function Write-Log {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias("LogContent")]
        [string]$Message,

        [Parameter(Mandatory=$false)]
        [Alias('LogPath')]
        [Alias('LogLocation')]
        [string]$Path=$Local:Path,

        [Parameter(Mandatory=$false)]
        [ValidateSet("Error","Warn","Info")]
        [string]$Level="Info",
        
        [Parameter(Mandatory=$false)]
        [switch]$NoClobber
    )

    Begin
    {
        # Set VerbosePreference to Continue so that verbose messages are displayed.
        $VerbosePreference = 'Continue'

        if(!$Path){
            $current_path = $PSScriptRoot;
            if($PSScriptRoot -eq ""){
                #default path
                $current_path = "C:\Temp";
            }
    
            #setup Report/Log file
            $DateNow = Get-Date -Format "yyyyMMdd_hhmm";
            $pathfile = "$current_path\WS1API_$DateNow";
            $Local:logLocation = "$pathfile.log";
            $Local:Path = $logLocation;
        }
        
    }
    Process
    {
        
        # If the file already exists and NoClobber was specified, do not write to the log.
        if ((Test-Path $Path) -AND $NoClobber) {
            Write-Error "Log file $Path already exists, and you specified NoClobber. Either delete the file or specify a different name."
            Return
            }

        # If attempting to write to a log file in a folder/path that doesn't exist create the file including the path.
        elseif (!(Test-Path $Path)) {
            #Write-Verbose "Creating $Path."
            $NewLogFile = New-Item $Path -Force -ItemType File
            }

        else {
            # Nothing to see here yet.
            }

        # Format Date for our Log File
        $FormattedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

        # Write message to error, warning, or verbose pipeline and specify $LevelText
        switch ($Level) {
            'Error' {
                Write-Error $Message
                $LevelText = 'ERROR:'
                }
            'Warn' {
                Write-Warning $Message
                $LevelText = 'WARNING:'
                }
            'Info' {
                Write-Verbose $Message
                $LevelText = 'INFO:'
                }
            }
        
        # Write log entry to $Path
        "$FormattedDate $LevelText $Message" | Out-File -FilePath $Path -Append
    }
    End
    {
    }
}

function Write-Log2{
    [CmdletBinding()]
    Param
    (
        [string]$Message,
        
        [Alias('LogPath')]
        [Alias('LogLocation')]
        [string]$Path=$Local:Path,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("Success","Error","Warn","Info")]
        [string]$Level="Info",
        
        [switch]$UseLocal
    )
    if((!$UseLocal) -and $Level -ne "Success"){
        Write-Log -Path "$Path" -Message $Message -Level $Level;
    } else {
        $ColorMap = @{"Success"="Green";"Error"="Red";"Warn"="Yellow"};
        $FontColor = "White";
        If($ColorMap.ContainsKey($Level)){
            $FontColor = $ColorMap[$Level];
        }
        $DateNow = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        #$DateNow = (Date).ToString("yyyy-mm-dd hh:mm:ss");
        Add-Content -Path $Path -Value ("$DateNow     ($Level)     $Message")
        Write-Host "$MethodName::$Level`t$Message" -ForegroundColor $FontColor;
    }
}

Function Main {

    If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
    {
        # Relaunch as an elevated process:
        Start-Process powershell.exe "-File",('"{0}"' -f $MyInvocation.MyCommand.Path) -Verb RunAs
        exit
    }

    #Initial Device Registration Checks
    Write-Log2 -Path "$logLocation" -Message "Running Initial Device Registration Checks" -Level Info
   
    $status = Get-WS1EnrollmentMode -ErrorAction SilentlyContinue

    if($status -eq $true) {
        Write-Log2 -Path "$logLocation" -Message "Device already registered. Exiting." -Level Info
        Start-Sleep -Seconds 1
        exit
    } else {
        Write-Log2 -Path "$logLocation" -Message "Device not registered with Workspace ONE. Continuing." -Level Info
        Start-Sleep -Seconds 1
    }
    

    #Test connectivity to destination server, if available, then proceed with unenrol and enrol
    Write-Log2 -Path "$logLocation" -Message "Checking connectivity to Destination Server" -Level Info
    Start-Sleep -Seconds 1
    $connectionStatus = Test-NetConnection -ComputerName $SERVER -Port 443 -InformationLevel Quiet -ErrorAction Stop

    if($connectionStatus -eq $true) {
        Write-Log2 -Path "$logLocation" -Message "Running Device Migration in the background" -Level Info
        Invoke-Registration
    } else {
        Write-Log2 -Path "$logLocation" -Message "Not connected to Wifi, showing UI notification to continue once reconnected" -Level Info
        Start-Sleep -Seconds 1
    }


}

Main
