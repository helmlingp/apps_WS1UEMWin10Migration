<#	
  .Synopsis
    This powershell script copies a script and AirwatchAgent.msi files to a C:\Recovery\OEM subfolder, creates a Scheduled Task that executes the script
  .NOTES
    Created:   	February, 2021
    Created by:	Phil Helmling, @philhelmling
    Organization: VMware, Inc.
    Filename:     DeployFiles.ps1
    Updated:      July, 2022
    Github:       https://github.com/helmlingp/apps_WS1UEMWin10Migration
  .DESCRIPTION
    This powershell script copies the specified script & AirwatchAgent.msi files to a C:\Recovery\OEM subfolder, creates a Scheduled Task that executes the script after 5 minutes
  .REQUIREMENTS
    AirwatchAgent.msi
    A script to run
  .EXAMPLE
    Install Command:      powershell.exe -ep bypass -file .\DeployFiles.ps1 -scriptname WS1Win10Migration.ps1 -username USERNAME -password PASSWORD -Server DESTINATION_SERVER_FQDN -OGName DESTINATION_GROUPID -Download

    Uninstall Command:    .

    When to Call Install Complete:    File Exists: C:\Recovery\OEM\WS1Win10Migration\WS1Win10Migration.ps1
#>
param (
  [Parameter(Mandatory=$true)]
  [string]$scriptname=$scriptname,
  [Parameter(Mandatory=$true)]
  [string]$username=$Username,
  [Parameter(Mandatory=$true)]
  [string]$password=$password,
  [Parameter(Mandatory=$true)]
  [string]$OGName=$OGName,
  [Parameter(Mandatory=$true)]
  [string]$Server=$Server,
  [switch]$Download
)

$current_path = $PSScriptRoot;
if($PSScriptRoot -eq ""){
    #PSScriptRoot only popuates if the script is being run.  Default to default location if empty
    $current_path = "C:\Temp";
}
$1 = (Get-Item "$current_path\$scriptname").BaseName
$deploypath = "C:\Recovery\OEM\$1"
#$deploypath = "$env:ProgramData\$1"
$script = "$deploypath\$scriptname"
$agent = "AirwatchAgent.msi"
$DateNow = Get-Date -Format "yyyyMMdd_hhmm";
$pathfile = "$deploypath\DeployFiles_$DateNow";
$logLocation = "$pathfile.log";

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

function Invoke-CreateTask{
    #Get Current time to set Scheduled Task to run powershell
    $DateTime = (Get-Date).AddMinutes(5).ToString("HH:mm")
    if($Download){
      $arg = "-ep Bypass -File $script -username $username -password $password -Server $Server -OGName $OGName -Download"
    }else{
      $arg = "-ep Bypass -File $script -username $username -password $password -Server $Server -OGName $OGName"
    }
    
    $TaskName = "WS1Win10Migration"
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
#Setup Logging
Write-Log2 -Path "$logLocation" -Message "DeployFiles Started" -Level Success

#Copy package files
Copy-TargetResource -Path $deploypath -File $scriptname -FiletoCopy "$current_path\$scriptname"
Write-Log2 -Path "$logLocation" -Message "Copied Script $scriptname" -Level Info
Copy-TargetResource -Path $deploypath -File $agent -FiletoCopy "$current_path\$agent"
Write-Log2 -Path "$logLocation" -Message "Copied Agent $agent" -Level Info

#Create Scheduled Task to run the main program
Invoke-CreateTask
Write-Log2 -Path "$logLocation" -Message "Created Task" -Level Info