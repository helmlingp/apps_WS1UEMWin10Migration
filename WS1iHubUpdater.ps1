<#	
  .Synopsis
    This powershell script downloads the latest Workspace ONE Intelligent Hub application (AirwatchAgent.msi) and calls the inbuilt updater
    
  .NOTES
    Created:   	  September, 2021
    Created by:	  Phil Helmling, @philhelmling
    Organization: VMware, Inc.
    Filename:     WS1iHubUpdater.ps1
    Github:       https://github.com/helmlingp/apps_WS1UEMWin10Migration
  .DESCRIPTION
    This powershell script downloads the latest Workspace ONE Intelligent Hub (AirwatchAgent.msi) and calls C:\Program Files (x86)\Airwatch\AgentUI\AW.WinPC.Updater.exe
    which updates Workspace ONE Intelligent Hub
  .REQUIREMENTS
    Deployed in SYSTEM CONTEXT as a Workspace ONE UEM Script
  .EXAMPLE
    Create a Workspace ONE UEM Script under Resources > Scripts > ADD > Windows
    Language = Powershell
    Execution Context & Privileges = SYSTEM CONTEXT
    Execution Architecture =  Auto
    Timeout = 30
#>

$agent = "C:\Program Files (x86)\Airwatch\AgentUI\Update\AirwatchAgent.msi"
$DateNow = Get-Date -Format "yyyyMMdd_hhmm";
$pathfile = "C:\Program Files (x86)\Airwatch\AgentUI\Update_$DateNow";
$logLocation = "$pathfile.log";
$Updater = "C:\Program Files (x86)\Airwatch\AgentUI\AW.WinPC.Updater.exe"

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

function Invoke-DownloadAirwatchAgent {
  try
  {
      [Net.ServicePointManager]::SecurityProtocol = 'Tls11,Tls12'
      $url = "https://packages.vmware.com/wsone/AirwatchAgent.msi"
      # alternatively download from https://<DS_FQDN>/agents/ProtectionAgent_AutoSeed/AirwatchAgent.msi
      $output = $agent
      $Response = Invoke-WebRequest -Uri $url -OutFile $output
      # This will only execute if the Invoke-WebRequest is successful.
      $StatusCode = $Response.StatusCode
  } catch {
      $StatusCode = $_.Exception.Response.StatusCode.value__
      Write-Log2 -Path "$logLocation" -Message "Failed to download AirwatchAgent.msi with StatusCode $StatusCode" -Level Info
  }
}

function Invoke-TestforUpdater {
  
  $TestforUpdater = Test-Path -Path $Updater -PathType Leaf
  if(!$TestforUpdater){
    Write-Log2 -Path $logLocation -Message "Copying AW.WinPC.Updater.exe to C:\Program Files (x86)\Airwatch\AgentUI directory" $StatusCode -Level Info
    Copy-Item -Path "C:\Program Files (x86)\Airwatch\AgentUI\Resources\AW.WinPC.Updater.exe" -Destination $Updater -Force
  }
}

function Invoke-iHubUpdate {
  Write-Log2 -Path "$logLocation" -Message "Updating Intelligent Hub" -Level Info
  $TestforiHub = Test-Path -Path $agent -PathType Leaf
  if ($TestforiHub) {
    Try
  {
    #Run AW.WinPC.Updater.exe
    Start-Process $Updater -Wait
    #call iHub UI install script as it fails to update sometimes
    #& "C:\Program Files (x86)\Airwatch\AgentUI\Resources\Hub.UI.Package\HubUI\CustomInstallPackage.ps1"
  }
  catch
  {
    Write-Log2 -Path "$logLocation" -Message $_.Exception -Level Info
  }
  }
}

function Main {
  #Download AirwatchAgent.msi if -Download switch used, otherwise requires AirwatchAgent.msi to be deployed in the ZIP.
  Invoke-DownloadAirwatchAgent

  #Test if AW.WinPC.Updater.exe exists in correct folder
  Invoke-TestforUpdater

  #Update Intelligent Hub
  Invoke-iHubUpdate
}

Main