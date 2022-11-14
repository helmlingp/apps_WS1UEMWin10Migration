<#
  .Synopsis
    This powershell script copies downloads or copies AirwatchAgent.msi files to a C:\Recovery\OEM subfolder, creates a Scheduled Task and a script to be run by the Scheduled Task to migrate a device to WS1 from another WS1 instance
  .NOTES
    Created:   	    October, 2022
    Created by:	    Phil Helmling, @philhelmling
    Organization:   VMware, Inc.
    Filename:       WS1toWS1Win10Migration.ps1
    Updated:        July, 2022
    Github:         https://github.com/helmlingp/apps_WS1UEMWin10Migration
  .DESCRIPTION
    Unenrols and then enrols a Windows 10+ device into a new instance whilst preserving all WS1 UEM managed applications from being uninstalled upon unenrolment.
    Maintains Azure AD join status. Does not delete device records from Intune.
    
    This Powershell script:
    1. Backs up the DeploymentManifestXML registry key for each WS1 UEM deployed application
    2. Uninstalls the Airwatch Agent which unenrols a device from the current WS1 UEM instance
    3. Installs AirwatchAgent.msi from current directory in staging enrolment flow to the target WS1 UEM instance using username and password

  .REQUIREMENTS
    Requires AirWatchAgent.msi in the current folder or specify the -Download switch
    Goto https://getwsone.com to download or goto https://<DS_FQDN>/agents/ProtectionAgent_AutoSeed/AirwatchAgent.msi to download it, substituting <DS_FQDN> with the FQDN for the Device Services Server.
    
    Note: to ensure the device stays encrypted if using an Encryption Profile, ensure “Keep System Encrypted at All Times” is enabled/ticked
  .EXAMPLE
    .\WS1toWS1Win10Migration.ps1 -username USERNAME -password PASSWORD -Server DESTINATION_SERVER_FQDN -OGName DESTINATION_GROUPID -Download
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
if($IsMacOS -or $IsLinux){$delimiter = "/"}else{$delimiter = "\"}
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
        #$T = New-ScheduledTaskTrigger -Once -RandomDelay "00:05" -At $DateTime
        $T = New-ScheduledTaskTrigger -AtLogOn -RandomDelay 60
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
      This powershell script copies downloads or copies AirwatchAgent.msi files to a C:\Recovery\OEM subfolder, creates a Scheduled Task and a script to be run by the Scheduled Task to migrate a device to WS1 from another WS1 instance
    .NOTES
      Created:   	    January, 2022
      Created by:	    Phil Helmling, @philhelmling
      Organization:   VMware, Inc.
      Filename:       WS1toWS1Win10Migration.ps1
      Updated:        October, 2022
      Github:         https://github.com/helmlingp/apps_WS1UEMWin10Migration
    .DESCRIPTION
      Unenrols and then enrols a Windows 10+ device into a new instance whilst preserving all WS1 UEM managed applications from being uninstalled upon unenrolment.
      Maintains Azure AD join status. Does not delete device records from Intune.
      
      This Powershell script:
      1. Backs up the DeploymentManifestXML registry key for each WS1 UEM deployed application
      2. Uninstalls the Airwatch Agent which unenrols a device from the current WS1 UEM instance
      3. Installs AirwatchAgent.msi from C:\Recovery\OEM directory in staging enrolment flow to the target WS1 UEM instance using username and password
  
    .REQUIREMENTS
      Requires AirWatchAgent.msi in the C:\Recovery\OEM folder
      Goto https://getwsone.com to download or goto https://<DS_FQDN>/agents/ProtectionAgent_AutoSeed/AirwatchAgent.msi to download it, substituting <DS_FQDN> with the FQDN for the Device Services Server.
      
      Note: to ensure the device stays encrypted if using an Encryption Profile, ensure “Keep System Encrypted at All Times” is enabled/ticked
    .EXAMPLE
      .\WS1toWS1Win10Migration.ps1 -username USERNAME -password PASSWORD -Server DESTINATION_SERVER_FQDN -OGName DESTINATION_GROUPID
  #>
  param (
    [Parameter(Mandatory=$true)][string]$username=$Username,
    [Parameter(Mandatory=$true)][string]$password=$password,
    [Parameter(Mandatory=$true)][string]$OGName=$OGName,
    [Parameter(Mandatory=$true)][string]$Server=$Server
  )
  
  #Enable Debug Logging
  $Debug = $false
  
  $current_path = $PSScriptRoot;
  if($PSScriptRoot -eq ""){
      #PSScriptRoot only popuates if the script is being run.  Default to default location if empty
      $current_path = Get-Location
  } 
  if($IsMacOS -or $IsLinux){$delimiter = "/"}else{$delimiter = "\"}
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
  
  function Remove-Agent {
      #Uninstall Agent - requires manual delete of device object in console
      Write-Log2 -Path "$logLocation" -Message "Uninstalling Workspace ONE Intelligent Hub" -Level Info
      #$b = Get-WmiObject -Class win32_product -Filter "Name like 'Workspace ONE Intelligent%'"
      #$b.Uninstall()
  
      $wow64uninstallkey = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
      $uninstallkey = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
  
      $uninstallkeys = @()
      $uninstallkeys += Get-Childitem -recurse $wow64uninstallkey | Get-ItemProperty | Where-Object { ($_.DisplayName -like "VMware*" -and $_.DisplayName -ne "VMware Tools") -or $_.DisplayName -like "*Workspace ONE*"}
      $uninstallkeys += Get-Childitem -recurse $uninstallkey | Get-ItemProperty | Where-Object { ($_.DisplayName -like "VMware*" -and $_.DisplayName -ne "VMware Tools") -or $_.DisplayName -like "*Workspace ONE*"}
      
      foreach ($uninstkey in $uninstallkeys) {
        $quninst = $uninstskey.QuietUninstallString
        if ($quninst){
          if($quninst.StartsWith("msiexec.exe /I")){
            $msiarg = ($quninst).substring(14)
            Start-Process msiexec.exe -ArgumentList "/X";$msiarg
          } else {
              Start-Process cmd.exe -ArgumentList "/c";$quninst
          }
        } 
        if (!$quninst){
          $uninstallstring = $uninstkey.UninstallString
          $msiarg = ($uninstallstring).substring(14)
            Start-Process msiexec.exe -ArgumentList "/X";$msiarg
        }
      }
  
      #uninstall WS1 App
      Write-Log2 -Path "$logLocation" -Message "Uninstalling Workspace ONE Intelligent Hub APPX" -Level Info
      $appxpackages = Get-AppxPackage -AllUsers -Name "*AirwatchLLC*"
      foreach ($appx in $appxpackages){
          Remove-AppxPackage -AllUsers -Package $appx.PackageFullName -Confirm:$false
      }
  
      #Cleanup residual registry keys
      Write-Log2 -Path "$logLocation" -Message "Delete residual registry keys" -Level Info
      Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\AirWatch" -Recurse -Force -ErrorAction SilentlyContinue
      Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\AirWatchMDM" -Recurse -Force -ErrorAction SilentlyContinue
  
      #delete certificates
      $Certs = get-childitem cert:"CurrentUser" -Recurse | Where-Object {$_.Issuer -eq "CN=AirWatchCa" -or $_.Issuer -eq "VMware Issuing" -or $_.Subject -like "*AwDeviceRoot*"}
      foreach ($Cert in $Certs) {
          $cert | Remove-Item -Force -ErrorAction SilentlyContinue
      } 
  }
  
  function Backup-DeploymentManifestXML {
  
      $appmanifestpath = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\AirWatchMDM\AppDeploymentAgent\AppManifests"
      $appmanifestsearchpath = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\AirWatchMDM\AppDeploymentAgent\AppManifests\*"
      $Apps = (Get-ItemProperty -Path "$appmanifestsearchpath" -ErrorAction SilentlyContinue).PSChildname
  
      foreach ($App in $Apps){
          $apppath = $appmanifestpath + "\" + $App
          Rename-ItemProperty -Path $apppath -Name "DeploymentManifestXML" -NewName "DeploymentManifestXML_BAK"
          New-ItemProperty -Path $apppath -Name "DeploymentManifestXML"
      }
  }
  
  function Backup-Recovery {
      $OEM = 'C:\Recovery\OEM'
      $AUTOAPPLY = 'C:\Recovery\AutoApply'
      $Customizations = 'C:\Recovery\Customizations'
      if($OEM){
          Copy-Item -Path $OEM -Destination "$OEM.bak" -Recurse -Force
      }
      if($AUTOAPPLY){
          Copy-Item -Path $AUTOAPPLY -Destination "$AUTOAPPLY.bak" -Recurse -Force
      }
      if($Customizations){
          Copy-Item -Path $Customizations -Destination "$Customizations.bak" -Recurse -Force
      }
  }
  
  function Restore-Recovery {
      $OEM = 'C:\Recovery\OEM'
      $AUTOAPPLY = 'C:\Recovery\AutoApply'
      $Customizations = 'C:\Recovery\Customizations'
      #$AirwatchAgentfile = "unattend.xml"
      $unattend = Get-ChildItem -Path $OEM -Include $unattendfile -Recurse -ErrorAction SilentlyContinue
      $PPKG = Get-ChildItem -Path $Customizations -Include *.ppkg* -Recurse -ErrorAction SilentlyContinue
      $PPKGfile = $PPKG.Name
      $AirwatchAgent = Get-ChildItem -Path $current_path -Include *AirwatchAgent.msi* -Recurse -ErrorAction SilentlyContinue
      $AirwatchAgentfile = $AirwatchAgent.Name
  
      if($unattend){
          Copy-Item -Path 
          Copy-TargetResource -Path "$AUTOAPPLY.bak" -File $AirwatchAgentfile -FiletoCopy $unattend
      }
      if($PPKG){
          Copy-TargetResource -Path "$Customizations.bak" -File $PPKGfile -FiletoCopy $PPKG
      }
      if($AirwatchAgent){
          Copy-TargetResource -Path $current_path -File $AirwatchAgentfile -FiletoCopy $AirwatchAgentfile
      }
  }
  
  function enable-notifications {
      Remove-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.DeviceEnrollmentActivity" -Name "Enabled" -ErrorAction SilentlyContinue -Force
  
      Remove-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\AirWatchLLC.WorkspaceONEIntelligentHub_htcwkw4rx2gx4!App" -Name "Enabled" -ErrorAction SilentlyContinue -Force
  
      Remove-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\com.airwatch.windowsprotectionagent" -Name "Enabled" -ErrorAction SilentlyContinue -Force
  
      Remove-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Workspace ONE Intelligent Hub" -Name "Enabled" -ErrorAction SilentlyContinue -Force
  
      Write-Log2 -Path "$logLocation" -Message "Toast Notifications for DeviceEnrollmentActivity, WS1 iHub, Protection Agent, and Hub App enabled" -Level Info
  }
  
  function Invoke-Cleanup {
      $OEMbak = Get-Item  -Path "C:\Recovery\OEM.bak"
      $AUTOAPPLYbak = Get-Item  -Path "C:\Recovery\AutoApply.bak"
      $Customizationsbak = Get-Item  -Path "C:\Recovery\Customizations.bak"
      if($OEMbak){
          Remove-Item -Path $OEMbak -Recurse -Force
      }
      if($AUTOAPPLYbak){
          Remove-Item -Path $AUTOAPPLYbak -Recurse -Force
      }
      if($Customizationsbak){
          Remove-Item -Path $Customizationsbak -Recurse -Force
      }
      
      $appmanifestpath = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\AirWatchMDM\AppDeploymentAgent\AppManifests"
      $appmanifestsearchpath = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\AirWatchMDM\AppDeploymentAgent\AppManifests\*"
      $Apps = (Get-ItemProperty -Path "$appmanifestsearchpath" -ErrorAction SilentlyContinue).PSChildname
  
      foreach ($App in $Apps){
          $apppath = $appmanifestpath + "\" + $App
          Remove-ItemProperty -Path $apppath -Name "DeploymentManifestXML_BAK"
      }
  
      #Remove Task that started the migration
      Unregister-ScheduledTask -TaskName "$scriptBaseName" -Confirm:$false
      #Remove folder containing scripts and agent file
      #Remove-Item -Path $current_path -Recurse -Force
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
  
  function Invoke-EnrollDevice {
      Write-Log2 -Path "$logLocation" -Message "Enrolling device into $SERVER" -Level Info
      Try
      {
          Start-Process msiexec.exe -ArgumentList "/i","$agentpath\$agent","/qn","ENROLL=Y","DOWNLOADWSBUNDLE=false","SERVER=$Server","LGNAME=$OGName","USERNAME=$username","PASSWORD=$password","ASSIGNTOLOGGEDINUSER=Y","/log $current_path\AWAgent.log";
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
  
      # Check Enrollment Status
      $enrolled = Get-EnrollmentStatus
      Write-Log2 -Path "$logLocation" -Message "Checking Device Enrollment Status. Unenrol if already enrolled" -Level Info
      Start-Sleep -Seconds 1
  
      if($enrolled) {
          Write-Log2 -Path "$logLocation" -Message "Device is enrolled" -Level Info
          Start-Sleep -Seconds 1
  
          # Keep Managed Applications by removing MDM Uninstall String
          Write-Log2 -Path "$logLocation" -Message "Backup AppManifest" -Level Info
          Backup-DeploymentManifestXML
  
          # Backup the C:\Recovery\OEM folder
          Write-Log2 -Path "$logLocation" -Message "Backup Recovery folder" -Level Info
          #Backup-Recovery
  
          #Uninstalls the Airwatch Agent which unenrols a device from the current WS1 UEM instance
          Start-Sleep -Seconds 1
          Write-Log2 -Path "$logLocation" -Message "Begin Unenrollment" -Level Info
          Remove-Agent
          
          # Sleep for 10 seconds before checking
          Start-Sleep -Seconds 10
          Write-Log2 -Path "$logLocation" -Message "Checking Enrollment Status" -Level Info
          Start-Sleep -Seconds 1
          # Wait till complete
          while($enrolled) { 
              $status = Get-EnrollmentStatus
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
          
          $status = Get-EnrollmentStatus
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
      Write-Log2 -Path "$logLocation" -Message "Resume BitLocker" -Level Info
      Get-BitLockerVolume | Resume-BitLocker
  
      #Enable Toast notifications
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
              Start-Sleep -Seconds 10
          }
      }
      
      #Cleanup
      Write-Log2 -Path "$logLocation" -Message "Cleanup Backups" -Level Info
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
    Write-Log2 -Path "$logLocation" -Message "Setup Logging" -Level Success

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