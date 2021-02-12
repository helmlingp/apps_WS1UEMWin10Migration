<#
.Synopsis
    This Powershell script:
    1. Backup the DeploymentManifestXML registry key for each WS1 UEM deployed application
    2. Uninstalls the Airwatch Agent which unenrols a device from the current WS1 UEM instance
    3. Installs AirwatchAgent.msi from current directory in staging enrolment flow to the target WS1 UEM instance using username and password
 .NOTES
    Created:   	    January, 2021
    Created by:	    Phil Helmling, @philhelmling
    Organization:   VMware, Inc.
    Filename:       WS1Win10Migration.ps1
    GitHub:         https://github.com/helmlingp/apps_WS1UEMWin10Migration
.DESCRIPTION
    Unenrols and then enrols a Windows 10 device into a new instance whilst preserving all WS1 UEM managed applications 
    from being uninstalled upon unenrol.
    Requires AirWatchAgent.msi in the current folder

.EXAMPLE
  .\WS1Win10Migration.ps1 -username USERNAME -password PASSWORD -Server DESTINATION_SERVER_URL -OGName DESTINATION_OG_NAME
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

#Enable Debug Logging, not needed if api-debug.config found
$Debug = $true;
#Run in background or display GUI
$silent = $true;

$current_path = $PSScriptRoot;
if($PSScriptRoot -eq ""){
    #PSScriptRoot only popuates if the script is being run.  Default to default location if empty
    $current_path = "C:\Temp";
} 
$DateNow = Get-Date -Format "yyyyMMdd_hhmm";
$pathfile = "$current_path\WS1W10Migration_$DateNow";
$Script:logLocation = "$pathfile.log";
$Script:Path = $logLocation;
if($Debug){
  write-host "Path: $Path"
  write-host "LogLocation: $LogLocation"
}

$Global:ProgressPreference = 'SilentlyContinue'
Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()

$Form                            = New-Object system.Windows.Forms.Form
$Form.ClientSize                 = '615,266'
$Form.text                       = "Workspace ONE Windows 10 Device Migration Utility"
$Form.TopMost                    = $false

$Status_Label                    = New-Object system.Windows.Forms.Label
$Status_Label.text               = "Enrolment Status"
$Status_Label.AutoSize           = $true
$Status_Label.width              = 240
$Status_Label.height             = 10
$Status_Label.Anchor             = 'top,right,left'
$Status_Label.location           = New-Object System.Drawing.Point(260,53)
$Status_Label.Font               = 'Microsoft Sans Serif,10'

$StartButton                     = New-Object system.Windows.Forms.Button
$StartButton.text                = "Start Migration"
$StartButton.width               = 113
$StartButton.height              = 30
$StartButton.location            = New-Object System.Drawing.Point(485,217)
$StartButton.Font                = 'Microsoft Sans Serif,10'

$ContinueButton                  = New-Object system.Windows.Forms.Button
$ContinueButton.Text             = "Continue"
$ContinueButton.Width            = 113
$ContinueButton.Height           = 30
$ContinueButton.Location         = New-Object System.Drawing.Point(485,217)
$ContinueButton.Font             = 'Microsoft Sans Serif,10'

$CloseButton                     = New-Object system.Windows.Forms.Button
$CloseButton.text                = "Complete"
$CloseButton.width               = 113
$CloseButton.height              = 30
$CloseButton.visible             = $false
$CloseButton.enabled             = $false
$CloseButton.location            = New-Object System.Drawing.Point(485,217)
$CloseButton.Font                = 'Microsoft Sans Serif,10'

$StatusMessageLabel              = New-Object system.Windows.Forms.Label
$StatusMessageLabel.AutoSize     = $true
$StatusMessageLabel.width        = 25
$StatusMessageLabel.height       = 10
$StatusMessageLabel.AutoSize     = $true
$StatusMessageLabel.TextAlign    = 1
$StatusMessageLabel.location     = New-Object System.Drawing.Point(200,87)
$StatusMessageLabel.Font         = 'Microsoft Sans Serif,10'

$Form.controls.AddRange(@($Status_Label,$StartButton,$CloseButton,$StatusMessageLabel,$ContinueButton))

$CloseButton.Add_Click({ $Form.Close() })
$StartButton.Add_Click({ Invoke-Migration })
$ContinueButton.Add_Click({ Invoke-ContinueMigration })

function Remove-Agent {
    #Uninstall Agent - requires manual delete of device object in console
    $b = Get-WmiObject -Class win32_product -Filter "Name like 'Workspace ONE Intelligent%'"
    $b.Uninstall()

    #uninstall WS1 App
    Get-AppxPackage *AirWatchLLC* | Remove-AppxPackage
    
<#     #Delte reg keys
    Write-Log "Syncing oma-dm to ensure that it breaks mdm relationship after hub removal"
	$GUID = (Get-Item -Path "HKLM:SOFTWARE\Microsoft\Provisioning\OMADM\Accounts\*" -ErrorAction SilentlyContinue).PSChildname
	Start-Process "$ENV:windir\system32\DeviceEnroller.exe" -arg "/o $GUID /c"
	write-log "Wait 5 min for OMA-DM Un-enrollment to complete"
    Start-Sleep 300
    
    Remove-Item -Path HKLM:\SOFTWARE\Airwatch\* -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path HKLM:\SOFTWARE\AirwatchMDM\* -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path HKLM:\SOFTWARE\Microsoft\EnterpriseResourceManager\Tracked\* -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path HKLM:\SOFTWARE\Microsoft\Enrollments\* -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path HKLM:\SOFTWARE\Microsoft\Provisioning\omadm\Accounts\* -Recurse -Force -ErrorAction SilentlyContinue
    # may not work ;)
    Remove-Item -Path HKLM:\SOFTWARE\Microsoft\EnterpriseDesktopAppManagement\*\MSI\* -Recurse -Force -ErrorAction SilentlyContinue
    
    #Delete folders
    $path = "$env:ProgramData\AirWatch\UnifiedAgent\Logs\"
    Get-ChildItem $path | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

    #delete certificates
    $Certs = get-childitem cert:"CurrentUser" -Recurse
    $AirwatchCert = $certs | Where-Object {$_.Issuer -eq "CN=AirWatchCa"}
    foreach ($Cert in $AirwatchCert) {
        $cert | Remove-Item -Force -ErrorAction SilentlyContinue
    }
    
    $AirwatchCert = $certs | Where-Object {$_.Subject -like "*AwDeviceRoot*"}
    foreach ($Cert in $AirwatchCert) {
        $cert | Remove-Item -Force -ErrorAction SilentlyContinue
    } #>
}

function Get-EnrollmentStatus {
    $output = $true;

    $OMADMPath = "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts\*"
    $Account = (Get-ItemProperty -Path $OMADMPath -ErrorAction SilentlyContinue).PSChildname

    $EnrollmentPath = "HKLM:\SOFTWARE\Microsoft\Enrollments\$Account"
    $EnrollmentUPN = (Get-ItemProperty -Path $EnrollmentPath -ErrorAction SilentlyContinue).UPN

    if($null -eq $EnrollmentUPN) {
        $output = $false
    }

    return $output
}

function Backup-DeploymentManifestXML {

    $appmsnifestpath = "HKLM:\SOFTWARE\AirWatchMDM\AppDeploymentAgent\AppManifests"
    $Apps = (Get-ItemProperty -Path $appmsnifestpath -ErrorAction SilentlyContinue).PSChildname

    foreach ($App in $Apps){
        $apppath = $appmsnifestpath + "\" + $App

        Rename-ItemProperty -Path $apppath -Name "DeploymentManifestXML" -NewName "DeploymentManifestXML_BAK"
        New-ItemProperty -Path $apppath -Name "DeploymentManifestXML"
    }
}

function Backup-Recovery {
    $path = 'C:\Recovery\OEM'
    if($path){
        Copy-Item -Path $path -Destination "$path.bak" -Recurse -Force
    }
}

function disable-notifications
{
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

function enable-notifications
{
    Remove-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.DeviceEnrollmentActivity" -Name "Enabled" -ErrorAction SilentlyContinue -Force

    Remove-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\AirWatchLLC.WorkspaceONEIntelligentHub_htcwkw4rx2gx4!App" -Name "Enabled" -ErrorAction SilentlyContinue -Force

    Remove-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\com.airwatch.windowsprotectionagent" -Name "Enabled" -ErrorAction SilentlyContinue -Force

    Remove-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Workspace ONE Intelligent Hub" -Name "Enabled" -ErrorAction SilentlyContinue -Force

    Write-Log2 -Path "$logLocation" -Message "Toast Notifications for DeviceEnrollmentActivity, WS1 iHub, Protection Agent, and Hub App enabled" -Level Info
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

Function Invoke-ContinueMigration {

    Write-Log2 -Path "$logLocation" -Message "Resuming Enrollment Process" -Level Info
    $StatusMessageLabel.Text = "Resuming Enrollment Process"
    Start-Sleep -Seconds 1

    $ContinueButton.Enabled = $false

    Invoke-EnrollDevice

    $enrolled = $false

    while($enrolled -eq $false) {
        $status = Get-EnrollmentStatus
        if($status -eq $true) {
            $enrolled = $status
            Write-Log2 -Path "$logLocation" -Message "Device Enrollment is complete" -Level Info
            $StatusMessageLabel.Text = "Device Enrollmentis complete"
            $ContinueButton.Visible = $false
            $CloseButton.Visible = $true
            $CloseButton.Enabled = $true

            # Enable Toast notifications
            enable-notifications
        } else {
            Write-Log2 -Path "$logLocation" -Message "Waiting for enrollment to complete" -Level Info
            $StatusMessageLabel.Text = "Waiting for enrollment to complete"
            Start-Sleep -Seconds 10
        }

        
    }
}

Function TestIsPendingReboot{

    $VerbosePreference = $using:VerbosePreference
    function Test-RegistryKey {
        [OutputType('bool')]
        [CmdletBinding()]
        param
        (
            [Parameter(Mandatory)]
            [ValidateNotNullOrEmpty()]
            [string]$Key
        )
    
        $ErrorActionPreference = 'Stop'

        if (Get-Item -Path $Key -ErrorAction Ignore) {
            $true
        }
    }

    function Test-RegistryValue {
        [OutputType('bool')]
        [CmdletBinding()]
        param
        (
            [Parameter(Mandatory)]
            [ValidateNotNullOrEmpty()]
            [string]$Key,

            [Parameter(Mandatory)]
            [ValidateNotNullOrEmpty()]
            [string]$Value
        )
    
        $ErrorActionPreference = 'Stop'

        if (Get-ItemProperty -Path $Key -Name $Value -ErrorAction Ignore) {
            $true
        }
    }

    function Test-RegistryValueNotNull {
        [OutputType('bool')]
        [CmdletBinding()]
        param
        (
            [Parameter(Mandatory)]
            [ValidateNotNullOrEmpty()]
            [string]$Key,

            [Parameter(Mandatory)]
            [ValidateNotNullOrEmpty()]
            [string]$Value
        )
    
        $ErrorActionPreference = 'Stop'

        if (($regVal = Get-ItemProperty -Path $Key -Name $Value -ErrorAction Ignore) -and $regVal.($Value)) {
            $true
        }
    }

    # Added "test-path" to each test that did not leverage a custom function from above since
    # an exception is thrown when Get-ItemProperty or Get-ChildItem are passed a nonexistant key path
    $tests = @(
        { Test-RegistryKey -Key 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending' }
        { Test-RegistryKey -Key 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootInProgress' }
        { Test-RegistryKey -Key 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired' }
        { Test-RegistryKey -Key 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\PackagesPending' }
        { Test-RegistryKey -Key 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\PostRebootReporting' }
        { Test-RegistryValueNotNull -Key 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Value 'PendingFileRenameOperations' }
        { Test-RegistryValueNotNull -Key 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Value 'PendingFileRenameOperations2' }
        { 
            # Added test to check first if key exists, using "ErrorAction ignore" will incorrectly return $true
            'HKLM:\SOFTWARE\Microsoft\Updates' | Where-Object { test-path $_ -PathType Container } | ForEach-Object {            
                (Get-ItemProperty -Path $_ -Name 'UpdateExeVolatile' | Select-Object -ExpandProperty UpdateExeVolatile) -ne 0 
            }
        }
        { Test-RegistryValue -Key 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' -Value 'DVDRebootSignal' }
        { Test-RegistryKey -Key 'HKLM:\SOFTWARE\Microsoft\ServerManager\CurrentRebootAttemps' }
        { Test-RegistryValue -Key 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon' -Value 'JoinDomain' }
        { Test-RegistryValue -Key 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon' -Value 'AvoidSpnSet' }
        {
            # Added test to check first if keys exists, if not each group will return $Null
            # May need to evaluate what it means if one or both of these keys do not exist
            ( 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName' | Where-Object { test-path $_ } | %{ (Get-ItemProperty -Path $_ ).ComputerName } ) -ne 
            ( 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName' | Where-Object { Test-Path $_ } | %{ (Get-ItemProperty -Path $_ ).ComputerName } )
        }
        {
            # Added test to check first if key exists
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Services\Pending' | Where-Object { 
                (Test-Path $_) -and (Get-ChildItem -Path $_) } | ForEach-Object { $true }
        }
    )

    foreach ($test in $tests) {
        Write-Verbose "Running scriptblock: [$($test.ToString())]"
        if (& $test) {
            $true
            break
        }
    }

    if (-not ($output.IsPendingReboot = Invoke-Command -Session $psRemotingSession -ScriptBlock $scriptBlock)) {
        $output.IsPendingReboot = $false
    }
}

Function Invoke-Migration {
    $StartButton.Enabled = $false
    Write-Log2 -Path "$logLocation" -Message "Beginning Migration Process" -Level Info
    $StatusMessageLabel.Text = "Beginning Migration Process"
    Start-Sleep -Seconds 1

    # If they passed the verbose arg, set the global var
    if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) {
        $global:isVerbose = $true
    }

    # Disable Toast notifications
    disable-notifications

    # Check Enrollment Status
    $enrolled = Get-EnrollmentStatus
    Write-Log2 -Path "$logLocation" -Message "Checking Device Enrollment Status" -Level Info
    $StatusMessageLabel.Text = "Checking Device Enrollment Status"
    Start-Sleep -Seconds 1
    if($enrolled) {
        Write-Log2 -Path "$logLocation" -Message "Device is enrolled" -Level Info
        $StatusMessageLabel.Text = "Device is enrolled"
        Start-Sleep -Seconds 1

        # Keep Managed Applications by removing MDM Uninstall String
        Backup-DeploymentManifestXML

        # Backup the C:\Recovery\OEM folder
        Backup-Recovery

        #Uninstalls the Airwatch Agent which unenrols a device from the current WS1 UEM instance
        $StatusMessageLabel.Text = "Removing Intelligent Hub to Initiate Device Side Unenrol"
        Start-Sleep -Seconds 1
        Remove-Agent
        
        # Sleep for 10 seconds before checking
        Start-Sleep -Seconds 10
        Write-Log2 -Path "$logLocation" -Message "Checking Enrollment Status" -Level Info
        $StatusMessageLabel.Text = "Checking Enrollment Status"
        Start-Sleep -Seconds 1
        # Wait till complete
        while($enrolled) { 
            $status = Get-EnrollmentStatus
            if($status -eq $false) {
                Write-Log2 -Path "$logLocation" -Message "Device is no longer enrolled into the Source environment" -Level Info
                $StatusMessageLabel.Text = "Device is no longer enrolled into the Source environment"
                Start-Sleep -Seconds 1
                $enrolled = $false
            }
            Start-Sleep -Seconds 5
        }

    }

    # Once not enrolled, enrol using Staging flow.
    Write-Log2 -Path "$logLocation" -Message "Running Enrollment process" -Level Info
    $StatusMessageLabel.Text = "Running Enrollment process"
    Start-Sleep -Seconds 1
    Invoke-EnrollDevice

    $enrolled = $false

    while($enrolled -eq $false) {
        $status = Get-EnrollmentStatus
        if($status -eq $true) {
            $enrolled = $status
            Write-Log2 -Path "$logLocation" -Message "Device Enrollment is complete" -Level Info
            $StatusMessageLabel.Text = "Device Enrollment is complete"
            Start-Sleep -Seconds 1
            $StartButton.Visible = $false
            $ContinueButton.Visible = $false
            $CloseButton.Visible = $true
            $CloseButton.Enabled = $true

            # Enable Toast notifications
            enable-notifications
        } else {
            Write-Log2 -Path "$logLocation" -Message "Waiting for enrollment to complete" -Level Info
            $StatusMessageLabel.Text = "Waiting for enrollment to complete"
            Start-Sleep -Seconds 10
        }
    }

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

    #Test connectivity to destination server, if available, then proceed with unenrol and enrol
    Write-Log2 -Path "$logLocation" -Message "Checking connectivity to Destination Server" -Level Info
    $StatusMessageLabel.Text = "Checking connectivity to Destination Server"
    Start-Sleep -Seconds 1
    #$connectionStatus = Test-Connection -ComputerName $SERVER -Quiet
    $connectionStatus = Test-NetConnection -ComputerName $SERVER -Port 443 -InformationLevel Quiet -ErrorAction Stop

    if($connectionStatus -eq $true) {
        if($silent) {
            Write-Log2 -Path "$logLocation" -Message "Running Device Migration in the background" -Level Info
            Invoke-Migration
        } else {        
            Write-Log2 -Path "$logLocation" -Message "Running Device Migration in the Foreground" -Level Info
            $Form.ShowDialog()
        }
    } else {
        Write-Log2 -Path "$logLocation" -Message "Not connected to Wifi, showing UI notification to continue once reconnected" -Level Info
        $StatusMessageLabel.Text = "Device cannot reach the new environment, please check network connectivity"
        Start-Sleep -Seconds 1
        # Update UI to have enrollment continue button
        $StartButton.Visible = $false
        $ContinueButton.Visible = $true
    }


}

Main