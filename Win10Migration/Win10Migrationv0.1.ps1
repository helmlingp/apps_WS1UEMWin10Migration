<#
.Synopsis
  This Powershell script:
  1. removes the Deployment Manifest registry key for each WS1 UEM deployed application
  2. unenrols a device from the source WS1 UEM instance
  3. enrols a device into the target WS1 UEM instance using username and password prompted from user
  4. then installs WS1 HUB app
  
.DESCRIPTION
  Unenrols and then enrols a Windows 10 device into a new instance whilst preventing all WS1 UEM applications 
  from being uninstalled upon unenrol.
  Requires AirWatchAgent.msi and AirWatchLLC.VMwareWorkspaceONE folder in the current folder

.AUTHOR
Mike Nelson
Modified by Phil Helmling

.EXAMPLE
  .\Win10Migrationv0.1.ps1
  .\Win10Migrationv0.1.ps1 -username USERNAME -password PASSWORD - DestinationURL DESTINATIONURL -DestinationOGNamne DESTINATIONOGNAME
#>

[CmdletBinding()]
Param(
    [switch]$silent
    
)

$current_path = $PSScriptRoot;
if($PSScriptRoot -eq ""){
    #PSScriptRoot only popuates if the script is being run.  Default to default location if empty
    $current_path = "C:\Temp";
} 

#test for airwatchagent.msi and AirWatchLLC.VMwareWorkspaceONE folder in the current folder


#TEST IF PARAMETERS
#IF NOT PARAMETERS, THEN CALL Get-AWAPIConfiguration function to read api.config
#Enable Debug Logging, not needed if api-debug.config found
$Debug = $true;

if(Test-Path "$current_path\api-debug.config"){
    $Debug = $true;
	$useDebugConfig = $true;
	Write-Host "---------------------------------------------------------------------------"
	Write-Host "Started Win10 Device Migration"
}

#Load api.config into private scope
$Private:api_settings_obj = Get-AWAPIConfiguration -Debug $Debug

$Private:Server = $Private:api_settings_obj.ApiConfig.Server;
$Private:API_Key = $Private:api_settings_obj.ApiConfig.ApiKey;
$Private:Auth = $Private:api_settings_obj.ApiConfig.ApiAuth;
$Private:SSLThumbprint = $Private:api_settings_obj.ApiConfig.SSLThumbprint;
$Private:OrganizationGroupName = $Private:api_settings_obj.ApiConfig.OrganizationGroupName;

If($Debug){
	Write-Log2 -Path "$logLocation" -Message "Private:Server: $Private:Server" -Level Info
	Write-Log2 -Path "$logLocation" -Message "Private:API_Key: $Private:API_Key" -Level Info
	Write-Log2 -Path "$logLocation" -Message "Private:Auth: $Private:Auth" -Level Info
	Write-Log2 -Path "$logLocation" -Message "Private:SSLThumbprint: $Private:SSLThumbprint" -Level Info
	Write-Log2 -Path "$logLocation" -Message "Private:OrganizationGroupName: $Private:OrganizationGroupName" -Level Info
}


# Script Vars
$DestinationURL = "ENROLLMENT_URL"
$DestinationOGName = "ENROLLMENT_OG_ID"
###############
#GATHER USERNAME AND PASSWORD BY PROMPTING
$Username = "PROMPTED_USERNAME"
$Password = "PROMPTED_PASSWORD"

$Global:ProgressPreference = 'SilentlyContinue'

Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()

$Form                            = New-Object system.Windows.Forms.Form
$Form.ClientSize                 = '615,266'
$Form.text                       = "Device Enrolment Utility"
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
$StartButton.text                = "Start Enrolment"
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
$StartButton.Add_Click({ Enrolment })
$ContinueButton.Add_Click({ Continue-Enrolment })


function Get-AWAPIConfiguration{
	param([bool]$Debug)
	If($Debug) {
		Write-Log2 -Path "$logLocation" -Message "Get device attributes from api.config" -Level Info
		Write-Log2 -Path "$logLocation" -Message "---------------------------------------------------------------------------" -Level Info
	}
	if(Test-Path "$current_path\api-debug.config"){
		$useDebugConfig = $true;
		#$Debug = $true;
	}
	#Read api.config file and return as object
	if(!$useDebugConfig){
        $Private:api_config_file = [IO.File]::ReadAllText("$current_path\api.config");
		If ($Debug) {
			Write-Log2 -Path "$logLocation" -Message "api_config_file: $current_path\api.config" -Level Info
		}
		#Encrypt api.config if not already (test to read if 'ApiConfig' exists)
        if($Private:api_config_file.Contains('"ApiConfig"')){
            $Private:api_settings = $Private:api_config_file;
            $encrypted = ConvertTo-EncryptedFile -FileContents $Private:api_config_file;
            if($encrypted){
                Set-Content -Path ("$current_path\api.config") -Value $encrypted;
            }
        } else {
			#If already enrypted, read into ConvertFrom-EncryptedFile function to decrypt
			$Private:api_settings = ConvertFrom-EncryptedFile -FileContents $Private:api_config_file;
        }
    } else {
        If ($Debug) {
			Write-Log2 -Path "$logLocation" -Message "api_config_file: $current_path\api-debug.config" -Level Info
		}
		$Private:api_config_file = [IO.File]::ReadAllText("$current_path\api-debug.config");
        $Private:api_settings = $Private:api_config_file;
    }
    $Private:api_settings_obj = ConvertFrom-Json -InputObject $Private:api_settings
	
    $content_type = "application/json;version=1";
    $content_type_v2 = "application/json;version=2";

    return $api_settings_obj;
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

Function Get-WS1HubAppStatus {
    $output = $true;

    $WS1HubAppInstalled = Get-AppxPackage -Name "AirWatchLLC.VMwareWorkspaceONE"
    if($null -eq $WS1HubAppInstalled) {
        $output = $false
    }
}

Function Enroll-Device {
    Write-Log2 -Path "$logLocation" -Message "Enrolling device into $DestinationURL" -Level Info
    Try
	{
		Start-Process msiexec.exe -Wait -ArgumentList "/i $current_path\AirwatchAgent.msi /quiet ENROLL=Y IMAGE=N SERVER=$DestinationURL LGNAME=$DestinationOGName USERNAME=$Username PASSWORD=$Password ASSIGNTOLOGGEDINUSER=Y /log $current_path\AWAgent.log"
	}
	catch
	{
        Write-Log2 -Path "$logLocation" -Message $_.Exception -Level Info
	}
}

Function Continue-Enrolment {

    Write-Log2 -Path "$logLocation" -Message "Resuming Enrollment Process" -Level Info
    $StatusMessageLabel.Text = "Resuming Enrollment Process"
    Start-Sleep -Seconds 1

    $ContinueButton.Enabled = $false

    Enroll-Device

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
        } else {
            Write-Log2 -Path "$logLocation" -Message "Waiting for enrollment to complete" -Level Info
            $StatusMessageLabel.Text = "Waiting for enrollment to complete"
            Start-Sleep -Seconds 10
        }

        
    }
}

Function Install-HubApp {
    Write-Log2 -Path "$logLocation" -Message "Installing WS1 Hub App" -Level Info
    #not sure if need to copy, should probably download with enrolment??
    $WS1Apppath = "$current_path\AirWatchLLC.VMwareWorkspaceONE"
    $WS1AppCachepath = "C:\Program Files (x86)\Airwatch\AgentUI\Resources\Bundle\AirWatchLLC.VMwareWorkspaceONE"
    $WS1Appfile = "668f4ce67ec547f3a39a59e031b8d07b.appxbundle"
    $WS1Applicense = "668f4ce67ec547f3a39a59e031b8d07b_License1.xml"
    if(Test-Path "$WS1Apppath\$WS1Appfile"){
        #Copy to normal download path
        Copy-Item -Force -Recurse "$WS1Apppath\*" -Destination $WS1AppCachepath
        
        Try {
            Add-AppxProvisionedPackage -Online -PackagePath $WS1Apppath\$WS1Appfile -LicensePath $WS1Apppath\$WS1Applicense;
        } catch {
            Write-Log2 -Path "$logLocation" -Message $_.Exception -Level Info
        }
    } else {
        Write-Log2 -Path "$logLocation" -Message "Can't find WS1 Hub App to install it" -Level Info
    }
    
}

Function Enrolment {
    $StartButton.Enabled = $false
    Write-Log2 -Path "$logLocation" -Message "Beginning Enrolment Process" -Level Info
    $StatusMessageLabel.Text = "Beginning Enrolment Process"
    Start-Sleep -Seconds 1

    # If they passed the verbose arg, set the global var
    if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) {
      $global:isVerbose = $true
    }

    # Once not enrolled - Run enrollment script.
    Write-Log2 -Path "$logLocation" -Message "Checking connectivity to Destination Server" -Level Info
    $StatusMessageLabel.Text = "Checking connectivity to Destination Server"
    Start-Sleep -Seconds 1
    $connectionStatus = Test-Connection -ComputerName $DestinationURL -Quiet
     
    if($connectionStatus -eq $true) 
    {
        Write-Log2 -Path "$logLocation" -Message "Device has connectivity to the Destination Servers" -Level Info
        $StatusMessageLabel.Text = "Device has connectivity to the New Environment"
        
        Write-Log2 -Path "$logLocation" -Message "Running Enrollment process" -Level Info
        $StatusMessageLabel.Text = "Running Enrollment process"
        Start-Sleep -Seconds 1
        Enroll-Device

        $enrolled = $false

        while($enrolled -eq $false) {
            $status = Get-EnrollmentStatus
            if($status -eq $true) {
                $enrolled = $status
                Write-Log2 -Path "$logLocation" -Message "Device Enrollment is complete" -Level Info
                $StatusMessageLabel.Text = "Device Enrollment is complete"
                Start-Sleep -Seconds 1
            } else {
                Write-Log2 -Path "$logLocation" -Message "Waiting for enrollment to complete" -Level Info
                $StatusMessageLabel.Text = "Waiting for enrollment to complete"
                Start-Sleep -Seconds 10
            }
        }

        Write-Log2 -Path "$logLocation" -Message "Running WS1 Hub App Install process" -Level Info
        $StatusMessageLabel.Text = "Running WS1 Hub App Install process"
        Start-Sleep -Seconds 1
        Install-HubApp
        $HubAppInstalled = $false
        
        while($HubAppInstalled -eq $false) {
            $status = Get-WS1HubAppStatus
            if($status -eq $true) {
                $HubAppInstalled = $status
                Write-Log2 -Path "$logLocation" -Message "WS1 Hub App Install is complete" -Level Info
                $StatusMessageLabel.Text = "WS1 Hub App Install is complete"
                Start-Sleep -Seconds 1
                $StartButton.Visible = $false
                $ContinueButton.Visible = $false
                $CloseButton.Visible = $true
                $CloseButton.Enabled = $true
            } else {
                Write-Log2 -Path "$logLocation" -Message "Waiting for WS1 Hub App Install to complete" -Level Info
                $StatusMessageLabel.Text = "Waiting for WS1 Hub App Install to complete"
                Start-Sleep -Seconds 10
            }
        }
    } else 
    {
        Write-Log2 -Path "$logLocation" -Message "Not connected to Wifi, showing UI notification to continue once reconnected" -Level Info
        $StatusMessageLabel.Text = "Device cannot reach the new environment, please check network connectivity"
        Start-Sleep -Seconds 1
        # Update UI to have enrollment continue button
        $StartButton.Visible = $false
        $ContinueButton.Visible = $true
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
        [string]$Path='C:\temp\grppolicies\setup_logs.txt',
        
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
            Write-Verbose "Creating $Path."
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

function Write-Log2{ #Wrapper function to made code easier to read;
    [CmdletBinding()]
    Param
    (
        [string]$Message,
        [string]$Path=$logLocation,
        [Parameter(Mandatory=$false)]
        [ValidateSet("Success","Error","Warn","Info")]
        [string]$Level="Info",
        [switch]$UseLocal
    )
    if((!$UseLocal) -and $Level -ne "Success"){
        Write-Log -LogPath $Path -LogContent $Message -Level $Level;
    } else {
        $ColorMap = @{"Success"="Green";"Error"="Red";"Warn"="Yellow"};
        $FontColor = "White";
        If($ColorMap.ContainsKey($Level)){
            $FontColor = $ColorMap[$Level];
        }
        $DateNow = (Date).ToString("yyyy-mm-dd hh:mm:ss");
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

    if($silent) {
        Write-Log2 -Path "$logLocation" -Message "Running enrolment in the background" -Level Info
        Enrolment
    } else {        
        Write-Log2 -Path "$logLocation" -Message "Showing UI flow" -Level Info
        $Form.ShowDialog()
    }
}

Main