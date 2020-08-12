<#
.Synopsis
  This Powershell script enrols a device into WS1 UEM environment using username and password prompted from user
  then installs WS1 HUB app
  Mike Nelson / Phil Helmling
.DESCRIPTION
   
.EXAMPLE
  .\alibabaenrolment.ps1
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

# Script Vars
$DestinationURL = "ENROLLMENT_URL"
$DestinationOGName = "ENROLLMENT_OG_ID"
$AWAGENTLOGPATH = "C:\Temp"
###############
#GATHER USERNAME AND PASSWORD BY PROMPTING
$Username = "PROMPTED_USERNAME"
$Password = "PROMPTED_PASSWORD"

$Global:ProgressPreference = 'SilentlyContinue'

<# This form was created using POSHGUI.com  a free online gui designer for PowerShell
.NAME
    Untitled
#>

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
    Write-Host "Enrolling device into $DestinationURL"

    Try
	{
		Start-Process msiexec.exe -Wait -ArgumentList "/i AirwatchAgent.msi /quiet ENROLL=Y IMAGE=N SERVER=$DestinationURL LGNAME=$DestinationOGName USERNAME=$Username PASSWORD=$Password ASSIGNTOLOGGEDINUSER=Y /log $AWAGENTLOGPATH\AWAgent.log"
	}
	catch
	{
		Write-host $_.Exception
	}
}

Function Continue-Enrolment {

    Write-Host "Resuming Enrollment Process"
    $StatusMessageLabel.Text = "Resuming Enrollment Process"
    Start-Sleep -Seconds 1

    $ContinueButton.Enabled = $false

    Enroll-Device

    $enrolled = $false

    while($enrolled -eq $false) {
        $status = Get-EnrollmentStatus
        if($status -eq $true) {
            $enrolled = $status
            Write-Host "Device Enrollment is complete"
            $StatusMessageLabel.Text = "Device Enrollmentis complete"
            $ContinueButton.Visible = $false
            $CloseButton.Visible = $true
            $CloseButton.Enabled = $true
        } else {
            Write-Host "Waiting for enrollment to complete"
            $StatusMessageLabel.Text = "Waiting for enrollment to complete"
            Start-Sleep -Seconds 10
        }

        
    }
}

Function Install-HubApp {
    Write-Host "Installing WS1 Hub App"
    #$current_path
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
            Write-host $_.Exception
        }
    } else {
        Write-Host "Can't find WS1 Hub App to install it"
    }
    
}
Function Enrolment {
    $StartButton.Enabled = $false
    Write-Host "Beginning Enrolment Process"
    $StatusMessageLabel.Text = "Beginning Enrolment Process"
    Start-Sleep -Seconds 1

    # If they passed the verbose arg, set the global var
    if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) {
      $global:isVerbose = $true
    }


    # Once not enrolled - Run enrollment script.
    Write-Host "Checking connectivity to Destination Server"
    $StatusMessageLabel.Text = "Checking connectivity to Destination Server"
    Start-Sleep -Seconds 1
    $connectionStatus = Test-Connection -ComputerName $DestinationURL -Quiet
     
    if($connectionStatus -eq $true) 
    {
        Write-Host "Device has connectivity to the Destination Server"
        $StatusMessageLabel.Text = "Device has connectivity to the New Environment"
        
        Write-Host "Running Enrollment process"
        $StatusMessageLabel.Text = "Running Enrollment process"
        Start-Sleep -Seconds 1
        Enroll-Device

        $enrolled = $false

        while($enrolled -eq $false) {
            $status = Get-EnrollmentStatus
            if($status -eq $true) {
                $enrolled = $status
                Write-Host "Device Enrollment is complete"
                $StatusMessageLabel.Text = "Device Enrollment is complete"
                Start-Sleep -Seconds 1
            } else {
                Write-Host "Waiting for enrollment to complete"
                $StatusMessageLabel.Text = "Waiting for enrollment to complete"
                Start-Sleep -Seconds 10
            }
        }

        Write-Host "Running WS1 Hub App Install process"
        $StatusMessageLabel.Text = "Running WS1 Hub App Install process"
        Start-Sleep -Seconds 1
        Install-HubApp
        $HubAppInstalled = $false
        
        while($HubAppInstalled -eq $false) {
            $status = Get-WS1HubAppStatus
            if($status -eq $true) {
                $HubAppInstalled = $status
                Write-Host "WS1 Hub App Install is complete"
                $StatusMessageLabel.Text = "WS1 Hub App Install is complete"
                Start-Sleep -Seconds 1
                $StartButton.Visible = $false
                $ContinueButton.Visible = $false
                $CloseButton.Visible = $true
                $CloseButton.Enabled = $true
            } else {
                Write-Host "Waiting for WS1 Hub App Install to complete"
                $StatusMessageLabel.Text = "Waiting for WS1 Hub App Install to complete"
                Start-Sleep -Seconds 10
            }
        }
    } else 
    {
        Write-Host "Not connected to Wifi, showing UI notification to continue once reconnected"
        $StatusMessageLabel.Text = "Device cannot reach the new environment, please check network connectivity"
        Start-Sleep -Seconds 1
        # Update UI to have enrollment continue button
        $StartButton.Visible = $false
        $ContinueButton.Visible = $true
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
        Write-Host "Running enrolment in the background"
        Enrolment
    } else {        
        Write-Host "Showing UI flow"
        $Form.ShowDialog()
    }
}

Main