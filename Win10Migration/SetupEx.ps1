#############################################
# File: SetupEx.ps1
# Author: Chase Bradley
# Modified by: Phil Helmling 08 Aug 2019, add onUnlock Task Triggers condition for Create-Task - references "TriggerType":"onUnlock" in setup.manifest
# Setup Shared Device Module
#############################################

#Test to see if we are running from the script or if we are running from the ISE
$current_path = $PSScriptRoot;
if($PSScriptRoot -eq ""){
    #PSScriptRoot only popuates if the script is being run.  Default to default location if empty
    $current_path = "C:\Temp\Reg";
} 

if(Test-Path "$current_path\setup.manifest"){
    $setup_manifest_file = [IO.File]::ReadAllText($current_path + "\setup.manifest");
    $setup_manifest = ConvertFrom-Json -InputObject $setup_manifest_file;
    $INSTALL_FILES = $true;
}

$AccessPolicyPath = "";

function Get-ItemPropertyValueSafe{
    Param([string]$Path, [string]$Name,$DefaultVal)
    $ReturnVal = $DefaultVal
    If(Test-Path $Path){
        If(Test-ItemProperty -Path $Path -Name $Name){
            $ReturnVal = Get-ItemPropertyValue -Path $Path -Name $Name;
        }
    }
    return $ReturnVal;
}

function Test-ItemProperty{
    Param([string]$Path, [string]$Name)
    return (Get-Item -Path $Path).GetValue($Name) -ne $null;
}

function Create-AccessList{
    param([string]$ModuleRegPath="HKLM:\SOFTWARE\AirWatch\ProductProvisioning",
         [string]$InstallPath="C:\Temp\Shared",
         [array]$AccessUsers=@(),
         [array]$AccessRules=@(),
         [int]$SecurityLevel=0,
         [bool]$TestInstall=$false
         )
    $installListDefaults = New-Object -TypeName PSCustomObject -Property @{"Name"="Install";"Type"="Install";"Paths"=@();"RegKeys"=@()};
    $historyListDefaults = New-Object -TypeName PSCustomObject -Property @{"Name"="History";"Type"="History";"Paths"=@();"RegKeys"=@()};
    $systemListDefaults = New-Object -TypeName PSCustomObject -Property @{"Name"="System";"Type"="System";"Paths"=@();"RegKeys"=@()};
    $accessProperties = @{"SecurityLevel"=$SecurityLevel;"BlockList"=@($installListDefaults;$systemListDefaults);"AllowList"=@();"HistoryList"=@($historyListDefaults)};
    If($AccessUsers){
        $accessProperties.Add("AccessUsers",$AccessUsers);
    } ElseIf ($AccessRules){
        $accessProperties.Add("AccessRules",$AccessRules);
    } Else {
        $DefaultAccessLogic0 = New-Object -TypeName PSCustomObject -Property @{"Group"="Users";"Rule"= "IN"}
        $DefaultAccessLogic1 = New-Object -TypeName PSCustomObject -Property @{"User"="Administrator";"Rule"= "NOTIN"}
        $DefaultAccessProperties = @{"AccessLogic"=@($DefaultAccessLogic0,$DefaultAccessLogic1)};
        $AccessRules = @($DefaultAccessProperties);
        $accessProperties.Add("AccessRules",$AccessRules);
    }
    $accesspolicies = New-Object -TypeName PSCustomObject -Property $accessProperties;

    $convertedJson = ConvertTo-Json $accesspolicies -Depth 10;
    Set-Content "$InstallPath\accesspolicies.access" $convertedJson -WhatIf:$TestInstall;

    $AccessPolicyPath = "$InstallPath\accesspolicies.access"

    #If($InstallAccessPolicy){
    New-ItemProperty -Path $ModuleRegPath -Name "AccessPolicy" -Value "$InstallPath\accesspolicies.access" -Force -WhatIf:$TestInstall;
    return $accesspolicies;
}

Function Get-InstallerPath{
    param([string]$Path, $Dictionary)

    If($Path -match "\`$([^\\]*)"){
        $Lookup = $Matches[1];
        If($Dictionary.ContainsKey($Lookup)){
            $Path = $Path.Replace($Matches[0],$Dictionary[$Lookup]);
        }
    }
    return $Path;
}

function Add-AccessPolicyItems{
    param([string]$RegPath,
          [string]$AccessPolicyName,
          [array]$Paths=@(),
          [array]$RegKeys=@(),
          [bool]$TestInstall=$false
    )

    $AccessPolicyFile =  Get-ItemPropertyValue -Path $RegPath -Name "AccessPolicy";  
    If(Test-Path -Path $AccessPolicyFile){
        $RawData = [IO.File]::ReadAllText($AccessPolicyFile);
        $accesspolicies = ConvertFrom-Json -InputObject $RawData;
    } 

    $Policy = $accesspolicies.BlockList | where Name -eq $AccessPolicyName;
    If(($Policy | measure).Count -eq 0){
        $Policy = New-Object -TypeName PSCustomObject -Property @{"Name"="$AccessPolicyName";"Type"="System";"Paths"=@();"RegKeys"=@()};
        $accesspolicies.BlockList += $newAccessPolicy;
    }
    $Policy.Paths += $Paths;
    $Policy.RegKeys += $RegKeys;

    $convertedJson = ConvertTo-Json $accesspolicies -Depth 10;
    Set-Content $AccessPolicyFile $convertedJson -WhatIf:$TestInstall;
}

Function Invoke-HidePaths{
    param($HidePaths,$PathDictionary)

    ForEach($HidePath in $HidePaths){   
        Get-InstallerPath -Path $HidePaths -Dictionary $PathDictionary                    
        If((Test-Path $HidePath)){
            $f=get-item $HidePath -Force
            $f.attributes="Hidden"
        }
    }
}

Function Create-Paths{
    param([string]$Path, $Folders, [bool]$TestInstall)
    $Folders = @();
    $Folders += $Folders;

    $CreatePath = $Path;
    If($CreatePath -match "\`$([^\\]*)"){
    $CreatePath = $CreatePath.Replace($Matches[0],$PathInfo[$Matches[1]]);
    }
    If($ManifestItem."$ManifestAction".Folder){
        $CreatePath = $CreatePath + "\" + $ManifestItem."$ManifestAction".Folder;
        New-Item -Path $CreatePath -ItemType Directory -Force -WhatIf:$TestInstall
    } ElseIf($ManifestItem."$ManifestAction".Folders){
        ForEach($Folder In $ManifestItem."$ManifestAction".Folders){
            $NewPath = $CreatePath + "\" + $Folder;
            New-Item -Path $NewPath -ItemType Directory -Force -WhatIf:$TestInstall
        }
    }
}

function Create-Task{
    Param([string]$TaskPath, [string]$TaskName, [string]$PShellScript, [string]$Interval, [string]$TriggerType,[bool]$AutoStart=$true,[bool]$TestInstall)
    Try{
        #Validate job does not exist
        $arg = '-ExecutionPolicy Bypass -File "' + $PShellScript + '"'


        $A = New-ScheduledTaskAction -Execute "C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe" -Argument $arg 
        
        If($TriggerType -eq "onUnlock"){
            #Add Windows Unlock trigger
            $stateChangeTriggerClass = Get-CimClass -Namespace ROOT\Microsoft\Windows\TaskScheduler -ClassName MSFT_TaskSessionStateChangeTrigger
            $onUnlockTrigger = New-CimInstance  -CimClass $stateChangeTriggerClass -Property @{ StateChange = 8 } -ClientOnly

            $logonTrigger = $(New-ScheduledTaskTrigger -AtLogOn)
            $T = @(
                            $logonTrigger,
                            $onUnlockTrigger
                        )
        } else {
			$T = New-ScheduledTaskTrigger -AtLogon
		}
        $P = New-ScheduledTaskPrincipal "System" -RunLevel Highest
        $S = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -StartWhenAvailable -Priority 5
        $S.CimInstanceProperties['MultipleInstances'].Value=3
        $D = New-ScheduledTask -Action $A -Principal $P -Trigger $T -Settings $S


        If(!$TestInstall){
            Register-ScheduledTask -InputObject $D -TaskName "$TaskName" -TaskPath "$TaskPath" -Force -ErrorAction Stop
         } Else {
            Write-Host "Create scheduled task named $TaskName at $TaskPath";
         }
        
        If($Interval){
            $Task = Get-ScheduledTask -TaskName "$TaskName" -TaskPath "$TaskPath";
            $Task.Triggers[0].Repetition.Interval = $Interval;
            $Task.Triggers[0].Repetition.StopAtDurationEnd = $false;
            If(!$TestInstall){
                $Task | Set-ScheduledTask -User "NT AUTHORITY\SYSTEM";
            } Else {
                Write-Host "Save scheduled task $TaskName with interval $Interval";
            }
        }

    } Catch {
        $e = $_.Exception.Message;
        Write-Host "Error: Job creation failed.  Validate user rights.";
    }

    If($AutoStart){
        If(!$TestInstall){
            Start-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath;
        } Else {
            Write-Host "Start scheduled task $TaskName";
        }
    }
}

Function Invoke-Installation{
        Param([object]$MyModule,[bool]$TestInstall=$false,[bool]$Install=$true)

        $InstallAccessPolicy = $false;
        $ModuleName = $MyModule.Name;
        
        $ModuleRegPath = "HKLM:\Software\AirWatch\ProductProvisioning";
        If($MyModule.RegistryLocation){
            $ModuleRegPath = $MyModule.RegistryLocation  
        }
        $ModuleInstallPath = $MyModule.InstallLocation;

        $ModuleSecurityLevel = $MyModule.SecureInstall;

        $Currentversion = $MyModule.Version;
        If(Test-Path $ModuleRegPath){
            If(Test-ItemProperty -Path $ModuleRegPath -Name $ModuleName){
                $Previousversion = Get-ItemPropertyValue -Path $ModuleRegPath -Name $ModuleName;
                If([System.Version]$Previousversion -gt [System.Version]$Currentversion){
                    continue; 
                }
            }
        } Else {
            #Create the new module reg path
            New-Item -Path $ModuleRegPath -Force -WhatIf:$TestInstall;
        }

        $PathInfoString = ""
        $PathInfo = @{};
        $PropertyPaths = $MyModule.PSObject.Properties | where TypeNameOfValue -EQ "System.String";
        ForEach($PPath in $PropertyPaths){
            $PathInfo.Add($PPath.Name, $PPath.Value);
            $PathInfoString += "(" + $PPath.Name + ";" + $PPath.Value + ")";
        }
        If($TestInstall){
            Write-Host $PathInfoString
        }

        ForEach($ManifestItem in $MyModule.Manifest){
            $ManifestAction = $ManifestItem.PSObject.Properties.Name 
            If($ManifestAction -eq "CopyFiles" -or $ManifestAction -eq "MoveFiles"){
                $CopyDestination = $ManifestItem.CopyFiles.Destination;
                $CopyDestination = Get-InstallerPath -Path $CopyDestination -Dictionary $PathInfo
                
                If(!(Test-Path -Path $CopyDestination)){
                    New-Item -Path $CopyDestination -ItemType Directory -Force -WhatIf:$TestInstall;
                }
                If ($ManifestItem."$ManifestAction".From){
                    $FromFiles = (Get-ChildItem -Path $ManifestItem."$ManifestAction".From -Force | Select-Object FullName).FullName
                } ElseIf ($ManifestItem."$ManifestAction".Files) {
                    $FromFiles = $ManifestItem."$ManifestAction".Files;
                }

                ForEach($InstallFile In $FromFiles){
                    If($ManifestAction -Like "CopyFiles"){
                        Copy-Item -Path $InstallFile $CopyDestination -Force -WhatIf:$TestInstall;
                    } ElseIf($ManifestAction -Like "MoveFiles"){
                        Move-Item -Path $InstallFile $CopyDestination -Force -WhatIf:$TestInstall;
                    }
                } 
            } ElseIf ($ManifestAction -eq "DeleteFiles"){
                ForEach($Delete In $ManifestItem."$ManifestAction"){
                    $DeleteFormatted = Get-InstallerPath -Path $DeleteFormatted -Dictionary $PathInfo
                    Remove-Item -Path $Delete -Force -WhatIf:$TestInstall;
                }
            } ElseIf ($ManifestAction -eq "CreateAccessFile"){
                $AccessInstallLocation = $ManifestItem."$ManifestAction".Location,
                $AccessInstallLocation = Get-InstallerPath -Path $AccessInstallLocation -Dictionary $PathInfo

                $UserList = $ManifestItem."$ManifestAction".UserList;
                $SecurityLevel = $ManifestItem."$ManifestAction".SecurityLevel;

                $AccessRules = $ManifestItem."$ManifestAction".AccessRules;

                $InstallAccessPolicy = Create-AccessList -ModuleRegPath $ModuleRegPath -InstallPath $MyModule.InstallLocation -AccessRules $AccessRules -SecurityLevel $SecurityLevel -AccessUsers $UserList -TestInstall $TestInstall;
            } ElseIf ($ManifestAction -eq "CreatePath" -or $ManifestAction -eq "CreatePaths"){
                 $CreatePath = $ManifestItem."$ManifestAction".Path;
                 If($ManifestItem."$ManifestAction".Folder){
                    $CreateFolders = $ManifestItem."$ManifestAction".Folder;
                 } ElseIf($ManifestItem."$ManifestAction".Folders){
                    $CreateFolders = $ManifestItem."$ManifestAction".Folders;
                 }
                  Create-Paths -Path $CreatePath -Folders $CreateFolders -TestInstall $TestInstall;                               
            } ElseIf ($ManifestAction -eq "CreateRegKeys"){
                $RegKeyPath = $ModuleRegPath
                If($ManifestItem."ManifestAction".Path){
                    $RegKeyPath = $ManifestItem."ManifestAction".Path
                    $RegKeyPath = Get-InstallerPath -Path $RegKeyPath -Dictionary $PathInfo
                }
                If(!(Test-Path $RegKeyPath)){
                    New-Item -Path $RegKeyPath -Force -WhatIf:$TestInstall;
                }
                ForEach($RegKey In $ManifestItem."$ManifestAction".Keys){
                    $KeyName = ($RegKey.PSObject.Properties | Select Name).Name;
                    $KeyValue = $RegKey."$KeyName";
                    New-ItemProperty -Path $RegKeyPath -Name $KeyName -Value $KeyValue -Force -WhatIf:$TestInstall;
                }
            } ElseIf ($ManifestAction -eq "CreateTask"){
                $TaskName = $ManifestItem."$ManifestAction".Name;
                $TaskPath = $ManifestItem."$ManifestAction".Path;
                
                $PowerShellFile = Get-InstallerPath -Path $ManifestItem."$ManifestAction".PSFile -Dictionary $PathInfo;
                If($Install){
                    $TaskInterval = "";
                    If($ManifestItem."$ManifestAction".TaskInterval){
                        $TaskInterval = $ManifestItem."$ManifestAction".TaskInterval;
                    }
                    $AutoStart = $true;
                    If($ManifestItem."$ManifestAction".AutoStart){
                        If($ManifestItem."$ManifestAction".AutoStart -eq 0){
                            $AutoStart = 0;
                        }
                    }
                    $TriggerType = ""; # always create tasks with -AtLogon trigger, however you can add triggers by updating the Create-Task function. On Windows Unlock ("onUnlock") is now supported.
                    If($ManifestItem."$ManifestAction".TriggerType){
                        $TriggerType = $ManifestItem."$ManifestAction".TriggerType;
                    }
                    If(!$TaskPath){
                        $TaskPath = "\AirWatch MDM\";
                    }
                    Create-Task -TaskName $TaskName -TaskPath $TaskPath -PShellScript $PowerShellFile -Interval $TaskInterval -Trigger $TriggerType -AutoStart $AutoStart -TestInstall $TestInstall;
                } Else {
                    # If((Get-ScheduledTask | where {$_.TaskName -EQ $TaskName -and $_.TaskPath -EQ $TaskPath} | measure).Count -gt 0){
                    #     Unregister-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -WhatIf:$TestInstall;
                    # }
                }
            } ElseIf ($ManifestAction -eq "AccessRule"){
                $AccessPolicyPath =  Get-ItemPropertyValue -Path $ModuleRegPath -Name "AccessPolicy";
                $ManifestPaths = @();
                $ManifestRegKeys = @();
                If($ManifestItem."$ManifestAction".Paths){
                    $Paths = $ManifestItem."$ManifestAction".Paths | % {(Get-InstallerPath -Path $_ -Dictionary $PathInfo)}
                    $ManifestPaths += $ManifestItem."$ManifestAction".Paths;
                }
                If($ManifestItem."$ManifestAction".RegKeys){
                    $ManifestRegKeys += $ManifestItem."$ManifestAction".RegKeys;
                }
                Add-AccessPolicyItems -RegPath $ModuleRegPath -AccessPolicyName "System" -Paths $ManifestPaths -RegKeys $ManifestRegKeys;
            } ElseIf($ManifestAction -eq "HidePaths"){
                $HidePaths = @();
                If($ManifestItem."$ManifestAction".Paths){
                    $HidePaths += $ManifestItem."$ManifestAction".Paths;
                    Invoke-HidePaths -HidePaths $HidePaths -PathDictionary $PathInfo;
                }
            }
        }
        New-ItemProperty -Path $ModuleRegPath -Name "$ModuleName`IVersion" -Value $Currentversion -Force -WhatIf:$TestInstall;
        New-ItemProperty -Path $ModuleRegPath -Name "$ModuleName`IPath" -Value $ModuleInstallPath -Force -WhatIf:$TestInstall;
        Add-AccessPolicyItems -RegPath $ModuleRegPath -AccessPolicyName "Install" -Paths @($ModuleInstallPath) -RegKeys @($ModuleRegPath) -TestInstall $TestInstall;
    }



cd $current_path;

If($INSTALL_FILES){ 
    ForEach($MyModule in $setup_manifest.Modules){
        Invoke-Installation $MyModule;
    }
    If((Get-ScheduledTask | where {$_.TaskName -eq "Apply_AccessPolicies" -and 
            $_.TaskPath -eq "\AirWatch MDM\"} | measure).Count -gt 0){
        Start-ScheduledTask -TaskName "Apply_AccessPolicies" -TaskPath "\AirWatch MDM\";
    }
}
