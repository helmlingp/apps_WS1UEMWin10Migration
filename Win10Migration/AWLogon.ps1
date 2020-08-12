#############################################
# File: AWLogon.ps1
# Author: Chase Bradley
# Modified by: Phil Helmling 08 Aug 2019, restructure for optimised flow and add "Current" LogonGroup condition - don't move device
# Modified by Phil Helmling: 5 December 2019, optimised to use $device_info more instead of API lookups, works with DeviceInventory Module for SmarterGroups etc
# Reassigns a Shared Device to logged in user and Moves OG if needed. Can specify "LogonGroup":"Current" in shared.config to leave
#############################################
$current_path = $PSScriptRoot;
if($PSScriptRoot -eq ""){
    #default path
    $current_path = "C:\Temp\UserManagement";
}

#Set-Variable -Name "current_path" -Value $current_path -Scope "Global"
$Global:current_path = $current_path

Unblock-File "$Global:current_path\Helpers.psm1"
$LocalHelpers = Import-Module "$Global:current_path\Helpers.psm1" -ErrorAction Stop -PassThru -Force;
#Global:shared_path set in Helpers.psm1
$shared_path = $Global:shared_path;
#Global:log_path set in Helpers.psm1
$logLocation = "$Global:log_path\UserManagement.log"; 

$GlobalModules = @();
$GlobalImporter = @("$shared_path\AirWatchAPI.psm1","$shared_path\Security-Functions.psm1");
foreach ($Import in $GlobalImporter){
    Unblock-File $Import;
    $GlobalModules += Import-Module $Import -ErrorAction Stop -PassThru -Force
}

#Enable Debug Logging, not needed if api-debug.config found
$Debug = $true;

if(Test-Path "$shared_path\api-debug.config"){
    $Debug = $true;
	$useDebugConfig = $true;
	Write-Log2 -Path "$logLocation" -Message "---------------------------------------------------------------------------" -Level Info
	Write-Log2 -Path $logLocation -Message "Started Import_SmarterGroups" -Level Info
	Write-Log2 -Path $logLocation -Message "GlobalModules: $GlobalModules" -Level Info	
}

#WS1 API endpoints
$device_endpoint = "api/mdm/devices/{DeviceId}/";
$change_user_endpoint = "/api/mdm/devices/{DeviceId}/enrollmentuser/";
$user_search_endpoint = "/api/system/users/search";
$user_details_endpoint = "/api/system/users/";
$og_search_endpoint = "/api/system/groups/search";
$change_og_endpoint = "/api/mdm/devices/{DeviceId}/commands/changeorganizationgroup/";
$smartgroup_search = "/api/mdm/smartgroups/search";
$smartgroup_refresh = "/api/mdm/smartgroups";

#Load the shared.config file
Try {
    $SharedConfigFile = [IO.File]::ReadAllText("$current_path\shared.config");
    $SharedConfig = ConvertFrom-JSON -InputObject $SharedConfigFile;
} Catch {
    $m = "Could not parse config file";
    Write-Log2 -Path $logLocation -Message $m -Level Error
    Throw $m;
}

#==========================Body=============================#
#Load api.config into private scope
$Private:api_settings_obj = Get-AWAPIConfiguration -Debug $Debug

$Private:Server = $Private:api_settings_obj.ApiConfig.Server;
$Private:API_Key = $Private:api_settings_obj.ApiConfig.ApiKey;
$Private:Auth = $Private:api_settings_obj.ApiConfig.ApiAuth;
$Private:SSLThumbprint = $Private:api_settings_obj.ApiConfig.SSLThumbprint;
$Private:TagsOrganizationGroupId = $Private:api_settings_obj.ApiConfig.TagsOrganizationGroupId;
$Private:TagsOrganizationGroupName = $Private:api_settings_obj.ApiConfig.TagsOrganizationGroupName;
$Private:DeviceId = $Private:api_settings_obj.ApiConfig.DeviceId;
If($Debug){
	Write-Log2 -Path "$logLocation" -Message "Private:Server: $Private:Server" -Level Info
	Write-Log2 -Path "$logLocation" -Message "Private:API_Key: $Private:API_Key" -Level Info
	Write-Log2 -Path "$logLocation" -Message "Private:Auth: $Private:Auth" -Level Info
	Write-Log2 -Path "$logLocation" -Message "Private:SSLThumbprint: $Private:SSLThumbprint" -Level Info
	Write-Log2 -Path "$logLocation" -Message "Private:TagsOrganizationGroupId: $Private:TagsOrganizationGroupId" -Level Info
	Write-Log2 -Path "$logLocation" -Message "Private:TagsOrganizationGroupName: $Private:TagsOrganizationGroupName" -Level Info
	Write-Log2 -Path "$logLocation" -Message "Private:DeviceId: $Private:DeviceId" -Level Info
}

#If this is the first run, the DeviceId should be blank. Find the device ID and store in api.config to be used for other lookups
If(!($Private:DeviceId)) { #-or !($Private:OrganizationGroupName)) {
	#If DeviceId and OrganizationGroupName not populated in api.config file, then set them from $device_info
	$device_info = Get-NewDeviceId -Debug $Debug -SSLThumbPrint $Private:SSLThumbPrint -Server $Private:Server -API_Key $Private:API_Key -Auth $Private:Auth
	If (!$device_info){
		$m = "Could not establish connection with the API.";
		Write-Log2 -Path $logLocation -Message $m -Level Error
		Throw $m;
	}
	If($device_info -eq "Unenrolled"){
		If($Debug) {
			Write-Log2 -Path "$logLocation" -Message "Device isn't enrolled" -Level Info
			Write-Log2 -Path "$logLocation" -Message "---------------------------------------------------------------------------" -Level Info
		}
	} Else {
		If($Debug) {
			Write-Log2 -Path "$logLocation" -Message "set missing values to $Private scope in order to reuse" -Level Info
			Write-Log2 -Path "$logLocation" -Message "---------------------------------------------------------------------------" -Level Info
		}
		$Private:DeviceId = $device_info.Id.Value
				
		#Save the Device Info into api.config so we don't need to make an API call next time
		$Private:api_settings_obj.ApiConfig.DeviceId = $Private:DeviceId;
		$apicontent = ConvertTo-Json $Private:api_settings_obj -Depth 10;
		
		If(!$useDebugConfig){
			$apiencryptedcontent = ConvertTo-EncryptedFile -FileContents $apicontent
			Set-Content "$shared_path\api.config" -Value $apiencryptedcontent
		} Else {
			Set-Content "$shared_path\api-debug.config" -Value $apicontent
		}
		If($Debug){
			Write-Log2 -Path "$logLocation" -Message "Private:DeviceId: $Private:DeviceId" -Level Info
			Write-Log2 -Path "$logLocation" -Message "Returning from initial DeviceId get" -Level Info
			Write-Log2 -Path "$logLocation" -Message "---------------------------------------------------------------------------" -Level Info
		}
	}
}

#Read device attributes
$device_info = Invoke-AWApiCommand -Endpoint $device_endpoint -Debug $Debug -SSLThumbPrint $Private:SSLThumbPrint -Server $Private:Server -API_Key $Private:API_Key -Auth $Private:Auth -DeviceId $Private:DeviceId;
if (!$device_info){
    $m = "Could not establish connection with the API.";
    Write-Log2 -Path $logLocation -Message $m -Level Error
    Throw $m;
}
If($Debug) {
	Write-Log2 -Path $logLocation -Message "device_info: $device_info" -Level Info
}

#Get Current Logged on User from Windows
$CurrentUsername = Get-CurrentLoggedonUser;
if ($debug){
    Write-Log2 -Path $logLocation -Message "Current UserName $CurrentUsername" -Level Info
}

#if device is not shared, don't do anything
if ($device_info.Ownership -eq "S") {

    if ($device_info.UserName -ne $CurrentUsername) {
        #change user
        #if device is assigned to another user ie has been checked out to someone else, then change user and move OG to force refresh
        if($debug){
            Write-Log2 -Path $logLocation -Message "Device is Shared and not assigned to UserName $CurrentUsername" -Level Info
        }

        #is user in WS1 directory?
        $user_search = Invoke-AWApiCommand -Endpoint "$user_search_endpoint`?username=$CurrentUsername" -Debug $Debug -SSLThumbPrint $Private:SSLThumbPrint -Server $Private:Server -API_Key $Private:API_Key -Auth $Private:Auth -DeviceId $Private:DeviceId;
        if($debug){
            Write-Log2 -Path $logLocation -Message "User is in WS1 $user_search.Users" -Level Info
        }

        #is user domain user?
        If($user_search){
            $domainUsers = $user_search.Users | where {$_.SecurityType -ne 0}
            If(($domainUsers | measure).Count -eq 1){
                $CurrentUserId = $domainUsers[0].Id.Value;
                if($debug){
                    Write-Log2 -Path $logLocation -Message "User $CurrentUsername is Domain User $CurrentUserId" -Level Info
                }
            }

            If($CurrentUserId){
                #change user on device
                $change_users = Invoke-AWApiCommand -Endpoint "$change_user_endpoint/$CurrentUserId" -Method PATCH -Debug $Debug -SSLThumbPrint $Private:SSLThumbPrint -Server $Private:Server -API_Key $Private:API_Key -Auth $Private:Auth -DeviceId $Private:DeviceId;
                if($change_users){
                    #move device to Logon OG
                    <# $OG_Switch = Invoke-AWApiCommand -Method Put -Endpoint ($change_og_endpoint + "$LogonGroupIdNum")
                    if($debug){
                        Write-Log2 -Path $logLocation -Message "Assigned User $CurrentUsername / $CurrentUserId to device" -Level Info
                    } #>
                } else {
                    $m = "An error occured.  Not able to change users through API.";
                    Write-Log2 -Path $logLocation -Message $m -Level Error
                    Throw $m;
                }
            }
        }
    } else {
        #do nothing
        if($debug){
            Write-Log2 -Path $logLocation -Message "Device already assigned to Username $CurrentUsername so not changing user assignment" -Level Info
        }
    }

    #If shared.config LogonGroup is set to 'Current' then leave the device in the same OG - ie don't move it
    #First Get OG IDs for Logon and Logoff OGs set in shared.config
    $LogonGroup = $SharedConfig.SharedConfig.LogonGroup;
    if($debug){
        Write-Log2 -Path $logLocation -Message "shared.config LogonGroup set to $LogonGroup" -Level Info
    }
    $LogoffGroup = $SharedConfig.SharedConfig.LogoffGroup;
    #If($LogonGroup -notlike "Current") {
    If($LogonGroup -ne "Current") {
        $OrganizationGroupName = $device_info.LocationGroupName;
        If($OrganizationGroupName -eq $LogonGroup){
            #if device is already in Logon OG, then don't need to move OG

            #MIGHT NEED TO CHANGE THIS BACK TO THE OLD WAY OF MATCHING ON OGID RATHER THAN OGNAME
            #IF SO, MOVE THE OG_SEARCH STUFF INTO ABOVE AND THEN CHANGE TEST
            #THIS WAY SHOULD BE QUICKER
            if($debug){
                Write-Log2 -Path $logLocation -Message "Device already in OG $LogonGroup so not moving OG" -Level Info
            }
        } else {
            #device is not in Logon OG so get OG IDs in order to do the OG move
            <# $Logoff_OG_Search = Invoke-AWApiCommand -Endpoint ("$og_search_endpoint`?groupid=$LogoffGroup" ) -ApiVersion 2;
            If($Logoff_OG_Search.OrganizationGroups){
                $LogoffGroupIdNum = $Logoff_OG_Search.OrganizationGroups[0].Id;
                if($debug){
                    Write-Log2 -Path $logLocation -Message "Logoff Group $LogoffGroup & ID $LogoffGroupIdNum" -Level Info
                }
            } #>
            $Logon_OG_Search = Invoke-AWApiCommand -Endpoint ("$og_search_endpoint`?groupid=$LogonGroup" ) -ApiVersion 2 -Debug $Debug -SSLThumbPrint $Private:SSLThumbPrint -Server $Private:Server -API_Key $Private:API_Key -Auth $Private:Auth -DeviceId $Private:DeviceId;
            If($Logon_OG_Search.OrganizationGroups){
                $LogonGroupIdNum = $Logon_OG_Search.OrganizationGroups[0].Id;
                if($debug){
                    Write-Log2 -Path $logLocation -Message "Logon Group $LogonGroup & ID $LogonGroupIdNum" -Level Info
                }
            }
            #Doublecheck the Logon / Logoff OG IDs
            #If(!$LogonGroupIdNum -or !$LogoffGroupIdNum){ 
            If(!$LogonGroupIdNum){    
                Throw "An error occured getting the Logon/Logoff Group IDs";
            }
            #$OrganizationGroupName = $device_info.LocationGroupName;
<#             $OGIDSearch = Invoke-AWApiCommand -Endpoint ("$og_search_endpoint`?name=$OrganizationGroupName" ) -ApiVersion 2;
            If($OGIDSearch.OrganizationGroups) {
                $CurrentOrganizationGroupId = $OGIDSearch.OrganizationGroups[0].Id;
                if($debug){
                    Write-Log2 -Path $logLocation -Message "Current OG ID $CurrentOrganizationGroupId" -Level Info
                }
            } #>

            $CurrentOrganizationGroupId = $device_info.LocationGroupId.Id.Value

            #Not sure if need to move out to Logoff OG before moving to Logon OG
            # If($CurrentOrganizationGroupId -ne $LogoffGroupIdNum){
            #     #move device to Logoff OG
            #     $OG_Switch = Invoke-AWApiCommand -Method Put -Endpoint ($change_og_endpoint + "$LogoffGroupIdNum")     
            # }

            #Basically puts device back into checkin position
            If($CurrentOrganizationGroupId -ne $LogonGroupIdNum){
                #move device to Logon OG
                $OG_Switch = Invoke-AWApiCommand -Method Put -Endpoint ($change_og_endpoint + "$LogonGroupIdNum") -Debug $Debug -SSLThumbPrint $Private:SSLThumbPrint -Server $Private:Server -API_Key $Private:API_Key -Auth $Private:Auth -DeviceId $Private:DeviceId;
                if($debug){
                    Write-Log2 -Path $logLocation -Message "Device moved to Logon OG" -Level Info
                }
            }
        }
    } else {
        if($debug){
            Write-Log2 -Path $logLocation -Message "shared.config LogonGroup is set to 'Current' then leave the device in the same OG - ie don't move it" -Level Info
        }
    }
}
else {
    if($debug){
        Write-Log2 -Path $logLocation -Message "Device Ownership is $device_info.Ownership / not 'Shared' so doing nothing" -Level Info
    }
}