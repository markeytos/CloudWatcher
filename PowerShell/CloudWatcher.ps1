Import-Module Az.KeyVault
Import-Module Az.Resources
Import-Module Az.Sql
Import-Module Az.Storage
Import-Module Az.Accounts

$accountName = Get-AutomationVariable -Name accountName #Storage Account Name
$accountKey = Get-AutomationVariable -Name accountKey #Storage Account Key
$containerName = Get-AutomationVariable -Name containerName  #Storage Account Container Name
$blobName = Get-AutomationVariable -Name blobName  #Storage Account Blob (file) Name
$RunType= Get-AutomationVariable -Name RunType # monitoring or Setup depending on what you want to run

function Set-Up {
    $subscriptions = Get-AzSubscription
    $subscriptionsObjects = @()
    foreach ($sub in $subscriptions){
        try
        {

        $groups = @()
        $groupsWithMenbers = @()
        Set-AzContext $sub
        Write-Output "Getting $($sub.Name) $($sub.Id) Resources" 
        $subResources = Get-AzResource 
        $subACLs = Get-AzRoleAssignment -IncludeClassicAdministrators 
        $subResourcesWithInfo = @()
        foreach ($subResource in $subResources)
        {
            $networkInfo = $null
            $accessPolicies = $null
             if($subResource.ResourceType -eq 'Microsoft.KeyVault/vaults')
             {
                $akvinfo = Get-AzKeyVault -VaultName $subResource.Name
                #check Netowkring Policies
                $networkInfo = $akvinfo.NetworkAcls
                #check access policies 
                $accessPolicies = $akvinfo.AccessPolicies
                foreach($accessPolicy in $accessPolicies)
                {
                    $isGroup = Get-AzADGroup -ObjectId $accessPolicy.ObjectId
                    if($null -ne $isGroup)
                    {
                        $groupInfo = [PSCustomObject] @{
                            'DisplayName' = $isGroup.DisplayName
                            'ObjectId' =  $isGroup.Id
                            'Type' = $isGroup.ObjectType
                        }
                        $groupsWithMenbers += Get-GroupInfo($groupInfo)
                    }
                }
             }
             elseif ($subResource.ResourceType -eq 'Microsoft.Sql/servers')
             {
                #check Netowkring Policies
                $networkInfo = Get-AzSqlServerFirewallRule -ResourceGroupName $subResource.ResourceGroupName  -ServerName $subResource.ResourceName 
                #check AD Admin
                $aadAdmin = Get-AzSqlServerActiveDirectoryAdministrator -ServerName $subResource.ResourceName  -ResourceGroupName $subResource.ResourceGroupName
                if($null -ne $aadAdmin)
                {
                    $isGroup = Get-AzADGroup -ObjectId $aadAdmin.ObjectId
                    if($null -ne $isGroup)
                    {
                        $accessPolicies = [PSCustomObject] @{
                            'DisplayName' = $isGroup.DisplayName
                            'ObjectId' =  $isGroup.Id
                            'Type' = $isGroup.ObjectType
                            'IsAzureADOnlyAuthentication' = $aadAdmin.IsAzureADOnlyAuthentication
                        }
                        $groupsWithMenbers += Get-GroupInfo($accessPolicies)
                        
                    }
                    else{
                        $accessPolicies = [PSCustomObject] @{
                                        'DisplayName' = $aadAdmin.DisplayName
                                        'ObjectId' =  $aadAdmin.ObjectId
                                        'Type' = "User or SP"
                                        'IsAzureADOnlyAuthentication' = $aadAdmin.IsAzureADOnlyAuthentication
                                    }
                    }
                }
             }
             $subResourcesWithInfo += [PSCustomObject] @{
                'Resource' = $subResource 
                'NetworkInfo' =  $networkInfo
                'AccessPolicies' = $accessPolicies
            }
        }
        $resourceProviders = Get-AzResourceProvider -ListAvailable | Where-Object RegistrationState -eq "Registered" | Select-Object ProviderNamespace, RegistrationState | Sort-Object ProviderNamespace
        $groups +=  $subACLs | Where-Object {$_.ObjectType -eq 'Group'} | Select-Object -Property ObjectId, DisplayName, ObjectType | Sort-Object DisplayName
        foreach ($azGroup in $groups)
        {
            $groupsWithMenbers += Get-GroupInfo($azGroup)
        }
        $subscriptionsObjects += [PSCustomObject] @{
            'SubID' = $sub.Id
            'Resources' = $subResourcesWithInfo 
            'ACLs' =  $subACLs
            'Groups' = $groupsWithMenbers
            'ResourceProviders' = $resourceProviders
        }
        }
        catch
       {
          Write-Output $Error
          Write-Output "Error processing sub: $($sub.SubID)"
       } 
    }
    Write-Output "Saving Baseline" 
    $OutputFilePath = 'baseline.json'
    $subscriptionsObjects | ConvertTo-Json -Depth 5 |  Out-File -FilePath $OutputFilePath
    $StorageContext = New-AzStorageContext -StorageAccountName $accountName -StorageAccountKey $accountKey
    Set-AzStorageBlobContent -Container $containerName -File $OutputFilePath -Blob "$(Get-Date -Format "MM-dd-yyyy-HH:mm")$($blobName)" -Context $StorageContext
}


function Get-GroupInfo([PSCustomObject]  $azGroupinfo)
{
    $groupMembers = Get-AzADGroupMember -GroupObjectId $azGroupinfo.ObjectId
    return [PSCustomObject] @{
        'Group' = $azGroupinfo 
        'GroupMembers' =  $groupMembers
    }
}

function Monitor-Subscriptions
{
    Write-Output  "Getting Json"
    $StorageContext = New-AzStorageContext -StorageAccountName $accountName -StorageAccountKey $accountKey
    $OutputFilePath = "test.json"
    Get-AzStorageBlobContent -Blob $blobName -Container $containerName -Destination $OutputFilePath -Context $StorageContext | Out-Null
    $baselineJSON = Get-Content -Path $OutputFilePath
   $baseline =  $baselineJSON | ConvertFrom-Json
   $err = $false
   foreach($sub in $baseline)
   {
       try{
        Write-Output "Checking Sub $($sub.SubID)"
        Set-AzContext -Subscription $sub.SubID | Out-Null
        #Check ACLs
        $groupsWithMenbers = @()
        $subACLs = Get-AzRoleAssignment -IncludeClassicAdministrators | Sort-Object DisplayName
        $aclComparison = Compare-Object $sub.ACLs $subACLs -Property {$_.Scope}, {$_.DisplayName}, {$_.ObjectId}, {$_.RoleDefinitionName}, {$_.RoleDefinitionId} | Select-Object @{Name="Scope";Expression={$_.'$_.Scope'}}, @{Name="Object Display Name";Expression={$_.'$_.DisplayName'}}, @{Name="ObjectId";Expression={$_.'$_.ObjectId'}}, @{Name="Role Definition Name";Expression={$_.'$_.RoleDefinitionName'}}, @{Name="RoleDefinitionId";Expression={$_.'$_.RoleDefinitionId'}},  SideIndicator
        if($null -ne $aclComparison)
        {
            $err = $true
            foreach($changedACL in $aclComparison)
            {
                if($changedACL.SideIndicator -eq "<=")
                {
                    Write-Output "ACL Removed: Scope: $($changedACL.Scope) Object Name: $($changedACL.'Object Display Name') ObjectID: $($changedACL.ObjectId) Role Name: $($changedACL.'Role Definition Name') RoleID: $($changedACL.RoleDefinitionId)"
                }
                if($changedACL.SideIndicator -eq "=>")
                {
                    Write-Output "ACL Added: Scope: $($changedACL.Scope) Object Name: $($changedACL.'Object Display Name') ObjectID: $($changedACL.ObjectId) Role Name: $($changedACL.'Role Definition Name') RoleID: $($changedACL.RoleDefinitionId)"
                }
            }
        }
        #Check Resources
        $subResources = Get-AzResource 
        if($null -eq $subResources -and $null -eq $sub.Resources.Resource)
        {
            #Do Nothing No resources
        }
        elseif($null -ne $subResources -and $null -eq $sub.Resources.Resource)
        {
            $err = $true
            Write-Output "New Resources detected in Subscription $($sub.SubID)"
        }
        elseif($null -eq $subResources -and $null -ne $sub.Resources.Resource)
        {
            $err = $true
            Write-Output "No Resources detected in Subscription $($sub.SubID)"
        }
        else
        {
            $resourceExistanceComparison = Compare-Object $sub.Resources.Resource $subResources -Property {$_.ResourceId} | Select-Object @{Name="ResourceId";Expression={$_.'$_.ResourceId'}}, SideIndicator
            if($null -ne $resourceExistanceComparison)
            {
                $err = $true
                foreach($changedResource in $resourceExistanceComparison)
                {
                    if($changedResource.SideIndicator -eq "<=")
                    {
                        Write-Output "Resource Removed: Resource ID: $($changedResource.ResourceId)"
                    }
                    if($changedResource.SideIndicator -eq "=>")
                    {
                        Write-Output "Resource Added: Resource ID: $($changedResource.ResourceId)"
                    }
                }
            }
            foreach($subResource in $subResources)
            {
                if($subResource.ResourceType -eq 'Microsoft.KeyVault/vaults')
                {
                    $akvinfo = Get-AzKeyVault -VaultName $subResource.Name
                    $baselineAKV = $sub.Resources  | Where-Object {$_.Resource.ResourceId -eq $akvinfo.ResourceId}
                    if($null -eq $baselineAKV)
                    {
                        $err = $true
                        Write-Output "Error $($akvinfo.ResourceId) does not exist in baseline."
                    }
                    else
                    {
                        #check Netowkring Policies
                        $networkInfo = $akvinfo.NetworkAcls
                        if($networkInfo.Bypass -ne $baselineAKV.NetworkInfo.Bypass)  
                        {
                            $err = $true
                            Write-Output   "Network change in AKV: $($akvinfo.VaultName) Baseline Bypass Value $($baselineAKV.NetworkInfo.Bypass) New Bypass Value: $($networkInfo.Bypass)"
                        }  
                        if($networkInfo.DefaultAction -ne $baselineAKV.NetworkInfo.DefaultAction)  
                        {
                            $err = $true
                            Write-Output  "Network change in AKV: $($akvinfo.VaultName) Baseline DefaultAction Value $($baselineAKV.NetworkInfo.DefaultAction) New DefaultAction Value: $($networkInfo.DefaultAction)"
                        } 
                        if($networkInfo.VirtualNetworkResourceIdsText -ne $baselineAKV.NetworkInfo.VirtualNetworkResourceIdsText)  
                        {
                            $err = $true
                            Write-Output   "Network change in AKV: $($akvinfo.VaultName) Baseline VirtualNetworkResourceIds Value $($baselineAKV.NetworkInfo.VirtualNetworkResourceIdsText) New VirtualNetworkResourceIds Value: $($networkInfo.VirtualNetworkResourceIdsText)"
                        }   
                        if($networkInfo.IpAddressRangesText -ne $baselineAKV.NetworkInfo.IpAddressRangesText)  
                        {
                            $err = $true
                            Write-Output  "Network change in AKV: $($akvinfo.VaultName) Baseline IpAddressRanges Value $($baselineAKV.NetworkInfo.IpAddressRangesText) New IpAddressRanges Value: $($networkInfo.IpAddressRangesText)"
                        }               
                        #check access policies 
                        foreach($accessPolicy in $akvinfo.AccessPolicies)
                        {
                            $baselineAccessPolicy = $baselineAKV.AccessPolicies  | Where-Object {$_.ObjectId -eq $accessPolicy.ObjectId} 
                            if($null -eq $baselineAccessPolicy)
                            {
                                $err = $true
                                Write-Output "New Object Id added to akv $($akvinfo.ResourceId) ObjectId: $($accessPolicy.ObjectId) Display Name: $($accessPolicy.DisplayName)."
                            }
                            else 
                            {
                                if($accessPolicy.PermissionsToKeysStr -ne $baselineAccessPolicy.PermissionsToKeysStr)  
                                {
                                    $err = $true
                                    Write-Output "Access Policy change in AKV: $($akvinfo.VaultName) Baseline PermissionsToKeys Value $($baselineAccessPolicy.PermissionsToKeysStr) New PermissionsToKeys Value: $($accessPolicy.PermissionsToKeysStr)"
                                } 
                                if($accessPolicy.PermissionsToCertificatesStr -ne $baselineAccessPolicy.PermissionsToCertificatesStr)  
                                {
                                    $err = $true
                                    Write-Output "Access Policy change in AKV: $($akvinfo.VaultName) Baseline PermissionsToCertificates Value $($baselineAccessPolicy.PermissionsToCertificatesStr) New PermissionsToCertificates Value: $($accessPolicy.PermissionsToCertificatesStr)"
                                } 
                                if($accessPolicy.PermissionsToSecretsStr -ne $baselineAccessPolicy.PermissionsToSecretsStr)  
                                {
                                    $err = $true
                                    Write-Output "Access Policy change in AKV: $($akvinfo.VaultName) Baseline PermissionsToSecrets Value $($baselineAccessPolicy.PermissionsToSecretsStr) New PermissionsToSecrets Value: $($accessPolicy.PermissionsToSecretsStr)"
                                } 
                            }
                            $isGroup = Get-AzADGroup -ObjectId $accessPolicy.ObjectId
                            if($null -ne $isGroup)
                            {
                                $groupInfo = [PSCustomObject] @{
                                    'DisplayName' = $isGroup.DisplayName
                                    'ObjectId' =  $isGroup.Id
                                    'Type' = $isGroup.ObjectType
                                }
                                $groupsWithMenbers += Get-GroupInfo($groupInfo)
                            }
                        }
                        #checked removed Access Policies.
                        $deletedAcessPolicies = Compare-Object $akvinfo.AccessPolicies $baselineAKV.AccessPolicies -Property {$_.ObjectId},  {$_.DisplayName} | Select-Object @{Name="ObjectId";Expression={$_.'$_.ObjectId'}}, @{Name="DisplayName";Expression={$_.'$_.DisplayName'}}, SideIndicator
                        if($null -ne $deletedAcessPolicies)
                        {
                            $err = $true
                            foreach($deletedPolicy in $deletedAcessPolicies)
                            {
                                if($deletedPolicy.SideIndicator -eq "=>")
                                {
                                    Write-Output "Access Policy Deleted in AKV:$($akvinfo.VaultName) AAD Object ID: $($deletedPolicy.ObjectId) AAD Object Display Name $($deletedPolicy.DisplayName)"
                                }
                            }
                        }
                    }
                }
                elseif($subResource.ResourceType -eq 'Microsoft.Sql/servers')
                {
                    #check Netowkring Policies
                    $baselineDB = $sub.Resources  | Where-Object {$_.Resource.ResourceId -eq $subResource.ResourceId}
                    $networkInfo = Get-AzSqlServerFirewallRule -ResourceGroupName $subResource.ResourceGroupName  -ServerName $subResource.ResourceName 
                    
                    $changedNetworkAcls = Compare-Object $networkInfo $baselineDB.NetworkInfo -Property {$_.StartIpAddress},  {$_.EndIpAddress},  {$_.FirewallRuleName}  | Select-Object @{Name="StartIpAddress";Expression={$_.'$_.StartIpAddress'}}, @{Name="EndIpAddress";Expression={$_.'$_.EndIpAddress'}}, @{Name="FirewallRuleName";Expression={$_.'$_.FirewallRuleName'}}, SideIndicator
                    
                    if($null -ne $changedNetworkAcls)
                    {
                        $err = $true
                        foreach($changedResource in $changedNetworkAcls)
                        {
                            if($changedResource.SideIndicator -eq "<=")
                            {
                                Write-Output "NetworkACL Removed: for SQL Server: $($subResource.Name) Rule Name $($changedResource.FirewallRuleName) Start IP: $($changedResource.StartIpAddress) End IP: $($changedResource.EndIpAddress)"
                            }
                            if($changedResource.SideIndicator -eq "=>")
                            {
                                Write-Output "NetworkACL Added: for SQL Server: $($subResource.Name) Rule Name $($changedResource.FirewallRuleName) Start IP: $($changedResource.StartIpAddress) End IP: $($changedResource.EndIpAddress)"
                            }
                        }
                    }
    
                    #check AD Admin
                    $aadAdmin = Get-AzSqlServerActiveDirectoryAdministrator -ServerName $subResource.ResourceName  -ResourceGroupName $subResource.ResourceGroupName
                    if($null -eq $baselineDB.AccessPolicies -and $null -eq $aadAdmin)
                    {
                        #Do Noting no AAD Admin
                    }
                    elseif($null -eq $baselineDB.AccessPolicies -and $null -ne $aadAdmin)
                    {
                        #AAD Admin Added
                        $err = $true
                        Write-Output "DB AAD Admin Added: for SQL Server: $($subResource.Name) AAD Admin Display Name $($aadAdmin.DisplayName) Object ID: $($aadAdmin.ObjectId)"
    
                    }
                    elseif($null -ne $baselineDB.AccessPolicies -and $null -eq $aadAdmin)
                    {
                        #AAD Admin Removed
                        $err = $true
                        Write-Output "DB AAD Admin Removed: for SQL Server: $($subResource.Name) AAD Admin Display Name $($baselineDB.AccessPolicies.DisplayName) Object ID: $($baselineDB.AccessPolicies.ObjectId)"
                    }
                    else
                    {
                        #Compare AAD Admins
                        if($baselineDB.AccessPolicies.ObjectId -ne $aadAdmin.ObjectId)
                        {
                            $err = $true
                            Write-Output "DB AAD Admin Changed: for SQL Server: $($subResource.Name) Baseline AAD Admin Display Name $($baselineDB.AccessPolicies.DisplayName)  Baseline Object ID: $($baselineDB.AccessPolicies.ObjectId). New AAD Admin Display Name $($aadAdmin.DisplayName) New Object ID: $($aadAdmin.ObjectId)"
                        }
                        if($baselineDB.AccessPolicies.IsAzureADOnlyAuthentication -ne $aadAdmin.IsAzureADOnlyAuthentication)
                        {
                            $err = $true
                            Write-Output "DB AAD Only Toggle Changed: for SQL Server: $($subResource.Name) Baseline Value $($baselineDB.AccessPolicies.IsAzureADOnlyAuthentication)  New Value: $($aadAdmin.IsAzureADOnlyAuthentication)"
                        }
                    }
                    if($null -ne $aadAdmin)
                    {
                        $isGroup = Get-AzADGroup -ObjectId $aadAdmin.ObjectId
                        if($null -ne $isGroup)
                        {
                            $groupInfo = [PSCustomObject] @{
                                'DisplayName' = $isGroup.DisplayName
                                'ObjectId' =  $isGroup.Id
                                'Type' = $isGroup.ObjectType
                            }
                            $groupsWithMenbers += Get-GroupInfo($groupInfo)
                        }
                    }
                    
                }
            }
        }
        
        #Check Groups (We only check the membership changes, the ACLs are checked above)
        $groups =  $subACLs | Where-Object {$_.ObjectType -eq 'Group'} | Select-Object -Property ObjectId, DisplayName, ObjectType | Sort-Object DisplayName
        foreach ($azGroup in $groups)
        {
            $groupsWithMenbers += Get-GroupInfo($azGroup)
        }
        foreach($group in $groupsWithMenbers)
        {
            $baselineGroup = $sub.Groups | Where-Object {$_.Group.ObjectId -eq $group.Group.ObjectId} | Select-Object -First 1                  
            if($null -eq $baselineGroup)
            {
                $err = $true
                Write-Output "Error Group $($group.Group.DisplayName) does not exist in baseline"
            }
            else
            {
                $MemberComparison = Compare-Object $baselineGroup.GroupMembers $group.GroupMembers -Property {$_.Id}, {$_.DisplayName}  | Select-Object @{Name="ObjectId";Expression={$_.'$_.Id'}}, @{Name="DisplayName";Expression={$_.'$_.DisplayName'}}, SideIndicator
                foreach($ChangedMember in $MemberComparison)
                {
                    if($ChangedMember.SideIndicator -eq '<=')
                    {
                        $err = $true
                        Write-Output "Member removed from group $($group.Group.DisplayName) Member Object ID: $($ChangedMember.ObjectId) Member Display Name $($ChangedMember.DisplayName)"
                    }
                    elseif($ChangedMember.SideIndicator -eq '=>')
                    {
                        $err = $true
                        Write-Output "Member Added from group $($group.Group.DisplayName) Member Object ID: $($ChangedMember.ObjectId) Member Display Name $($ChangedMember.DisplayName)"
                    }
                }
            }
        }
        #Resource Providers
        $resourceProviders = Get-AzResourceProvider -ListAvailable | Where-Object RegistrationState -eq "Registered" | Select-Object ProviderNamespace, RegistrationState | Sort-Object ProviderNamespace
        $resourceProviderComparison = Compare-Object $sub.ResourceProviders $resourceProviders -Property {$_.ProviderNamespace}  | Select-Object @{Name="ProviderNamespace";Expression={$_.'$_.ProviderNamespace'}}, SideIndicator
        foreach($ChangedRP in $resourceProviderComparison)
        {
            if($ChangedRP.SideIndicator -eq '<=')
            {
                $err = $true
                Write-Output "Resource Provider removed $($ChangedRP.ProviderNamespace) "
            }
            elseif($ChangedRP.SideIndicator -eq '=>')
            {
                $err = $true
                Write-Output "Resource Provider Added $($ChangedRP.ProviderNamespace) "
            }
        }
       }
       catch
       {
          Write-Output "Error processing sub: $($sub.SubID)"
          Write-Output $Error
          $err = $true
       }
        
   }
   if($err -eq $true)
    {
        throw "Baseline Error"
    }
    else
    {
        Write-Output "No changes detected :)"
    }
}

Disable-AzContextAutosave -Scope Process

$connection = Get-AutomationConnection -Name AzureRunAsConnection

Write-Output "Starting Authentication"
Connect-AzAccount -ServicePrincipal -Tenant $connection.TenantID  -ApplicationId $connection.ApplicationID  -CertificateThumbprint $connection.CertificateThumbprint

if($RunType -eq "monitoring")
{
    Write-Output  "Starting Monitoring"
    Monitor-Subscriptions
    
}
else
{
    Write-Output "Running First time setup"
    Set-Up
}
