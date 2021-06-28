$roleID = '700d08d5-5e3b-4147-aef6-636400b78af6'
$appObjID = '<APP ID FROM >'
Add-AzureADDirectoryRoleMember -ObjectId $roleID  -RefObjectId  $appObjID