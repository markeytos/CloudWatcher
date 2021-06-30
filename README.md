# Cloud Watcher
Cloud Watcher is an Open Source script that scans your subscription and compares it to a baseline, this helps companies reduce the time to detect breaches to their cloud resources. 

## Requirements

- Azure Account
- Azure Automation Service with runas service principal
- Storage Account

## In Scope

Azure has an ever growing number of resources and features, making it impossible for us to cover all of them, we currently monitor the following actions and resources:

- RBAC Changes to subscriptions
- Classic Administrator changes to subscriptions
- Azure Resource Provider changes to subscription
- Resource creation or deletion
- Change of Group membership (just first degree, we do not support nested groups)
- SQL Firewall changes
- SQL Server AAD Admin changes
- AKV Access Policies Changes
- AKV Firewall changes

## Installation Instructions

### AAD App Creation and Setup

1) Create Azure Automation Account with runas account

1) Give the service principal created reader access to the subscriptions you want to monitor.

1) Go to Azure Active Directory > Enterprise Applications and select the application created as the runas account. (you might have to change the filter to all applications and search for the name of your application)

1) Copy the object ID shown in the application page. 

1) Run the following commands replacing <App ObjectID> with the app's object Id.

```powershell
$roleID = '700d08d5-5e3b-4147-aef6-636400b78af6'
$appObjID = '<APP ObjectID>'
Connect-AzureAD
Add-AzureADDirectoryRoleMember -ObjectId $roleID  -RefObjectId  $appObjID
```

### Storage Account Setup

Before setting this up, please read the "Recommended Use" section since we have some security recommendations as on where to set up this storage account.

1) Create a storage account.

1) Create a container to hold your baseline

### Runbook Setup

#### Variable Setup

1) In the Azure portal, go to the Azure Automation Account you created in the first section. 

1) Go to Variables (under the Share Resources section)

1) Create a variable named "accountName" with the storage account name as the value.

1) Create a variable named "blobName" with a name for the baseline file (we use "baseline.json") as the value.

1) Create a variable named "containerName" with the storage account container name as the value.

1) Create a variable named "RunType" This value is used to tell the script if you are running in monitoring mode or Baselining mode. enter "monitoring" or "baseline" as the value depending on which mode you want to run. 

1) Create a variable named "accountKey" with the storage account SAS key as the value **Remember to set this value as encrypted!**

#### Adding Modules

In the Azure Automation Resource, go to modules, and add the following modules:

- Az.KeyVault

- Az.Resources

- Az.Sql

- Az.Storage

- Az.Accounts 

#### Runbook Setup

Now that we have set up the script to run. 

1) In the Azure Automation account, go to runbooks. 

1) Click on "Browse Gallery"
  ![image](https://user-images.githubusercontent.com/8607853/124001165-593c8580-d9a2-11eb-9e74-b7cae8043fc8.png)
1) In the search field type "CloudWatcher"
1) Select the CloudWatcher created by "markeytos"
  ![image](https://user-images.githubusercontent.com/8607853/124001756-f3043280-d9a2-11eb-87b2-24449391e37e.png)
1) Click Import
1) Enter the name for your Runbook
1) This should add the runbook in your runbook list:
  ![image](https://user-images.githubusercontent.com/8607853/124002176-6a39c680-d9a3-11eb-8d7f-c5da9d44d3c8.png)
1) Click on it and click the edit button.
1) Once the editor is open, click the test pane and run the test to make sure it is working properly. **Note: The fist time you run it you should set the run type as baseline to have a baseline in the storage account.**
1) If the run is successfull, go back to the edit pane and click on publish:
  ![image](https://user-images.githubusercontent.com/8607853/124002785-285d5000-d9a4-11eb-9452-447bec5992f3.png)
Your Runbook should now be published and it should allow you to add it to schedules. 

## Recommended Use

For security reasons we recommend running the automation account, and hosting the storage account in a different subscription than the subscription being hosted. This prevents attackers that get access to your subscription to stop or modify the baseline. 

### How Did We Set It Up

#### Resource Setup

At Keytos, we set up the automation account in a subscription that none of the identities of the monitored subscriptions have access to, and in one of those subscriptions we have a another version monitoring that subscription. 

#### Storage Access

The monitoring account, only has reader access to the storage account, meaning that a compromise of that account would not allow changes to the storage account (which is actually hosted in another tenant all together).

