# Cloud Watcher
Cloud Watcher is an Open Source script that scans your subscription and compares it to a baseline, this helps companies reduce the time to detect breaches to their cloud resources. 

## Available Versions

CloudWatcher is available in two versions:
1. **PowerShell (Azure Automation)** - `CloudWatcher.ps1` - Designed to run in Azure Automation
2. **Azure CLI (Bash)** - `CloudWatcher-CLI.sh` - Designed to run in Kubernetes containers or any environment with Azure CLI

## Requirements

### PowerShell Version (Azure Automation)
- Azure Account
- Azure Automation Service with runas service principal
- Storage Account

### Azure CLI Version (Kubernetes/Container)
- Azure Account
- Azure CLI installed (`az` command)
- `jq` installed for JSON processing
- Storage Account
- One of the following authentication methods:
  - Service Principal with Certificate (App ID + Certificate file)
  - Managed Service Identity (MSI)

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

### Azure CLI Version (Kubernetes/Container)

The Azure CLI version (`CloudWatcher-CLI.sh`) can run in any environment with Azure CLI installed, including Kubernetes containers.

#### Prerequisites

1. Install Azure CLI: https://docs.microsoft.com/en-us/cli/azure/install-azure-cli
2. Install jq: `apt-get install jq` (or equivalent for your OS)
3. Create a storage account and container to hold your baseline

#### Authentication Options

The CLI version supports two authentication methods:

##### Option 1: Managed Service Identity (MSI)

Use this when running in Azure Kubernetes Service (AKS) or other Azure compute with managed identity enabled.

```bash
./CloudWatcher-CLI.sh \
    --auth-method msi \
    --storage-account mystorageaccount \
    --container baseline \
    --blob-name baseline.json \
    --sas-token "?sv=2021-06-08&ss=b&srt=co&sp=rwdlacx&se=..." \
    --run-type setup
```

##### Option 2: Service Principal with Certificate

Use this for non-Azure environments or when you need explicit credentials.

1. Create an App Registration in Azure AD
2. Generate a certificate and upload it to the App Registration
3. Grant the service principal Reader access to the subscriptions you want to monitor
4. Assign the Directory Readers role to the service principal (see AAD App Creation section below)

```bash
./CloudWatcher-CLI.sh \
    --auth-method certificate \
    --app-id "your-app-id" \
    --tenant-id "your-tenant-id" \
    --certificate-path "/path/to/certificate.pem" \
    --storage-account mystorageaccount \
    --container baseline \
    --blob-name baseline.json \
    --sas-token "?sv=2021-06-08&ss=b&srt=co&sp=rwdlacx&se=..." \
    --run-type setup
```

#### Running in Kubernetes

Example Kubernetes CronJob to run CloudWatcher monitoring:

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: cloudwatcher
spec:
  schedule: "0 * * * *"  # Run every hour
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: cloudwatcher
            image: mcr.microsoft.com/azure-cli:latest
            command:
            - /bin/bash
            - -c
            - |
              apt-get update && apt-get install -y jq
              /scripts/CloudWatcher-CLI.sh \
                --auth-method msi \
                --storage-account $(STORAGE_ACCOUNT) \
                --container $(CONTAINER_NAME) \
                --blob-name $(BLOB_NAME) \
                --sas-token "$(SAS_TOKEN)" \
                --run-type monitoring
            env:
            - name: STORAGE_ACCOUNT
              valueFrom:
                secretKeyRef:
                  name: cloudwatcher-secrets
                  key: storage-account
            - name: CONTAINER_NAME
              valueFrom:
                secretKeyRef:
                  name: cloudwatcher-secrets
                  key: container-name
            - name: BLOB_NAME
              valueFrom:
                secretKeyRef:
                  name: cloudwatcher-secrets
                  key: blob-name
            - name: SAS_TOKEN
              valueFrom:
                secretKeyRef:
                  name: cloudwatcher-secrets
                  key: sas-token
            volumeMounts:
            - name: scripts
              mountPath: /scripts
          volumes:
          - name: scripts
            configMap:
              name: cloudwatcher-script
              defaultMode: 0755
          restartPolicy: OnFailure
```

#### Command Line Options

```
Authentication Options:
  --auth-method <method>    Authentication method: 'certificate' or 'msi'
  --app-id <id>             Application (client) ID (required for certificate auth)
  --tenant-id <id>          Tenant ID (required for certificate auth)
  --certificate-path <path> Path to certificate file (required for certificate auth)
  --use-msi                 Use Managed Service Identity (shortcut for --auth-method msi)

Storage Options:
  --storage-account <name>  Storage account name
  --container <name>        Container name for baseline storage
  --blob-name <name>        Blob name for baseline file
  --sas-token <token>       SAS token for storage access

Run Options:
  --run-type <type>         Run type: 'setup' to create baseline, 'monitoring' to compare
```

### PowerShell Version (Azure Automation)

### AAD App Creation and Setup

1) Create Azure Automation Account with runas account

1) Give the service principal created reader access to the subscriptions you want to monitor.

1) Go to Azure Active Directory > Enterprise Applications and select the application created as the runas account. (you might have to change the filter to all applications and search for the name of your application)

1) Copy the object ID shown in the application page.

1) Get the Directory Readers Role ID running 'Get-AzureADDirectoryRole' 

1) Run the following commands replacing <App ObjectID> with the app's object Id. and the role ID with the 'Directory readers' role ID.

```powershell
$roleID = '<Role ID>'
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
1) If the run is successful, go back to the edit pane and click on publish:
  ![image](https://user-images.githubusercontent.com/8607853/124002785-285d5000-d9a4-11eb-9452-447bec5992f3.png)
Your Runbook should now be published and it should allow you to add it to schedules. 

## Installation Video Tutorial
  https://youtu.be/z4aY8kFKo8M
  
  
## Recommended Use

For security reasons we recommend running the automation account, and hosting the storage account in a different subscription than the subscription being hosted. This prevents attackers that get access to your subscription to stop or modify the baseline. 

### How Did We Set It Up

At Keytos we wanted to ensure the security of our CloudWatcher deployment. To do this we use 3 different subscriptions, and they all point at each other with CloudWatchers.
  
![image](https://user-images.githubusercontent.com/8607853/127204078-438b4f4d-f3cc-43c6-8493-169da6a71f0c.png)

To simplify it I am just going to show one of the CloudWatchers in the diagram. 
  
 ![image](https://user-images.githubusercontent.com/8607853/127204128-9802862f-f2a3-411b-bbe8-88151d8511d8.png)
 
The Idea is that you have the subscription that you want to monitor (Subscription A). Then in a different subscription (Subscription B) that ideally does not share any of the same administrator identities with the subscription you want to monitor, you create the CloudWatcher Automation Account. Then in another Subscription (Subscription C) (At Keytos we do it in another Tenant) you have a storage account with the baseline. The token given to the CloudWatcher in Subscription B only has read access to the baseline blob, meaning that a compromise of that account does not allow to make changes to the baseline. 

  
