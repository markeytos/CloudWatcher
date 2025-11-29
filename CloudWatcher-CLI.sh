#!/bin/bash

# CloudWatcher CLI - Azure subscription monitoring tool
# This script runs in Azure CLI and can be used in Kubernetes containers
# 
# Supports two authentication methods:
# 1. Service Principal with Certificate: --app-id and --certificate-path
# 2. Managed Service Identity (MSI): --use-msi
#
# Usage:
#   ./CloudWatcher-CLI.sh --auth-method <certificate|msi> [auth options] --storage-account <name> \
#                         --container <name> --blob-name <name> --sas-token <token> --run-type <setup|monitoring>
#
# Examples:
#   # Using MSI:
#   ./CloudWatcher-CLI.sh --auth-method msi --storage-account mystorageaccount --container baseline \
#                         --blob-name baseline.json --sas-token "?sv=..." --run-type monitoring
#
#   # Using Certificate:
#   ./CloudWatcher-CLI.sh --auth-method certificate --app-id <app-id> --tenant-id <tenant-id> \
#                         --certificate-path /path/to/cert.pem --storage-account mystorageaccount \
#                         --container baseline --blob-name baseline.json --sas-token "?sv=..." --run-type setup

set -e

# Default values
AUTH_METHOD=""
APP_ID=""
TENANT_ID=""
CERTIFICATE_PATH=""
STORAGE_ACCOUNT=""
CONTAINER_NAME=""
BLOB_NAME=""
SAS_TOKEN=""
RUN_TYPE=""

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --auth-method)
            AUTH_METHOD="$2"
            shift 2
            ;;
        --app-id)
            APP_ID="$2"
            shift 2
            ;;
        --tenant-id)
            TENANT_ID="$2"
            shift 2
            ;;
        --certificate-path)
            CERTIFICATE_PATH="$2"
            shift 2
            ;;
        --use-msi)
            AUTH_METHOD="msi"
            shift
            ;;
        --storage-account)
            STORAGE_ACCOUNT="$2"
            shift 2
            ;;
        --container)
            CONTAINER_NAME="$2"
            shift 2
            ;;
        --blob-name)
            BLOB_NAME="$2"
            shift 2
            ;;
        --sas-token)
            SAS_TOKEN="$2"
            shift 2
            ;;
        --run-type)
            RUN_TYPE="$2"
            shift 2
            ;;
        --help|-h)
            echo "CloudWatcher CLI - Azure subscription monitoring tool"
            echo ""
            echo "Usage:"
            echo "  $0 --auth-method <certificate|msi> [auth options] --storage-account <name> \\"
            echo "     --container <name> --blob-name <name> --sas-token <token> --run-type <setup|monitoring>"
            echo ""
            echo "Authentication Options:"
            echo "  --auth-method <method>    Authentication method: 'certificate' or 'msi'"
            echo "  --app-id <id>             Application (client) ID (required for certificate auth)"
            echo "  --tenant-id <id>          Tenant ID (required for certificate auth)"
            echo "  --certificate-path <path> Path to certificate file (required for certificate auth)"
            echo "  --use-msi                 Use Managed Service Identity (shortcut for --auth-method msi)"
            echo ""
            echo "Storage Options:"
            echo "  --storage-account <name>  Storage account name"
            echo "  --container <name>        Container name for baseline storage"
            echo "  --blob-name <name>        Blob name for baseline file"
            echo "  --sas-token <token>       SAS token for storage access"
            echo ""
            echo "Run Options:"
            echo "  --run-type <type>         Run type: 'setup' to create baseline, 'monitoring' to compare"
            echo ""
            echo "Examples:"
            echo "  # Using MSI:"
            echo "  $0 --auth-method msi --storage-account mystorageaccount --container baseline \\"
            echo "     --blob-name baseline.json --sas-token \"?sv=...\" --run-type monitoring"
            echo ""
            echo "  # Using Certificate:"
            echo "  $0 --auth-method certificate --app-id <app-id> --tenant-id <tenant-id> \\"
            echo "     --certificate-path /path/to/cert.pem --storage-account mystorageaccount \\"
            echo "     --container baseline --blob-name baseline.json --sas-token \"?sv=...\" --run-type setup"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Validate required parameters
validate_params() {
    local errors=()
    
    if [[ -z "$AUTH_METHOD" ]]; then
        errors+=("--auth-method is required (certificate or msi)")
    elif [[ "$AUTH_METHOD" == "certificate" ]]; then
        if [[ -z "$APP_ID" ]]; then
            errors+=("--app-id is required for certificate authentication")
        fi
        if [[ -z "$TENANT_ID" ]]; then
            errors+=("--tenant-id is required for certificate authentication")
        fi
        if [[ -z "$CERTIFICATE_PATH" ]]; then
            errors+=("--certificate-path is required for certificate authentication")
        elif [[ ! -f "$CERTIFICATE_PATH" ]]; then
            errors+=("Certificate file not found: $CERTIFICATE_PATH")
        fi
    elif [[ "$AUTH_METHOD" != "msi" ]]; then
        errors+=("Invalid auth method: $AUTH_METHOD. Must be 'certificate' or 'msi'")
    fi
    
    if [[ -z "$STORAGE_ACCOUNT" ]]; then
        errors+=("--storage-account is required")
    fi
    
    if [[ -z "$CONTAINER_NAME" ]]; then
        errors+=("--container is required")
    fi
    
    if [[ -z "$BLOB_NAME" ]]; then
        errors+=("--blob-name is required")
    fi
    
    if [[ -z "$SAS_TOKEN" ]]; then
        errors+=("--sas-token is required")
    fi
    
    if [[ -z "$RUN_TYPE" ]]; then
        errors+=("--run-type is required (setup or monitoring)")
    elif [[ "$RUN_TYPE" != "setup" && "$RUN_TYPE" != "monitoring" ]]; then
        errors+=("Invalid run type: $RUN_TYPE. Must be 'setup' or 'monitoring'")
    fi
    
    if [[ ${#errors[@]} -gt 0 ]]; then
        echo "Validation errors:"
        for error in "${errors[@]}"; do
            echo "  - $error"
        done
        exit 1
    fi
}

# Authenticate to Azure
authenticate() {
    echo "Starting Authentication..."
    
    if [[ "$AUTH_METHOD" == "msi" ]]; then
        echo "Using Managed Service Identity..."
        az login --identity
    elif [[ "$AUTH_METHOD" == "certificate" ]]; then
        echo "Using Service Principal with Certificate..."
        az login --service-principal \
            --username "$APP_ID" \
            --tenant "$TENANT_ID" \
            --password "$CERTIFICATE_PATH"
    fi
    
    echo "Authentication successful"
}

# Get all subscriptions
get_subscriptions() {
    az account list --query "[].{id:id, name:name}" -o json
}

# Set subscription context
set_subscription() {
    local sub_id="$1"
    az account set --subscription "$sub_id"
}

# Get all resources in current subscription
get_resources() {
    az resource list -o json
}

# Get role assignments in current subscription
get_role_assignments() {
    az role assignment list --all --include-classic-administrators -o json 2>/dev/null || az role assignment list --all -o json
}

# Get Key Vault information
get_keyvault_info() {
    local vault_name="$1"
    az keyvault show --name "$vault_name" -o json 2>/dev/null
}

# Get Key Vault network rules
get_keyvault_network_rules() {
    local vault_name="$1"
    az keyvault network-rule list --name "$vault_name" -o json 2>/dev/null
}

# Get SQL Server firewall rules
get_sql_firewall_rules() {
    local server_name="$1"
    local resource_group="$2"
    az sql server firewall-rule list --server "$server_name" --resource-group "$resource_group" -o json 2>/dev/null
}

# Get SQL Server AD admin
get_sql_ad_admin() {
    local server_name="$1"
    local resource_group="$2"
    az sql server ad-admin list --server-name "$server_name" --resource-group "$resource_group" -o json 2>/dev/null
}

# Get AD group members
get_group_members() {
    local group_id="$1"
    az ad group member list --group "$group_id" -o json 2>/dev/null
}

# Get resource providers
get_resource_providers() {
    az provider list --query "[?registrationState=='Registered'].{namespace:namespace, state:registrationState}" -o json
}

# Check if object is a group
is_ad_group() {
    local object_id="$1"
    az ad group show --group "$object_id" -o json 2>/dev/null
}

# Upload blob to storage
upload_blob() {
    local file_path="$1"
    local blob_name="$2"
    
    az storage blob upload \
        --account-name "$STORAGE_ACCOUNT" \
        --container-name "$CONTAINER_NAME" \
        --name "$blob_name" \
        --file "$file_path" \
        --sas-token "$SAS_TOKEN" \
        --overwrite
}

# Download blob from storage
download_blob() {
    local blob_name="$1"
    local file_path="$2"
    
    az storage blob download \
        --account-name "$STORAGE_ACCOUNT" \
        --container-name "$CONTAINER_NAME" \
        --name "$blob_name" \
        --file "$file_path" \
        --sas-token "$SAS_TOKEN"
}

# Process group information
process_group_info() {
    local object_id="$1"
    local display_name="$2"
    
    local group_info
    group_info=$(is_ad_group "$object_id")
    
    if [[ -n "$group_info" && "$group_info" != "null" ]]; then
        local members
        members=$(get_group_members "$object_id")
        echo "{\"group\": {\"objectId\": \"$object_id\", \"displayName\": \"$display_name\"}, \"members\": $members}"
    else
        echo ""
    fi
}

# Setup function - creates baseline
setup() {
    echo "Running First time setup"
    
    local subscriptions
    subscriptions=$(get_subscriptions)
    
    local baseline="[]"
    
    # Process each subscription
    echo "$subscriptions" | jq -c '.[]' | while read -r sub; do
        local sub_id
        sub_id=$(echo "$sub" | jq -r '.id')
        local sub_name
        sub_name=$(echo "$sub" | jq -r '.name')
        
        echo "Getting $sub_name ($sub_id) Resources"
        
        set_subscription "$sub_id" 2>/dev/null || {
            echo "Error: Could not set subscription $sub_id"
            continue
        }
        
        # Get resources
        local resources
        resources=$(get_resources)
        
        # Get role assignments
        local acls
        acls=$(get_role_assignments)
        
        # Get resource providers
        local providers
        providers=$(get_resource_providers)
        
        # Process resources with additional info
        local resources_with_info="[]"
        local groups_with_members="[]"
        
        echo "$resources" | jq -c '.[]' 2>/dev/null | while read -r resource; do
            local resource_type
            resource_type=$(echo "$resource" | jq -r '.type')
            local resource_name
            resource_name=$(echo "$resource" | jq -r '.name')
            local resource_group
            resource_group=$(echo "$resource" | jq -r '.resourceGroup')
            
            local network_info="null"
            local access_policies="null"
            
            if [[ "$resource_type" == "Microsoft.KeyVault/vaults" ]]; then
                # Get Key Vault info
                local kv_info
                kv_info=$(get_keyvault_info "$resource_name")
                if [[ -n "$kv_info" ]]; then
                    network_info=$(echo "$kv_info" | jq '.properties.networkAcls // null')
                    access_policies=$(echo "$kv_info" | jq '.properties.accessPolicies // null')
                fi
            elif [[ "$resource_type" == "Microsoft.Sql/servers" ]]; then
                # Get SQL Server firewall rules
                network_info=$(get_sql_firewall_rules "$resource_name" "$resource_group")
                # Get SQL Server AD admin
                access_policies=$(get_sql_ad_admin "$resource_name" "$resource_group")
            fi
            
            # Add to resources with info
            echo "{\"resource\": $resource, \"networkInfo\": $network_info, \"accessPolicies\": $access_policies}"
        done > /tmp/resources_info_$$.json 2>/dev/null || true
        
        # Collect all resource info into array
        if [[ -f /tmp/resources_info_$$.json ]]; then
            resources_with_info=$(cat /tmp/resources_info_$$.json | jq -s '.')
            rm -f /tmp/resources_info_$$.json
        fi
        
        # Process groups from ACLs
        echo "$acls" | jq -c '.[] | select(.principalType == "Group" or .objectType == "Group")' 2>/dev/null | while read -r group_acl; do
            local object_id
            object_id=$(echo "$group_acl" | jq -r '.principalId // .objectId')
            local display_name
            display_name=$(echo "$group_acl" | jq -r '.principalName // .displayName')
            
            if [[ -n "$object_id" && "$object_id" != "null" ]]; then
                local members
                members=$(get_group_members "$object_id" 2>/dev/null || echo "[]")
                echo "{\"group\": {\"objectId\": \"$object_id\", \"displayName\": \"$display_name\"}, \"members\": $members}"
            fi
        done > /tmp/groups_$$.json 2>/dev/null || true
        
        # Collect all group info
        if [[ -f /tmp/groups_$$.json ]]; then
            groups_with_members=$(cat /tmp/groups_$$.json | jq -s 'unique_by(.group.objectId)')
            rm -f /tmp/groups_$$.json
        fi
        
        # Create subscription object
        echo "{\"subId\": \"$sub_id\", \"resources\": $resources_with_info, \"acls\": $acls, \"groups\": $groups_with_members, \"resourceProviders\": $providers}"
    done > /tmp/subscriptions_$$.json 2>/dev/null
    
    # Combine all subscriptions into final baseline
    if [[ -f /tmp/subscriptions_$$.json ]]; then
        baseline=$(cat /tmp/subscriptions_$$.json | jq -s '.')
        rm -f /tmp/subscriptions_$$.json
    fi
    
    # Save baseline
    echo "Saving Baseline"
    local output_file="/tmp/baseline.json"
    echo "$baseline" | jq '.' > "$output_file"
    
    # Upload to storage
    local timestamp
    timestamp=$(date +"%m-%d-%Y-%H:%M")
    upload_blob "$output_file" "${timestamp}${BLOB_NAME}"
    
    echo "Baseline saved successfully"
    rm -f "$output_file"
}

# Monitoring function - compares against baseline
monitor() {
    echo "Starting Monitoring"
    echo "Getting Json"
    
    local output_file="/tmp/baseline_download.json"
    download_blob "$BLOB_NAME" "$output_file"
    
    local baseline
    baseline=$(cat "$output_file")
    rm -f "$output_file"
    
    # Use a file to track errors across subshells
    local error_file="/tmp/cloudwatcher_errors_$$.txt"
    rm -f "$error_file"
    
    # Process each subscription in baseline
    echo "$baseline" | jq -c '.[]' | while read -r sub; do
        local sub_id
        sub_id=$(echo "$sub" | jq -r '.subId')
        
        echo "Checking Sub $sub_id"
        
        set_subscription "$sub_id" 2>/dev/null || {
            echo "Error: Could not set subscription $sub_id"
            echo "error" >> "$error_file"
            continue
        }
        
        # Check ACLs
        local current_acls
        current_acls=$(get_role_assignments)
        local baseline_acls
        baseline_acls=$(echo "$sub" | jq '.acls')
        
        # Compare ACLs by roleAssignmentId or scope+principalId+roleDefinitionId
        local acl_comparison
        acl_comparison=$(jq -n --argjson baseline "$baseline_acls" --argjson current "$current_acls" '
            {
                "added": ($current | map(select(. as $item | 
                    $baseline | map(.id // .roleAssignmentId) | index($item.id // $item.roleAssignmentId) | not))),
                "removed": ($baseline | map(select(. as $item | 
                    $current | map(.id // .roleAssignmentId) | index($item.id // $item.roleAssignmentId) | not)))
            }')
        
        local added_acls
        added_acls=$(echo "$acl_comparison" | jq '.added | length')
        local removed_acls
        removed_acls=$(echo "$acl_comparison" | jq '.removed | length')
        
        if [[ "$added_acls" -gt 0 ]]; then
            echo "error" >> "$error_file"
            echo "$acl_comparison" | jq -r '.added[] | "ACL Added: Scope: \(.scope) Object Name: \(.principalName // .displayName) ObjectID: \(.principalId // .objectId) Role Name: \(.roleDefinitionName)"'
        fi
        
        if [[ "$removed_acls" -gt 0 ]]; then
            echo "error" >> "$error_file"
            echo "$acl_comparison" | jq -r '.removed[] | "ACL Removed: Scope: \(.scope) Object Name: \(.principalName // .displayName) ObjectID: \(.principalId // .objectId) Role Name: \(.roleDefinitionName)"'
        fi
        
        # Check Resources
        local current_resources
        current_resources=$(get_resources)
        local baseline_resources
        baseline_resources=$(echo "$sub" | jq '[.resources[].resource]')
        
        local resource_comparison
        resource_comparison=$(jq -n --argjson baseline "$baseline_resources" --argjson current "$current_resources" '
            {
                "added": ($current | map(select(. as $item | 
                    $baseline | map(.id) | index($item.id) | not))),
                "removed": ($baseline | map(select(. as $item | 
                    $current | map(.id) | index($item.id) | not)))
            }')
        
        local added_resources
        added_resources=$(echo "$resource_comparison" | jq '.added | length')
        local removed_resources
        removed_resources=$(echo "$resource_comparison" | jq '.removed | length')
        
        if [[ "$added_resources" -gt 0 ]]; then
            echo "error" >> "$error_file"
            echo "$resource_comparison" | jq -r '.added[] | "Resource Added: Resource ID: \(.id)"'
        fi
        
        if [[ "$removed_resources" -gt 0 ]]; then
            echo "error" >> "$error_file"
            echo "$resource_comparison" | jq -r '.removed[] | "Resource Removed: Resource ID: \(.id)"'
        fi
        
        # Check each resource for detailed changes (Key Vault, SQL Server)
        echo "$current_resources" | jq -c '.[]' | while read -r resource; do
            local resource_type
            resource_type=$(echo "$resource" | jq -r '.type')
            local resource_name
            resource_name=$(echo "$resource" | jq -r '.name')
            local resource_id
            resource_id=$(echo "$resource" | jq -r '.id')
            local resource_group
            resource_group=$(echo "$resource" | jq -r '.resourceGroup')
            
            if [[ "$resource_type" == "Microsoft.KeyVault/vaults" ]]; then
                local baseline_kv
                baseline_kv=$(echo "$sub" | jq --arg id "$resource_id" '.resources[] | select(.resource.id == $id)')
                
                if [[ -z "$baseline_kv" || "$baseline_kv" == "null" ]]; then
                    continue
                fi
                
                local kv_info
                kv_info=$(get_keyvault_info "$resource_name")
                
                if [[ -n "$kv_info" ]]; then
                    # Check network rules
                    local current_network
                    current_network=$(echo "$kv_info" | jq '.properties.networkAcls')
                    local baseline_network
                    baseline_network=$(echo "$baseline_kv" | jq '.networkInfo')
                    
                    local current_bypass
                    current_bypass=$(echo "$current_network" | jq -r '.bypass // "None"')
                    local baseline_bypass
                    baseline_bypass=$(echo "$baseline_network" | jq -r '.bypass // "None"')
                    
                    if [[ "$current_bypass" != "$baseline_bypass" ]]; then
                        echo "error" >> "$error_file"
                        echo "Network change in AKV: $resource_name Baseline Bypass Value $baseline_bypass New Bypass Value: $current_bypass"
                    fi
                    
                    local current_default
                    current_default=$(echo "$current_network" | jq -r '.defaultAction // "Allow"')
                    local baseline_default
                    baseline_default=$(echo "$baseline_network" | jq -r '.defaultAction // "Allow"')
                    
                    if [[ "$current_default" != "$baseline_default" ]]; then
                        echo "error" >> "$error_file"
                        echo "Network change in AKV: $resource_name Baseline DefaultAction Value $baseline_default New DefaultAction Value: $current_default"
                    fi
                    
                    # Check access policies
                    local current_policies
                    current_policies=$(echo "$kv_info" | jq '.properties.accessPolicies // []')
                    local baseline_policies
                    baseline_policies=$(echo "$baseline_kv" | jq '.accessPolicies // []')
                    
                    local policy_comparison
                    policy_comparison=$(jq -n --argjson baseline "$baseline_policies" --argjson current "$current_policies" '
                        {
                            "added": ($current | map(select(. as $item | 
                                $baseline | map(.objectId) | index($item.objectId) | not))),
                            "removed": ($baseline | map(select(. as $item | 
                                $current | map(.objectId) | index($item.objectId) | not)))
                        }')
                    
                    local added_policies
                    added_policies=$(echo "$policy_comparison" | jq '.added | length')
                    local removed_policies
                    removed_policies=$(echo "$policy_comparison" | jq '.removed | length')
                    
                    if [[ "$added_policies" -gt 0 ]]; then
                        echo "error" >> "$error_file"
                        echo "$policy_comparison" | jq -r --arg kv "$resource_name" '.added[] | "New Object Id added to akv \($kv) ObjectId: \(.objectId)"'
                    fi
                    
                    if [[ "$removed_policies" -gt 0 ]]; then
                        echo "error" >> "$error_file"
                        echo "$policy_comparison" | jq -r --arg kv "$resource_name" '.removed[] | "Access Policy Deleted in AKV: \($kv) AAD Object ID: \(.objectId)"'
                    fi
                fi
                
            elif [[ "$resource_type" == "Microsoft.Sql/servers" ]]; then
                local baseline_db
                baseline_db=$(echo "$sub" | jq --arg id "$resource_id" '.resources[] | select(.resource.id == $id)')
                
                if [[ -z "$baseline_db" || "$baseline_db" == "null" ]]; then
                    continue
                fi
                
                # Check firewall rules
                local current_fw
                current_fw=$(get_sql_firewall_rules "$resource_name" "$resource_group")
                local baseline_fw
                baseline_fw=$(echo "$baseline_db" | jq '.networkInfo // []')
                
                local fw_comparison
                fw_comparison=$(jq -n --argjson baseline "$baseline_fw" --argjson current "$current_fw" '
                    {
                        "added": ($current | map(select(. as $item | 
                            $baseline | map(.name) | index($item.name) | not))),
                        "removed": ($baseline | map(select(. as $item | 
                            $current | map(.name) | index($item.name) | not)))
                    }')
                
                local added_fw
                added_fw=$(echo "$fw_comparison" | jq '.added | length')
                local removed_fw
                removed_fw=$(echo "$fw_comparison" | jq '.removed | length')
                
                if [[ "$added_fw" -gt 0 ]]; then
                    echo "error" >> "$error_file"
                    echo "$fw_comparison" | jq -r --arg server "$resource_name" '.added[] | "NetworkACL Added: for SQL Server: \($server) Rule Name \(.name) Start IP: \(.startIpAddress) End IP: \(.endIpAddress)"'
                fi
                
                if [[ "$removed_fw" -gt 0 ]]; then
                    echo "error" >> "$error_file"
                    echo "$fw_comparison" | jq -r --arg server "$resource_name" '.removed[] | "NetworkACL Removed: for SQL Server: \($server) Rule Name \(.name) Start IP: \(.startIpAddress) End IP: \(.endIpAddress)"'
                fi
                
                # Check AD admin
                local current_admin
                current_admin=$(get_sql_ad_admin "$resource_name" "$resource_group")
                local baseline_admin
                baseline_admin=$(echo "$baseline_db" | jq '.accessPolicies // []')
                
                local current_admin_count
                current_admin_count=$(echo "$current_admin" | jq 'length')
                local baseline_admin_count
                baseline_admin_count=$(echo "$baseline_admin" | jq 'length')
                
                if [[ "$baseline_admin_count" -eq 0 && "$current_admin_count" -gt 0 ]]; then
                    echo "error" >> "$error_file"
                    echo "$current_admin" | jq -r --arg server "$resource_name" '.[] | "DB AAD Admin Added: for SQL Server: \($server) AAD Admin Display Name \(.login) Object ID: \(.sid)"'
                elif [[ "$baseline_admin_count" -gt 0 && "$current_admin_count" -eq 0 ]]; then
                    echo "error" >> "$error_file"
                    echo "$baseline_admin" | jq -r --arg server "$resource_name" '.[] | "DB AAD Admin Removed: for SQL Server: \($server) AAD Admin Display Name \(.login // .displayName) Object ID: \(.sid // .objectId)"'
                elif [[ "$current_admin_count" -gt 0 && "$baseline_admin_count" -gt 0 ]]; then
                    local current_sid
                    current_sid=$(echo "$current_admin" | jq -r '.[0].sid // ""')
                    local baseline_sid
                    baseline_sid=$(echo "$baseline_admin" | jq -r '.[0].sid // .[0].objectId // ""')
                    
                    if [[ "$current_sid" != "$baseline_sid" ]]; then
                        echo "error" >> "$error_file"
                        echo "DB AAD Admin Changed: for SQL Server: $resource_name"
                    fi
                fi
            fi
        done
        
        # Check Groups membership
        local baseline_groups
        baseline_groups=$(echo "$sub" | jq '.groups // []')
        
        # Get current groups from ACLs
        echo "$current_acls" | jq -c '.[] | select(.principalType == "Group" or .objectType == "Group")' 2>/dev/null | while read -r group_acl; do
            local object_id
            object_id=$(echo "$group_acl" | jq -r '.principalId // .objectId')
            local display_name
            display_name=$(echo "$group_acl" | jq -r '.principalName // .displayName')
            
            if [[ -n "$object_id" && "$object_id" != "null" ]]; then
                local baseline_group
                baseline_group=$(echo "$baseline_groups" | jq --arg id "$object_id" '.[] | select(.group.objectId == $id)')
                
                if [[ -z "$baseline_group" || "$baseline_group" == "null" ]]; then
                    echo "error" >> "$error_file"
                    echo "Error Group $display_name does not exist in baseline"
                else
                    local current_members
                    current_members=$(get_group_members "$object_id" 2>/dev/null || echo "[]")
                    local baseline_members
                    baseline_members=$(echo "$baseline_group" | jq '.members // []')
                    
                    local member_comparison
                    member_comparison=$(jq -n --argjson baseline "$baseline_members" --argjson current "$current_members" '
                        {
                            "added": ($current | map(select(. as $item | 
                                $baseline | map(.id) | index($item.id) | not))),
                            "removed": ($baseline | map(select(. as $item | 
                                $current | map(.id) | index($item.id) | not)))
                        }')
                    
                    local added_members
                    added_members=$(echo "$member_comparison" | jq '.added | length')
                    local removed_members
                    removed_members=$(echo "$member_comparison" | jq '.removed | length')
                    
                    if [[ "$added_members" -gt 0 ]]; then
                        echo "error" >> "$error_file"
                        echo "$member_comparison" | jq -r --arg group "$display_name" '.added[] | "Member Added to group \($group) Member Object ID: \(.id) Member Display Name \(.displayName)"'
                    fi
                    
                    if [[ "$removed_members" -gt 0 ]]; then
                        echo "error" >> "$error_file"
                        echo "$member_comparison" | jq -r --arg group "$display_name" '.removed[] | "Member removed from group \($group) Member Object ID: \(.id) Member Display Name \(.displayName)"'
                    fi
                fi
            fi
        done
        
        # Check Resource Providers
        local current_providers
        current_providers=$(get_resource_providers)
        local baseline_providers
        baseline_providers=$(echo "$sub" | jq '.resourceProviders // []')
        
        local provider_comparison
        provider_comparison=$(jq -n --argjson baseline "$baseline_providers" --argjson current "$current_providers" '
            {
                "added": ($current | map(select(. as $item | 
                    $baseline | map(.namespace) | index($item.namespace) | not))),
                "removed": ($baseline | map(select(. as $item | 
                    $current | map(.namespace) | index($item.namespace) | not)))
            }')
        
        local added_providers
        added_providers=$(echo "$provider_comparison" | jq '.added | length')
        local removed_providers
        removed_providers=$(echo "$provider_comparison" | jq '.removed | length')
        
        if [[ "$added_providers" -gt 0 ]]; then
            echo "error" >> "$error_file"
            echo "$provider_comparison" | jq -r '.added[] | "Resource Provider Added \(.namespace)"'
        fi
        
        if [[ "$removed_providers" -gt 0 ]]; then
            echo "error" >> "$error_file"
            echo "$provider_comparison" | jq -r '.removed[] | "Resource Provider removed \(.namespace)"'
        fi
    done
    
    # Check if any errors were recorded
    if [[ -f "$error_file" ]]; then
        rm -f "$error_file"
        echo "Baseline Error"
        exit 1
    else
        echo "No changes detected :)"
    fi
}

# Main execution
main() {
    validate_params
    authenticate
    
    if [[ "$RUN_TYPE" == "monitoring" ]]; then
        monitor
    else
        setup
    fi
}

main
