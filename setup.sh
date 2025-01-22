#!/bin/bash

# Check if prefix is provided
if [[ "$1" != "create" && "$1" != "destroy" && "$1" != "recreate" ]]; then
    echo "Invalid action. Use 'create', 'destroy', or 'recreate'."
    exit 1
fi

if [[ "$1" == "create" && -z "$2" ]]; then
    echo "Error: Prefix is required for create action"
    echo "Usage: ./setup.sh create <prefix>"
    exit 1
fi

# Set prefix if provided
if [[ -n "$2" ]]; then
    # Convert to lowercase and replace any non-alphanumeric chars with underscore
    export PREFIX=$(echo "$2" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]/_/g')
    echo "Using prefix: $PREFIX"
fi

# Function to prompt for configuration values
prompt_for_config() {
    # Get full paths for required JSON files
    local script_dir="$(cd "$(dirname "$0")" && pwd)"
    local credentials_path="$script_dir/credentials.json"
    local role_mappings_path="$script_dir/role_mappings.json"

    # Check for credentials.json
    if [[ ! -f "$credentials_path" ]]; then
        echo "Error: credentials.json not found at: $credentials_path"
        echo
        echo "To set up credentials:"
        echo "1. Go to Skyflow Management Console"
        echo "2. Navigate to Vault Settings > Service Accounts"
        echo "3. Create a new JWT service account with appropriate permissions"
        echo "4. Download the service account credentials JSON file"
        echo "5. Save it as 'credentials.json' in: $credentials_path"
        echo
        exit 1
    fi

    # Check for role_mappings.json
    if [[ ! -f "$role_mappings_path" ]]; then
        echo "Error: role_mappings.json not found at: $role_mappings_path"
        echo
        echo "To set up role mappings:"
        echo "1. Create role_mappings.json file with your Skyflow role mappings"
        echo "2. Include defaultRoleID and roleMappings array"
        echo "3. Save it in: $role_mappings_path"
        echo
        exit 1
    fi

    # Validate JSON format for both files
    if ! jq . "$credentials_path" >/dev/null 2>&1; then
        echo "Error: Invalid JSON format in credentials.json"
        exit 1
    fi
    if ! jq . "$role_mappings_path" >/dev/null 2>&1; then
        echo "Error: Invalid JSON format in role_mappings.json"
        exit 1
    fi

    # Source config.sh first to get default values
    source "$(dirname "$0")/config.sh"

    echo
    echo "Enter values for configuration (press Enter to use default values):"
    
    # Prompt for BigQuery project ID
    read -p "BigQuery Project ID [${DEFAULT_PROJECT_ID}]: " input
    export PROJECT_ID=${input:-$DEFAULT_PROJECT_ID}
    
    # Prompt for BigQuery region
    read -p "BigQuery Region [${DEFAULT_REGION}]: " input
    export REGION=${input:-$DEFAULT_REGION}
    
    # Prompt for Skyflow account ID
    read -p "Skyflow Account ID [${DEFAULT_SKYFLOW_ACCOUNT_ID}]: " input
    export SKYFLOW_ACCOUNT_ID=${input:-$DEFAULT_SKYFLOW_ACCOUNT_ID}
    
    # Prompt for Skyflow vault ID
    read -p "Skyflow Vault ID [${DEFAULT_SKYFLOW_VAULT_ID}]: " input
    export SKYFLOW_VAULT_ID=${input:-$DEFAULT_SKYFLOW_VAULT_ID}
    
    # Prompt for Skyflow table name
    read -p "Skyflow Table Name [${DEFAULT_SKYFLOW_TABLE_NAME}]: " input
    export SKYFLOW_TABLE_NAME=${input:-$DEFAULT_SKYFLOW_TABLE_NAME}
    
    # Prompt for batch sizes
    read -p "Skyflow Insert Batch Size [${DEFAULT_SKYFLOW_INSERT_BATCH_SIZE}]: " input
    export SKYFLOW_INSERT_BATCH_SIZE=${input:-$DEFAULT_SKYFLOW_INSERT_BATCH_SIZE}
    
    read -p "Skyflow Detokenize Batch Size [${DEFAULT_SKYFLOW_DETOKENIZE_BATCH_SIZE}]: " input
    export SKYFLOW_DETOKENIZE_BATCH_SIZE=${input:-$DEFAULT_SKYFLOW_DETOKENIZE_BATCH_SIZE}

    echo "Configuration values set."
    echo

    # Source config.sh again to apply any other dependent variables
    source "$(dirname "$0")/config.sh"
}

# Source operations
source "$(dirname "$0")/google_cloud_ops.sh"

create_components() {
    install_prerequisites

    # Get full path for credentials.json
    local script_dir="$(cd "$(dirname "$0")" && pwd)"
    local credentials_path="$script_dir/credentials.json"

    echo "Creating Secret Manager secrets..."
    # Create credentials secret
    gcloud secrets create "${PREFIX}_credentials" \
        --replication-policy="automatic" \
        --data-file="$credentials_path"

    # Create role mappings secret (process with envsubst first)
    echo "Creating role mappings secret..."
    cat "$script_dir/role_mappings.json" | envsubst | gcloud secrets create "${PREFIX}_role_mappings" \
        --replication-policy="automatic" \
        --data-file=-

    echo "Creating BigQuery dataset..."
    bq --location=${REGION} mk --dataset "${PROJECT_ID}:${DATASET}"

    echo "Creating BigQuery table and inserting sample data..."
    cat "$(dirname "$0")/sql/insert_sample_data.sql" | envsubst | bq query --use_legacy_sql=false

    # Deploy unified Skyflow service
    deploy_services

    echo "Creating BigQuery connection..."
    bq mk --connection \
        --project_id="${PROJECT_ID}" \
        --connection_type=CLOUD_RESOURCE \
        --location="${REGION}" \
        "${CONNECTION_NAME}"

    echo "Creating BigQuery remote functions..."
    # Create all functions using unified service endpoint
    cat "$(dirname "$0")/sql/create_tokenize_table_function.sql" | envsubst | bq query --use_legacy_sql=false
    cat "$(dirname "$0")/sql/create_tokenize_value_function.sql" | envsubst | bq query --use_legacy_sql=false
    cat "$(dirname "$0")/sql/create_detokenize_function.sql" | envsubst | bq query --use_legacy_sql=false

    echo "Setup complete!"
}

destroy_components() {
    echo "Dropping BigQuery functions..."
    bq query --use_legacy_sql=false "DROP FUNCTION IF EXISTS \`${PROJECT_ID}.${DATASET}.${PREFIX}_skyflow_tokenize_table\`"
    bq query --use_legacy_sql=false "DROP FUNCTION IF EXISTS \`${PROJECT_ID}.${DATASET}.${PREFIX}_skyflow_tokenize\`"
    bq query --use_legacy_sql=false "DROP FUNCTION IF EXISTS \`${PROJECT_ID}.${DATASET}.${PREFIX}_skyflow_detokenize\`"

    echo "Deleting BigQuery table..."
    bq rm -f -t "${PROJECT_ID}:${DATASET}.${TABLE}"

    echo "Deleting BigQuery dataset..."
    bq rm -f -d "${PROJECT_ID}:${DATASET}"

    echo "Deleting BigQuery connection..."
    bq rm -f --connection --location="${REGION}" "${CONNECTION_NAME}"

    # Clean up Cloud Run resources
    cleanup_resources

    echo "Deleting Secret Manager secrets..."
    gcloud secrets delete "${PREFIX}_credentials" --quiet || true
    gcloud secrets delete "${PREFIX}_role_mappings" --quiet || true

    echo "Destroy complete!"
}

# Main logic
# Prompt for configuration values first
prompt_for_config

if [[ "$1" == "create" ]]; then
    create_components
elif [[ "$1" == "destroy" ]]; then
    destroy_components
elif [[ "$1" == "recreate" ]]; then
    destroy_components
    create_components
fi
