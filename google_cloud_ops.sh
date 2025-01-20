#!/bin/bash

install_prerequisites() {
    echo "Installing prerequisites..."
    
    # Check for Homebrew
    if ! command -v brew &> /dev/null; then
        echo "Homebrew not found. Please install Homebrew first: https://brew.sh"
        exit 1
    fi

    # Install gettext for envsubst
    if ! command -v envsubst &> /dev/null; then
        echo "Installing gettext for envsubst..."
        brew install gettext
        echo "gettext installed."
    else
        echo "gettext already installed."
    fi
    
    # Install Google Cloud SDK via Homebrew
    if ! command -v gcloud &> /dev/null; then
        echo "Installing Google Cloud SDK via Homebrew..."
        brew install --cask google-cloud-sdk
        echo "Google Cloud SDK installed."
    else
        echo "Google Cloud SDK already installed."
    fi

    # Check if already authenticated and has access to project
    if gcloud projects describe $PROJECT_ID >/dev/null 2>&1; then
        echo "Already authenticated with access to project $PROJECT_ID"
    else
        echo "Authentication needed for project access..."
        gcloud auth login --quiet
        gcloud config set project $PROJECT_ID
    fi

    # Enable necessary APIs
    echo "Enabling necessary APIs..."
    gcloud services enable bigquery.googleapis.com
    gcloud services enable run.googleapis.com
    gcloud services enable cloudbuild.googleapis.com
    gcloud services enable iam.googleapis.com
    gcloud services enable secretmanager.googleapis.com
    echo "All necessary APIs enabled."
}

deploy_cloud_run() {
    echo "Deploying Cloud Run service: $SKYFLOW_SERVICE_NAME..."
    
    # Store current directory
    local current_dir=$(pwd)
    
    # Get absolute path to source directory
    local source_dir=$(cd "$(dirname "$0")/$SKYFLOW_SOURCE_PATH" && pwd)
    
    echo "Deploying from source directory: $source_dir"
    
    # Change to source directory
    cd "$source_dir"
    
    # Set environment variables
    local env_vars="SKYFLOW_VAULT_URL=$SKYFLOW_VAULT_URL"
    env_vars="$env_vars,SKYFLOW_TABLE_NAME=$SKYFLOW_TABLE_NAME"
    env_vars="$env_vars,SKYFLOW_ACCOUNT_ID=$SKYFLOW_ACCOUNT_ID"
    env_vars="$env_vars,PROJECT_ID=$PROJECT_ID"
    env_vars="$env_vars,PREFIX=$PREFIX"
    env_vars="$env_vars,SKYFLOW_INSERT_BATCH_SIZE=$SKYFLOW_INSERT_BATCH_SIZE"
    env_vars="$env_vars,SKYFLOW_DETOKENIZE_BATCH_SIZE=$SKYFLOW_DETOKENIZE_BATCH_SIZE"
    env_vars="$env_vars,BIGQUERY_UPDATE_BATCH_SIZE=$BIGQUERY_UPDATE_BATCH_SIZE"
    
    # Deploy Cloud Run service and capture the endpoint
    local endpoint
    if ! endpoint=$(gcloud run deploy "$SKYFLOW_SERVICE_NAME_HYPHENATED" \
        --source=. \
        --region=$REGION \
        --allow-unauthenticated \
        --set-env-vars "$env_vars" \
        --set-secrets CREDENTIALS_JSON=${PREFIX}_credentials:latest,ROLE_MAPPINGS_JSON=${PREFIX}_role_mappings:latest \
        --format="value(status.url)"); then
        echo "Error: Cloud Run deployment failed for $SKYFLOW_SERVICE_NAME"
        cd "$current_dir"
        exit 1
    fi

    # Verify endpoint is not empty
    if [ -z "$endpoint" ]; then
        echo "Error: Cloud Run endpoint is empty for $SKYFLOW_SERVICE_NAME"
        cd "$current_dir"
        exit 1
    fi

    echo "Cloud Run endpoint for $SKYFLOW_SERVICE_NAME: $endpoint"
    
    # Get project number
    echo "Getting project number..."
    PROJECT_NUMBER=$(gcloud projects describe $PROJECT_ID --format="value(projectNumber)")
    if [ -z "$PROJECT_NUMBER" ]; then
        echo "Error: Failed to get project number"
        cd "$current_dir"
        exit 1
    fi

    # Add invoker permission for the BigQuery connection service account
    echo "Adding Cloud Run invoker permission..."
    if ! gcloud run services add-iam-policy-binding "$SKYFLOW_SERVICE_NAME_HYPHENATED" \
        --region="$REGION" \
        --member="serviceAccount:${PROJECT_NUMBER}-compute@developer.gserviceaccount.com" \
        --role="roles/run.invoker"; then
        echo "Error: Failed to add IAM binding for $SKYFLOW_SERVICE_NAME"
        cd "$current_dir"
        exit 1
    fi

    # Grant Secret Manager access to the Cloud Run service account
    echo "Granting Secret Manager access..."
    if ! gcloud projects add-iam-policy-binding $PROJECT_ID \
        --member="serviceAccount:${PROJECT_NUMBER}-compute@developer.gserviceaccount.com" \
        --role="roles/secretmanager.secretAccessor"; then
        echo "Error: Failed to grant Secret Manager access"
        cd "$current_dir"
        exit 1
    fi
    
    # Return to original directory
    cd "$current_dir"
    
    # Export endpoint
    export SKYFLOW_ENDPOINT=$endpoint
    
    echo "Cloud Run deployment successful for $SKYFLOW_SERVICE_NAME"
}

deploy_services() {
    # Deploy unified Skyflow service
    deploy_cloud_run
}

cleanup_resources() {
    echo "Deleting Cloud Run service..."
    # Delete service
    gcloud run services delete "$SKYFLOW_SERVICE_NAME_HYPHENATED" --region=$REGION --quiet
}
