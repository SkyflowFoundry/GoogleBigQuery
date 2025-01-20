#!/bin/bash

# Default values (can be overridden by environment variables)
DEFAULT_PROJECT_ID="solutionseng"
DEFAULT_REGION="us-west1"
DEFAULT_SKYFLOW_ACCOUNT_ID="e5ef2e2ffd44443b81cdf79f9dc7e8dd"
DEFAULT_SKYFLOW_VAULT_ID="d77559286eb94afbba350625d7e31c05"
DEFAULT_SKYFLOW_TABLE_NAME="pii"
DEFAULT_SKYFLOW_INSERT_BATCH_SIZE="25"
DEFAULT_SKYFLOW_DETOKENIZE_BATCH_SIZE="25"

# Project configuration
export PROJECT_ID="${PROJECT_ID:-$DEFAULT_PROJECT_ID}"
export DATASET="${PREFIX}_skyflow"
export TABLE="${PREFIX}_customer_data_platform"
export REGION="${REGION:-$DEFAULT_REGION}"

# Cloud Run configuration
export SKYFLOW_SERVICE_NAME="${PREFIX}_skyflow_service"
# Point to the Cloud Run code directory
export SKYFLOW_SOURCE_PATH="cloud_run/skyflow"

# Skyflow configuration
export SKYFLOW_ACCOUNT_ID="${SKYFLOW_ACCOUNT_ID:-$DEFAULT_SKYFLOW_ACCOUNT_ID}"
export SKYFLOW_VAULT_ID="${SKYFLOW_VAULT_ID:-$DEFAULT_SKYFLOW_VAULT_ID}"
export SKYFLOW_TABLE_NAME="${SKYFLOW_TABLE_NAME:-$DEFAULT_SKYFLOW_TABLE_NAME}"
export SKYFLOW_VAULT_URL="https://ebfc9bee4242.vault.skyflowapis.com/v1/vaults/${SKYFLOW_VAULT_ID}"

# Connection name for BigQuery
export CONNECTION_NAME="${PREFIX}_cloud_resource_connection"

# Store the hyphenated version of service name for SQL
export SKYFLOW_SERVICE_NAME_HYPHENATED=$(echo "$SKYFLOW_SERVICE_NAME" | tr '_' '-')

# Batch size configurations
export SKYFLOW_INSERT_BATCH_SIZE="${SKYFLOW_INSERT_BATCH_SIZE:-$DEFAULT_SKYFLOW_INSERT_BATCH_SIZE}"
export SKYFLOW_DETOKENIZE_BATCH_SIZE="${SKYFLOW_DETOKENIZE_BATCH_SIZE:-$DEFAULT_SKYFLOW_DETOKENIZE_BATCH_SIZE}"
export BIGQUERY_UPDATE_BATCH_SIZE="1000"
