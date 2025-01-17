CREATE OR REPLACE TABLE ${PROJECT_ID}.${DATASET}.${TABLE} (
    customer_id STRING NOT NULL,
    first_name STRING,
    last_name STRING,
    email STRING,
    phone_number STRING,
    address STRING,
    date_of_birth STRING,
    signup_date TIMESTAMP,
    last_login TIMESTAMP,
    total_purchases INT64,
    total_spent FLOAT64,
    loyalty_status STRING,
    preferred_language STRING,
    consent_marketing BOOLEAN,
    consent_data_sharing BOOLEAN,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP
);
