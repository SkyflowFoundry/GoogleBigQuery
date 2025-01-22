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
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP(),
    updated_at TIMESTAMP
);

-- Insert sample data into the table
INSERT INTO ${PROJECT_ID}.${DATASET}.${TABLE} (
    customer_id,
    first_name,
    last_name,
    email,
    phone_number,
    address,
    date_of_birth,
    signup_date,
    last_login,
    total_purchases,
    total_spent,
    loyalty_status,
    preferred_language,
    consent_marketing,
    consent_data_sharing,
    created_at,
    updated_at
)
WITH numbered_rows AS (
  SELECT id
  FROM UNNEST(GENERATE_ARRAY(1, 10)) AS id
),
base_data AS (
  SELECT
    id,
    CASE MOD(id, 4)
      WHEN 0 THEN 'Jonathan'
      WHEN 1 THEN 'Jessica'
      WHEN 2 THEN 'Michael'
      WHEN 3 THEN 'Stephanie'
    END AS first_name,
    CASE MOD(id, 4)
      WHEN 0 THEN 'Anderson'
      WHEN 1 THEN 'Williams'
      WHEN 2 THEN 'Johnson'
      WHEN 3 THEN 'Rodgers'
    END AS last_name,
    CASE MOD(id, 10)
      WHEN 0 THEN 'London, England, SW1A 1AA'
      WHEN 1 THEN 'Paris, France, 75001'
      WHEN 2 THEN 'Berlin, Germany, 10115'
      WHEN 3 THEN 'Tokyo, Japan, 100-0001'
      WHEN 4 THEN 'Sydney, Australia, 2000'
      WHEN 5 THEN 'Toronto, Canada, M5H 2N2'
      WHEN 6 THEN 'Singapore, 238859'
      WHEN 7 THEN 'Dubai, UAE, 12345'
      WHEN 8 THEN 'São Paulo, Brazil, 01310-000'
      ELSE 'Mumbai, India, 400001'
    END AS city
  FROM numbered_rows
)
SELECT
  CONCAT('CUST', FORMAT('%05d', id)) AS customer_id,
  first_name,
  last_name,
  LOWER(CONCAT(first_name, '.', last_name, CAST(id AS STRING), '@example.com')) AS email,
  CONCAT('+1-', FORMAT('%03d', 100 + MOD(id, 900)), '-', FORMAT('%03d', 100 + MOD(id * 2, 900)), '-', FORMAT('%04d', 1000 + MOD(id * 3, 9000))) AS phone_number,
  CONCAT(CAST(100 + MOD(id * 5, 900) AS STRING), ' Main Street, ', city) AS address,
  FORMAT_DATE('%Y-%m-%d', DATE_ADD(DATE '1950-01-01', INTERVAL id * 365 DAY)) AS date_of_birth,
  TIMESTAMP(DATE_ADD(DATE '2018-01-01', INTERVAL id - 1 DAY)) AS signup_date,
  TIMESTAMP(DATE_ADD(DATE '2023-01-01', INTERVAL id - 1 DAY)) AS last_login,
  id * 5 AS total_purchases,
  id * 50.00 AS total_spent,
  CASE MOD(id, 4)
    WHEN 0 THEN 'Silver'
    WHEN 1 THEN 'Gold'
    WHEN 2 THEN 'Platinum'
    WHEN 3 THEN 'Diamond'
  END AS loyalty_status,
  CASE MOD(id, 2) WHEN 0 THEN 'English' ELSE 'Spanish' END AS preferred_language,
  CASE MOD(id, 2) WHEN 0 THEN TRUE ELSE FALSE END AS consent_marketing,
  CASE MOD(id, 3) WHEN 0 THEN TRUE ELSE FALSE END AS consent_data_sharing,
  CURRENT_TIMESTAMP() AS created_at,
  CURRENT_TIMESTAMP() AS updated_at
FROM base_data;