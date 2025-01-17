-- Check if the table has data and clear it
SELECT * FROM ${PROJECT_ID}.${DATASET}.${TABLE};
DELETE FROM ${PROJECT_ID}.${DATASET}.${TABLE} WHERE TRUE;

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
WITH random_data AS (
  SELECT
    CONCAT('CUST', FORMAT('%05d', x + 1)) AS customer_id,
    CASE 
      WHEN RAND() < 0.25 THEN 'Jonathan' 
      WHEN RAND() < 0.5 THEN 'Jessica'
      WHEN RAND() < 0.75 THEN 'Michael'
      ELSE 'Stephanie' 
    END AS first_name,
    CASE 
      WHEN RAND() < 0.25 THEN 'Anderson' 
      WHEN RAND() < 0.5 THEN 'Williams' 
      WHEN RAND() < 0.75 THEN 'Johnson'
      ELSE 'Johnson'
    END AS last_name,
    CONCAT(
      LOWER(CASE 
        WHEN RAND() < 0.25 THEN 'jonathan' 
        WHEN RAND() < 0.5 THEN 'jessica' 
        WHEN RAND() < 0.75 THEN 'michael' 
        ELSE 'sarah' 
      END), '.', 
      LOWER(SUBSTR(TO_HEX(MD5(CAST(RAND() AS STRING))), 1, 8)), '@example.com'
    ) AS email,
    CONCAT(
      '+1-', 
      CAST(FLOOR(100 + RAND() * 900) AS STRING), '-',
      CAST(FLOOR(100 + RAND() * 900) AS STRING), '-',
      CAST(FLOOR(1000 + RAND() * 9000) AS STRING)
    ) AS phone_number,
    CONCAT(
      FLOOR(10 + RAND() * 990), ' ',
      CASE 
        WHEN r < 0.1 THEN CONCAT(
          CASE WHEN RAND() < 0.5 THEN 'Oxford Street' ELSE 'Baker Street' END,
          ', London, England, SW1A 1AA'
        )
        WHEN r < 0.2 THEN CONCAT(
          CASE WHEN RAND() < 0.5 THEN 'Boulevard Saint-Michel' ELSE 'Rue de Rivoli' END,
          ', Paris, France, 75001'
        )
        WHEN r < 0.3 THEN CONCAT(
          CASE WHEN RAND() < 0.5 THEN 'Kurfürstendamm' ELSE 'Friedrichstrasse' END,
          ', Berlin, Germany, 10115'
        )
        WHEN r < 0.4 THEN CONCAT(
          CASE WHEN RAND() < 0.5 THEN 'Ginza-dori' ELSE 'Omotesando' END,
          ', Tokyo, Japan, 100-0001'
        )
        WHEN r < 0.5 THEN CONCAT(
          CASE WHEN RAND() < 0.5 THEN 'George Street' ELSE 'Pitt Street' END,
          ', Sydney, Australia, 2000'
        )
        WHEN r < 0.6 THEN CONCAT(
          CASE WHEN RAND() < 0.5 THEN 'Yonge Street' ELSE 'Bay Street' END,
          ', Toronto, Canada, M5H 2N2'
        )
        WHEN r < 0.7 THEN CONCAT(
          CASE WHEN RAND() < 0.5 THEN 'Orchard Road' ELSE 'Marina Bay' END,
          ', Singapore, 238859'
        )
        WHEN r < 0.8 THEN CONCAT(
          CASE WHEN RAND() < 0.5 THEN 'Sheikh Zayed Road' ELSE 'Jumeirah Beach Road' END,
          ', Dubai, UAE, 12345'
        )
        WHEN r < 0.9 THEN CONCAT(
          CASE WHEN RAND() < 0.5 THEN 'Avenida Paulista' ELSE 'Rua Oscar Freire' END,
          ', São Paulo, Brazil, 01310-000'
        )
        ELSE CONCAT(
          CASE WHEN RAND() < 0.5 THEN 'Marine Drive' ELSE 'Colaba Causeway' END,
          ', Mumbai, India, 400001'
        )
      END
    ) AS address,
    CONCAT(
      CAST(FLOOR(1950 + RAND() * 50) AS STRING), '-',
      LPAD(CAST(FLOOR(1 + RAND() * 12) AS STRING), 2, '0'), '-',
      LPAD(CAST(FLOOR(1 + RAND() * 28) AS STRING), 2, '0')
    ) AS date_of_birth,
    TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL CAST(RAND() * 3650 AS INT64) DAY) AS signup_date, -- Random past sign-up dates
    TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL CAST(RAND() * 365 AS INT64) DAY) AS last_login, -- Random recent logins
    CAST(FLOOR(1 + RAND() * 200) AS INT64) AS total_purchases,
    ROUND(RAND() * 25000, 2) AS total_spent,
    CASE 
      WHEN RAND() < 0.2 THEN 'Silver'
      WHEN RAND() < 0.5 THEN 'Gold'
      WHEN RAND() < 0.8 THEN 'Platinum'
      ELSE 'Diamond'
    END AS loyalty_status,
    CASE 
      WHEN RAND() < 0.5 THEN 'English' 
      ELSE 'Spanish' 
    END AS preferred_language,
    RAND() > 0.4 AS consent_marketing,
    RAND() > 0.6 AS consent_data_sharing,
    CURRENT_TIMESTAMP() AS created_at,
    CURRENT_TIMESTAMP() AS updated_at
  FROM UNNEST(GENERATE_ARRAY(0, 199)) AS x,
  (SELECT RAND() AS r)
)
SELECT *
FROM random_data;
