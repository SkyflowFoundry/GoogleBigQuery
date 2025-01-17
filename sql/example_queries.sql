-- Example: Tokenize specific columns in a table
SELECT ${PROJECT_ID}.${DATASET}.${PREFIX}_skyflow_tokenize_table( 
  '${PROJECT_ID}.${DATASET}.${TABLE}',
  'first_name,last_name,email'
);

-- Example: Query with both tokenize and detokenize
SELECT customer_id,
  ${PROJECT_ID}.${DATASET}.${PREFIX}_skyflow_detokenize(email) as email,
  ${PROJECT_ID}.${DATASET}.${PREFIX}_skyflow_detokenize(first_name) as first_name
FROM ${PROJECT_ID}.${DATASET}.${TABLE}
WHERE first_name = ${PROJECT_ID}.${DATASET}.${PREFIX}_skyflow_tokenize('Jonathan');

-- Example: Multiple conditions with tokenization
SELECT * FROM ${PROJECT_ID}.${DATASET}.${TABLE}
WHERE first_name = ${PROJECT_ID}.${DATASET}.${PREFIX}_skyflow_tokenize('Jonathan')
   OR email = ${PROJECT_ID}.${DATASET}.${PREFIX}_skyflow_tokenize('jonathan@example.com');

-- Example: Using IN clause with tokenization
SELECT * FROM ${PROJECT_ID}.${DATASET}.${TABLE}
WHERE email IN (
    SELECT ${PROJECT_ID}.${DATASET}.${PREFIX}_skyflow_tokenize(email)
    FROM new_emails_table
);

-- Example: Detokenize specific columns in results
SELECT 
    customer_id,
    ${PROJECT_ID}.${DATASET}.${PREFIX}_skyflow_detokenize(email) as email,
    ${PROJECT_ID}.${DATASET}.${PREFIX}_skyflow_detokenize(first_name) as first_name,
    ${PROJECT_ID}.${DATASET}.${PREFIX}_skyflow_detokenize(last_name) as last_name,
    signup_date,
    total_purchases
FROM ${PROJECT_ID}.${DATASET}.${TABLE}
WHERE total_purchases > 100;
