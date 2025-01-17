CREATE OR REPLACE FUNCTION `${DATASET}.${PREFIX}_skyflow_tokenize_table`(
    table_name STRING,
    pii_columns STRING
)
RETURNS STRING
REMOTE WITH CONNECTION `${PROJECT_ID}.${REGION}.${CONNECTION_NAME}`
OPTIONS (
    endpoint = '${SKYFLOW_ENDPOINT}',
    user_defined_context = [
        ("operation", "tokenize_table")
    ]
);
