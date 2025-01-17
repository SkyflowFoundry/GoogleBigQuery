CREATE OR REPLACE FUNCTION `${DATASET}.${PREFIX}_skyflow_tokenize`(
    value STRING
)
RETURNS STRING
REMOTE WITH CONNECTION `${PROJECT_ID}.${REGION}.${CONNECTION_NAME}`
OPTIONS (
    endpoint = '${SKYFLOW_ENDPOINT}',
    max_batching_rows = 1,
    user_defined_context = [
        ("operation", "tokenize_value")
    ]
);
