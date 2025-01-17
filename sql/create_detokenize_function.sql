CREATE OR REPLACE FUNCTION `${DATASET}.${PREFIX}_skyflow_detokenize`(
    token STRING
)
RETURNS STRING
REMOTE WITH CONNECTION `${PROJECT_ID}.${REGION}.${CONNECTION_NAME}`
OPTIONS (
    endpoint = '${SKYFLOW_ENDPOINT}',
    user_defined_context = [
        ("operation", "detokenize")
    ]
);
