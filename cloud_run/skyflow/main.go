// Package main implements a unified Skyflow service for tokenization and detokenization.
package main

import (
    "cloud.google.com/go/bigquery"
    secretmanager "cloud.google.com/go/secretmanager/apiv1"
    secretmanagerpb "google.golang.org/genproto/googleapis/cloud/secretmanager/v1"
    cloudresourcemanager "google.golang.org/api/cloudresourcemanager/v1"
    "google.golang.org/api/iterator"
    "bytes"
    "context"
    "crypto"
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha256"
    "crypto/x509"
    "encoding/base64"
    "encoding/json"
    "encoding/pem"
    "errors"
    "fmt"
    "io/ioutil"
    "log"
    "net/http"
    "os"
    "strconv"
    "strings"
    "sync"
    "time"
)

// Operation types and constants
const (
    OpTokenizeValue = "tokenize_value"
    OpTokenizeTable = "tokenize_table"
    OpDetokenize    = "detokenize"

    // Minimum length for PII values
    minPiiLength = 7
)

// Role types
const (
    RoleSkyflowAdmin     = "skyflow_admin"
    RoleSkyflowCS        = "skyflow_cs"
    RoleSkyflowMarketing = "skyflow_marketing"
)

// Role to Skyflow ID mapping
var roleScopes = map[string]string{
    RoleSkyflowAdmin:     "ufea24a62a2d461e97f155b81c5da5b7",   // Full access
    RoleSkyflowCS:        "ac917e7c350543a2990d0e4bff61fc00",   // Masked access
    RoleSkyflowMarketing: "oe572f8d5cef4077b182c2c6a549bf16",   // No access
}

// Operation to required roles mapping
var operationRoles = map[string][]string{
    OpTokenizeValue: {RoleSkyflowAdmin, RoleSkyflowCS, RoleSkyflowMarketing},
    OpTokenizeTable: {RoleSkyflowAdmin},
    OpDetokenize:    {RoleSkyflowAdmin, RoleSkyflowCS, RoleSkyflowMarketing},
}

// Cache structure for tokenization results (within same request)
type tokenPromise struct {
    done  chan struct{}
    token string
    err   error
}

var (
    // Cache for in-flight requests
    inFlightRequests sync.Map // value -> *tokenPromise
    // Cache for bearer tokens
    bearerTokenCache sync.Map // roleID:userEmail -> token
    mutex            sync.Mutex
    credentials      *SkyflowCredentials
)

// SkyflowCredentials holds the credentials from credentials.json
type SkyflowCredentials struct {
    ClientID           string `json:"clientID"`
    ClientName         string `json:"clientName"`
    TokenURI          string `json:"tokenURI"`
    KeyID             string `json:"keyID"`
    PrivateKey        string `json:"privateKey"`
    KeyValidAfterTime  string `json:"keyValidAfterTime"`
    KeyValidBeforeTime string `json:"keyValidBeforeTime"`
    KeyAlgorithm      string `json:"keyAlgorithm"`
}

// BigQueryRequest represents the request from BigQuery
type BigQueryRequest struct {
    Calls             [][]interface{} `json:"calls"`
    SessionUser       string          `json:"sessionUser"`
    RequestID         string          `json:"requestId"`
    Caller           string          `json:"caller"`
    UserDefinedContext json.RawMessage `json:"userDefinedContext"`
}

type BigQueryResponse struct {
    Replies []interface{} `json:"replies"`
}

// TokenizeValueRequest represents the request for single value tokenization
type TokenizeValueRequest struct {
    TokenizationParameters []struct {
        Column string `json:"column"`
        Table  string `json:"table"`
        Value  string `json:"value"`
    } `json:"tokenizationParameters"`
}

// TokenizeValueResponse represents the response for single value tokenization
type TokenizeValueResponse struct {
    Records []struct {
        Token string `json:"token"`
    } `json:"records"`
}

// TokenizeTableRequest represents the request for table tokenization
type TokenizeTableRequest struct {
    Records      []Record `json:"records"`
    Tokenization bool     `json:"tokenization"`
}

type Record struct {
    Fields map[string]string `json:"fields"`
    Table  string           `json:"table"`
}

// DetokenizeRequest represents the request for detokenization
type DetokenizeRequest struct {
    DetokenizationParameters []TokenParam `json:"detokenizationParameters"`
}

type TokenParam struct {
    Token     string `json:"token"`
    Redaction string `json:"redaction,omitempty"`
}

// DetokenizeResponse represents the response for detokenization
type DetokenizeResponse struct {
    Records []DetokenizedRecord `json:"records"`
}

type DetokenizedRecord struct {
    Token     string      `json:"token"`
    ValueType string      `json:"valueType"`
    Value     string      `json:"value"`
    Error     interface{} `json:"error"`
}

// hasRequiredRole checks if the user has any of the required roles
func hasRequiredRole(userRoles []string, requiredRoles []string) (string, bool) {
    for _, userRole := range userRoles {
        roleName := extractRoleName(userRole)
        for _, required := range requiredRoles {
            if roleName == required {
                return roleName, true
            }
        }
    }
    return "", false
}

// extractRoleName gets the base role name from a full role string
func extractRoleName(role string) string {
    if strings.HasPrefix(role, "roles/") {
        return role[len("roles/"):]
    }
    if strings.HasPrefix(role, "projects/") {
        parts := strings.Split(role, "/")
        if len(parts) >= 4 && parts[2] == "roles" {
            return parts[3]
        }
    }
    return role
}

func main() {
    http.HandleFunc("/", handleRequest)
    port := os.Getenv("PORT")
    if port == "" {
        port = "8080"
    }
    log.Printf("Starting unified Skyflow service on port %s", port)
    if err := http.ListenAndServe(":"+port, nil); err != nil {
        log.Fatal(err)
    }
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
        return
    }

    // Read request body
    body, err := ioutil.ReadAll(r.Body)
    if err != nil {
        http.Error(w, fmt.Sprintf("Error reading request body: %v", err), http.StatusBadRequest)
        return
    }
    log.Printf("Received request body: %s", string(body))

    // Parse request
    var bqReq BigQueryRequest
    if err := json.Unmarshal(body, &bqReq); err != nil {
        http.Error(w, fmt.Sprintf("Error decoding request: %v", err), http.StatusBadRequest)
        return
    }

    // Validate session user
    if bqReq.SessionUser == "" {
        http.Error(w, "SessionUser is required", http.StatusBadRequest)
        return
    }

    // Get operation from userDefinedContext
    var userContext struct {
        Operation string `json:"operation"`
    }
    if err := json.Unmarshal(bqReq.UserDefinedContext, &userContext); err != nil {
        http.Error(w, fmt.Sprintf("Error parsing user defined context: %v", err), http.StatusBadRequest)
        return
    }
    operation := userContext.Operation
    if operation == "" {
        http.Error(w, "Operation not specified in user_defined_context", http.StatusBadRequest)
        return
    }

    // Get user roles
    roles, err := getUserRoles(r.Context(), bqReq.SessionUser)
    if err != nil {
        http.Error(w, fmt.Sprintf("Error getting user roles: %v", err), http.StatusInternalServerError)
        return
    }

    // Check if user has required role
    roleName, hasRole := hasRequiredRole(roles, operationRoles[operation])
    if !hasRole {
        http.Error(w, fmt.Sprintf("User does not have required role for %s operation", operation), http.StatusForbidden)
        return
    }

    // Handle operation
    var response interface{}
    switch operation {
    case OpTokenizeValue:
        response, err = handleTokenizeValue(bqReq)
    case OpTokenizeTable:
        response, err = handleTokenizeTable(bqReq)
    case OpDetokenize:
        response, err = handleDetokenize(bqReq, roleName)
    default:
        http.Error(w, fmt.Sprintf("Unknown operation: %s", operation), http.StatusBadRequest)
        return
    }

    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    // Return response
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}

// handleTokenizeValue handles single value tokenization requests
func handleTokenizeValue(req BigQueryRequest) (*BigQueryResponse, error) {
    value, ok := req.Calls[0][0].(string)
    if !ok {
        return nil, fmt.Errorf("invalid value format: expected string")
    }

    if value == "" {
        return &BigQueryResponse{Replies: []interface{}{value}}, nil
    }

    // Check/create in-flight promise
    promise := &tokenPromise{done: make(chan struct{})}
    actual, loaded := inFlightRequests.LoadOrStore(value, promise)
    if loaded {
        // Another request is already processing this value
        log.Printf("Waiting for in-flight request for value: %s", value)
        p := actual.(*tokenPromise)
        <-p.done  // Wait for it to complete
        return &BigQueryResponse{Replies: []interface{}{p.token}}, p.err
    }

    // We're the first request, get the token from Skyflow
    log.Printf("Making Skyflow API call for value: %s", value)
    
    // Create request payload
    skyflowReq := TokenizeValueRequest{
        TokenizationParameters: []struct {
            Column string `json:"column"`
            Table  string `json:"table"`
            Value  string `json:"value"`
        }{
            {
                Column: "pii",
                Table:  os.Getenv("SKYFLOW_TABLE_NAME"),
                Value:  value,
            },
        },
    }

    // Get bearer token
    bearerToken, err := getBearerToken(req.SessionUser, "")
    if err != nil {
        promise.err = err
        close(promise.done)
        inFlightRequests.Delete(value)
        return nil, err
    }

    // Make request
    jsonData, err := json.Marshal(skyflowReq)
    if err != nil {
        promise.err = err
        close(promise.done)
        inFlightRequests.Delete(value)
        return nil, err
    }

    skyflowURL := os.Getenv("SKYFLOW_VAULT_URL") + "/tokenize"
    httpReq, err := http.NewRequest("POST", skyflowURL, bytes.NewBuffer(jsonData))
    if err != nil {
        promise.err = err
        close(promise.done)
        inFlightRequests.Delete(value)
        return nil, err
    }

    httpReq.Header.Set("Content-Type", "application/json")
    httpReq.Header.Set("Accept", "application/json")
    httpReq.Header.Set("Authorization", "Bearer "+bearerToken)
    httpReq.Header.Set("X-SKYFLOW-ACCOUNT-ID", os.Getenv("SKYFLOW_ACCOUNT_ID"))

    client := &http.Client{}
    resp, err := client.Do(httpReq)
    if err != nil {
        promise.err = err
        close(promise.done)
        inFlightRequests.Delete(value)
        return nil, err
    }
    defer resp.Body.Close()

    // Handle 404 by returning empty string
    if resp.StatusCode == http.StatusNotFound {
        log.Printf("Skyflow returned 404 for value: %s, returning empty string", value)
        promise.token = ""
        close(promise.done)
        inFlightRequests.Delete(value)
        return &BigQueryResponse{Replies: []interface{}{""}}, nil
    }

    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        promise.err = err
        close(promise.done)
        inFlightRequests.Delete(value)
        return nil, err
    }

    if resp.StatusCode != http.StatusOK {
        err = fmt.Errorf("unexpected status code %d: %s", resp.StatusCode, string(body))
        promise.err = err
        close(promise.done)
        inFlightRequests.Delete(value)
        return nil, err
    }

    var tokenResp TokenizeValueResponse
    if err := json.Unmarshal(body, &tokenResp); err != nil {
        promise.err = err
        close(promise.done)
        inFlightRequests.Delete(value)
        return nil, err
    }

    if len(tokenResp.Records) == 0 {
        err = fmt.Errorf("no records in response")
        promise.err = err
        close(promise.done)
        inFlightRequests.Delete(value)
        return nil, err
    }

    // Store result and signal completion
    promise.token = tokenResp.Records[0].Token
    close(promise.done)
    inFlightRequests.Delete(value)

    return &BigQueryResponse{Replies: []interface{}{tokenResp.Records[0].Token}}, nil
}

// handleTokenizeTable handles table tokenization requests
func handleTokenizeTable(req BigQueryRequest) (*BigQueryResponse, error) {
    tableName, ok := req.Calls[0][0].(string)
    if !ok {
        return nil, fmt.Errorf("invalid table name format")
    }

    columns, ok := req.Calls[0][1].(string)
    if !ok {
        return nil, fmt.Errorf("invalid columns format")
    }

    if tableName == "" || columns == "" {
        return nil, fmt.Errorf("table name and columns are required")
    }

    // Split columns and build query
    columnList := strings.Split(columns, ",")
    for i, col := range columnList {
        columnList[i] = strings.TrimSpace(col)
    }
    query := fmt.Sprintf("SELECT %s FROM `%s`", strings.Join(columnList, ", "), tableName)
    log.Printf("Executing query: %s", query)
    bqData, err := queryBigQuery(query)
    if err != nil {
        return nil, fmt.Errorf("error querying BigQuery: %v", err)
    }

    // Get batch sizes from environment variables
    skyflowBatchSize := 25 // default
    if batchStr := os.Getenv("SKYFLOW_INSERT_BATCH_SIZE"); batchStr != "" {
        if val, err := strconv.Atoi(batchStr); err == nil && val > 0 {
            skyflowBatchSize = val
        }
    }

    bigqueryBatchSize := 1000 // default
    if batchStr := os.Getenv("BIGQUERY_UPDATE_BATCH_SIZE"); batchStr != "" {
        if val, err := strconv.Atoi(batchStr); err == nil && val > 0 {
            bigqueryBatchSize = val
        }
    }

    // Process values in batches for each column
    columnTokenMaps := make(map[string]map[string]string) // column -> (original -> token)
    for _, column := range columnList {
        columnTokenMaps[column] = make(map[string]string)
    }

    // Get bearer token
    bearerToken, err := getBearerToken(req.SessionUser, "")
    if err != nil {
        return nil, err
    }

    batch := make([]Record, 0, skyflowBatchSize)
    for _, row := range bqData {
        for colIdx, column := range columnList {
            value := row[colIdx]
            strValue := fmt.Sprintf("%v", value)
            if value == nil || strValue == "" {
                continue
            }

            // Skip values that don't meet minimum length requirement
            if len(strValue) < minPiiLength {
                log.Printf("Skipping value with length %d for column %s (minimum required: %d)",
                    len(strValue), column, minPiiLength)
                continue
            }

            batch = append(batch, Record{
                Fields: map[string]string{
                    "pii": strValue,
                },
                Table: column, // Use column name to track which column this record belongs to
            })

            // When batch is full, send the request
            if len(batch) == skyflowBatchSize {
                if err := processBatch(batch, columnTokenMaps, bearerToken); err != nil {
                    return nil, fmt.Errorf("error processing batch: %v", err)
                }
                batch = make([]Record, 0, skyflowBatchSize)
            }
        }
    }

    // Process any remaining records in the final batch
    if len(batch) > 0 {
        if err := processBatch(batch, columnTokenMaps, bearerToken); err != nil {
            return nil, fmt.Errorf("error processing final batch: %v", err)
        }
    }

    // Process updates in batches to avoid query size limits
    for column, valueTokenMap := range columnTokenMaps {
        if len(valueTokenMap) == 0 {
            continue
        }

        // Convert map to slices for batch processing
        origValues := make([]string, 0, len(valueTokenMap))
        tokenValues := make([]string, 0, len(valueTokenMap))
        for origValue, tokenVal := range valueTokenMap {
            origValues = append(origValues, origValue)
            tokenValues = append(tokenValues, tokenVal)
        }

        // Process in batches
        for i := 0; i < len(origValues); i += bigqueryBatchSize {
            end := i + bigqueryBatchSize
            if end > len(origValues) {
                end = len(origValues)
            }

            batchOrig := origValues[i:end]
            batchTokens := tokenValues[i:end]

            cases := make([]string, 0, len(batchOrig))
            for j := range batchOrig {
                cases = append(cases, fmt.Sprintf("WHEN %s = '%s' THEN '%s'",
                    column,
                    strings.ReplaceAll(batchOrig[j], "'", "\\'"), // Escape single quotes
                    batchTokens[j]))
            }

            // Build and execute update query for this batch
            updateQuery := fmt.Sprintf(`
UPDATE %s
SET 
    %s = CASE %s ELSE %s END,
    updated_at = CURRENT_TIMESTAMP()
WHERE %s IN (%s)`,
                tableName,
                column,
                strings.Join(cases, " "),
                column,
                column,
                strings.Join(buildOriginalValuesList(
                    mapFromSlices(batchOrig, batchTokens)), ","))

            log.Printf("Executing batch update query for column %s (%d/%d values)",
                column, end, len(origValues))

            if err := executeUpdate(updateQuery); err != nil {
                return nil, fmt.Errorf("error updating table: %v", err)
            }
        }
    }

    // Calculate total number of tokenized values
    totalTokenized := 0
    for _, valueTokenMap := range columnTokenMaps {
        totalTokenized += len(valueTokenMap)
    }

    return &BigQueryResponse{
        Replies: []interface{}{fmt.Sprintf("Successfully tokenized %d values in columns: %s", totalTokenized, columns)},
    }, nil
}

// processBatch handles a batch of records for tokenization
func processBatch(batch []Record, columnTokenMaps map[string]map[string]string, bearerToken string) error {
    skyflowReq := TokenizeTableRequest{
        Records:      batch,
        Tokenization: true,
    }

    // Make request
    jsonData, err := json.Marshal(skyflowReq)
    if err != nil {
        return fmt.Errorf("error marshaling request: %v", err)
    }

    skyflowURL := os.Getenv("SKYFLOW_VAULT_URL") + "/" + os.Getenv("SKYFLOW_TABLE_NAME")
    httpReq, err := http.NewRequest("POST", skyflowURL, bytes.NewBuffer(jsonData))
    if err != nil {
        return fmt.Errorf("error creating request: %v", err)
    }

    httpReq.Header.Set("Content-Type", "application/json")
    httpReq.Header.Set("Accept", "application/json")
    httpReq.Header.Set("Authorization", "Bearer "+bearerToken)
    httpReq.Header.Set("X-SKYFLOW-ACCOUNT-ID", os.Getenv("SKYFLOW_ACCOUNT_ID"))

    client := &http.Client{}
    resp, err := client.Do(httpReq)
    if err != nil {
        return fmt.Errorf("error making request: %v", err)
    }
    defer resp.Body.Close()

    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        return fmt.Errorf("error reading response: %v", err)
    }

    if resp.StatusCode != http.StatusOK {
        return fmt.Errorf("unexpected status code %d: %s", resp.StatusCode, string(body))
    }

    var skyflowResp struct {
        Records []struct {
            SkyflowID string            `json:"skyflow_id"`
            Tokens    map[string]string `json:"tokens"`
        } `json:"records"`
    }
    if err := json.Unmarshal(body, &skyflowResp); err != nil {
        return fmt.Errorf("error unmarshaling response: %v", err)
    }

    // Map tokens back to their respective columns
    for i, record := range skyflowResp.Records {
        if tokenValue, ok := record.Tokens["pii"]; ok {
            column := batch[i].Table
            originalValue := batch[i].Fields["pii"]
            columnTokenMaps[column][originalValue] = tokenValue
        }
    }

    return nil
}

// handleDetokenize handles detokenization requests
func handleDetokenize(req BigQueryRequest, roleName string) (*BigQueryResponse, error) {
    // Get role scope
    roleID := roleScopes[roleName]
    if roleID == "" {
        return nil, fmt.Errorf("invalid role: %s", roleName)
    }

    // Get batch size from environment variable
    batchSize := 25 // default
    if batchStr := os.Getenv("SKYFLOW_DETOKENIZE_BATCH_SIZE"); batchStr != "" {
        if val, err := strconv.Atoi(batchStr); err == nil && val > 0 {
            batchSize = val
        }
    }

    // Process tokens in batches
    allResponses := make([]interface{}, 0, len(req.Calls))
    for i := 0; i < len(req.Calls); i += batchSize {
        end := i + batchSize
        if end > len(req.Calls) {
            end = len(req.Calls)
        }

        batch := req.Calls[i:end]
        detokenizeReq := DetokenizeRequest{
            DetokenizationParameters: make([]TokenParam, len(batch)),
        }

        for j, call := range batch {
            if len(call) == 0 {
                continue
            }
            
            // Extract token and optional redaction level
            tokenStr := ""
            redaction := "DEFAULT"
            
            if tokenVal, ok := call[0].(string); ok {
                tokenStr = tokenVal
            }
            
            if len(call) > 1 {
                if redactionVal, ok := call[1].(string); ok {
                    redaction = redactionVal
                }
            }
            
            detokenizeReq.DetokenizationParameters[j] = TokenParam{
                Token:     tokenStr,
                Redaction: redaction,
            }
        }

        // Make Skyflow request
        resp, err := makeSkyflowRequest(detokenizeReq, req.SessionUser, roleID)
        if err != nil {
            log.Printf("Error making Skyflow request: %v", err)
            for range batch {
                allResponses = append(allResponses, nil)
            }
            continue
        }

        // Map responses back to original order
        for j := range batch {
            if j < len(resp.Records) && resp.Records[j].Error == nil {
                allResponses = append(allResponses, resp.Records[j].Value)
            } else {
                allResponses = append(allResponses, nil)
            }
        }
    }

    return &BigQueryResponse{Replies: allResponses}, nil
}

// getUserRoles fetches user roles from Cloud Resource Manager
func getUserRoles(ctx context.Context, email string) ([]string, error) {
    // Get project ID from environment variable
    projectID := os.Getenv("PROJECT_ID")
    if projectID == "" {
        return nil, fmt.Errorf("PROJECT_ID environment variable not set")
    }

    // Initialize the Cloud Resource Manager client with default credentials
    client, err := cloudresourcemanager.NewService(ctx)
    if err != nil {
        return nil, fmt.Errorf("failed to create Cloud Resource Manager client: %v", err)
    }

    // Get IAM Policy
    policy, err := client.Projects.GetIamPolicy(projectID, &cloudresourcemanager.GetIamPolicyRequest{}).Context(ctx).Do()
    if err != nil {
        return nil, fmt.Errorf("failed to get IAM policy: %v", err)
    }

    // Find roles for the user
    roles := make([]string, 0, len(policy.Bindings))
    for _, binding := range policy.Bindings {
        for _, member := range binding.Members {
            if strings.EqualFold(member, fmt.Sprintf("user:%s", email)) {
                roles = append(roles, binding.Role)
            }
        }
    }

    return roles, nil
}

// getBearerToken gets a bearer token from Skyflow with optional role scope
func getBearerToken(userEmail string, roleID string) (string, error) {
    mutex.Lock()
    defer mutex.Unlock()

    // Generate cache key
    key := userEmail
    if roleID != "" {
        key = fmt.Sprintf("%s:%s", roleID, userEmail)
    }

    // Check cache
    if token, ok := bearerTokenCache.Load(key); ok {
        return token.(string), nil
    }

    // Load credentials from Secret Manager
    creds, err := getCredentials()
    if err != nil {
        return "", err
    }

    // Generate JWT token
    signedToken, err := generateJWTToken(creds, userEmail)
    if err != nil {
        return "", err
    }

    // Prepare token request
    tokenData := map[string]string{
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion":  signedToken,
    }
    if roleID != "" {
        tokenData["scope"] = fmt.Sprintf("role:%s", roleID)
    }

    tokenJSON, err := json.Marshal(tokenData)
    if err != nil {
        return "", err
    }

    // Make request
    req, err := http.NewRequest("POST", creds.TokenURI, bytes.NewBuffer(tokenJSON))
    if err != nil {
        return "", err
    }
    req.Header.Set("Content-Type", "application/json")

    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        return "", err
    }
    defer resp.Body.Close()

    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        return "", err
    }

    if resp.StatusCode != http.StatusOK {
        return "", fmt.Errorf("failed to get bearer token: %s", string(body))
    }

    var response map[string]interface{}
    if err := json.Unmarshal(body, &response); err != nil {
        return "", err
    }

    accessToken, ok := response["accessToken"].(string)
    if !ok || accessToken == "" {
        return "", fmt.Errorf("no accessToken in response")
    }

    // Cache token
    bearerTokenCache.Store(key, accessToken)

    return accessToken, nil
}

// getCredentials loads credentials from Secret Manager
func getCredentials() (*SkyflowCredentials, error) {
    if credentials != nil {
        return credentials, nil
    }

    ctx := context.Background()
    client, err := secretmanager.NewClient(ctx)
    if err != nil {
        return nil, fmt.Errorf("failed to create secretmanager client: %v", err)
    }
    defer client.Close()

    // Get project ID from environment variable
    projectID := os.Getenv("PROJECT_ID")
    if projectID == "" {
        return nil, fmt.Errorf("PROJECT_ID environment variable not set")
    }

    // Get prefix from environment variable
    prefix := os.Getenv("PREFIX")
    if prefix == "" {
        return nil, fmt.Errorf("PREFIX environment variable not set")
    }

    // Access the latest version of the secret
    secretName := fmt.Sprintf("projects/%s/secrets/%s_credentials/versions/latest", projectID, prefix)
    result, err := client.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
        Name: secretName,
    })
    if err != nil {
        return nil, fmt.Errorf("failed to access secret version: %v", err)
    }

    // Parse the JSON data
    var creds SkyflowCredentials
    err = json.Unmarshal(result.Payload.Data, &creds)
    if err != nil {
        return nil, fmt.Errorf("failed to unmarshal credentials: %v", err)
    }

    credentials = &creds
    return credentials, nil
}

// getSecret gets a secret from Secret Manager
func getSecret(secretName string) ([]byte, error) {
    ctx := context.Background()
    client, err := secretmanager.NewClient(ctx)
    if err != nil {
        return nil, fmt.Errorf("failed to create Secret Manager client: %w", err)
    }
    defer client.Close()

    projectID := os.Getenv("PROJECT_ID")
    if projectID == "" {
        return nil, fmt.Errorf("PROJECT_ID environment variable is not set")
    }

    prefix := os.Getenv("PREFIX")
    if prefix == "" {
        return nil, fmt.Errorf("PREFIX environment variable is not set")
    }

    accessRequest := &secretmanagerpb.AccessSecretVersionRequest{
        Name: fmt.Sprintf("projects/%s/secrets/%s_%s/versions/latest", projectID, prefix, secretName),
    }
    result, err := client.AccessSecretVersion(ctx, accessRequest)
    if err != nil {
        return nil, fmt.Errorf("failed to access secret version: %w", err)
    }

    return result.Payload.Data, nil
}

// generateJWTToken generates a JWT token for Skyflow authentication
func generateJWTToken(creds *SkyflowCredentials, userEmail string) (string, error) {
    // Decode private key
    block, _ := pem.Decode([]byte(creds.PrivateKey))
    if block == nil {
        return "", errors.New("failed to parse PEM block containing the private key")
    }

    privKeyInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
    if err != nil {
        return "", err
    }
    privKey, ok := privKeyInterface.(*rsa.PrivateKey)
    if !ok {
        return "", errors.New("not an RSA private key")
    }

    // Create JWT header and claims
    header := map[string]interface{}{
        "alg": "RS256",
        "typ": "JWT",
    }

    now := time.Now().Unix()
    claims := map[string]interface{}{
        "iss": creds.ClientID,
        "key": creds.KeyID,
        "aud": creds.TokenURI,
        "exp": now + 3600,
        "sub": creds.ClientID,
        "ctx": userEmail,
    }

    // Encode header and claims
    headerBytes, err := json.Marshal(header)
    if err != nil {
        return "", err
    }
    claimsBytes, err := json.Marshal(claims)
    if err != nil {
        return "", err
    }

    // Base64URL encode header and claims
    encodedHeader := base64.RawURLEncoding.EncodeToString(headerBytes)
    encodedClaims := base64.RawURLEncoding.EncodeToString(claimsBytes)

    // Create unsigned token
    unsignedToken := encodedHeader + "." + encodedClaims

    // Create signature
    hash := sha256.Sum256([]byte(unsignedToken))
    signature, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hash[:])
    if err != nil {
        return "", err
    }

    // Base64URL encode signature
    encodedSignature := base64.RawURLEncoding.EncodeToString(signature)

    // Combine to create signed token
    return unsignedToken + "." + encodedSignature, nil
}

// queryBigQuery executes a query and returns the results
func queryBigQuery(query string) ([][]interface{}, error) {
    ctx := context.Background()

    client, err := bigquery.NewClient(ctx, os.Getenv("PROJECT_ID"))
    if err != nil {
        return nil, fmt.Errorf("error creating BigQuery client: %v", err)
    }
    defer client.Close()

    q := client.Query(query)
    it, err := q.Read(ctx)
    if err != nil {
        return nil, fmt.Errorf("error executing query: %v", err)
    }

    rows := make([][]interface{}, 0)
    for {
        row := make([]bigquery.Value, 0)
        err := it.Next(&row)
        if err == iterator.Done {
            break
        }
        if err != nil {
            return nil, fmt.Errorf("error reading row: %v", err)
        }
    // Convert BigQuery Values to interface{} slice
    interfaceRow := make([]interface{}, len(row))
    for i, v := range row {
        interfaceRow[i] = v
    }
    rows = append(rows, interfaceRow)
    }

    return rows, nil
}

// executeUpdate executes an update query
func executeUpdate(query string) error {
    ctx := context.Background()
    client, err := bigquery.NewClient(ctx, os.Getenv("PROJECT_ID"))
    if err != nil {
        return fmt.Errorf("error creating BigQuery client: %v", err)
    }
    defer client.Close()

    q := client.Query(query)
    job, err := q.Run(ctx)
    if err != nil {
        return fmt.Errorf("error executing update: %v", err)
    }

    status, err := job.Wait(ctx)
    if err != nil {
        return fmt.Errorf("error waiting for job: %v", err)
    }

    if status.Err() != nil {
        return fmt.Errorf("job completed with error: %v", status.Err())
    }

    return nil
}

// Helper function to build list of original values for IN clause
func buildOriginalValuesList(valueTokenMap map[string]string) []string {
    values := make([]string, 0, len(valueTokenMap))
    for origValue := range valueTokenMap {
        values = append(values, fmt.Sprintf("'%s'",
            strings.ReplaceAll(origValue, "'", "\\'"))) // Escape single quotes
    }
    return values
}

// Helper function to create a map from two slices
func mapFromSlices(keys, values []string) map[string]string {
    m := make(map[string]string)
    for i := range keys {
        m[keys[i]] = values[i]
    }
    return m
}

// makeSkyflowRequest makes a request to the Skyflow API
func makeSkyflowRequest(req DetokenizeRequest, userEmail string, roleID string) (*DetokenizeResponse, error) {
    skyflowURL := os.Getenv("SKYFLOW_VAULT_URL") + "/detokenize"

    // Get bearer token with user context and role ID
    bearerToken, err := getBearerToken(userEmail, roleID)
    if err != nil {
        return nil, fmt.Errorf("error getting bearer token: %v", err)
    }

    jsonData, err := json.Marshal(req)
    if err != nil {
        return nil, fmt.Errorf("error marshaling request: %v", err)
    }

    httpReq, err := http.NewRequest("POST", skyflowURL, bytes.NewBuffer(jsonData))
    if err != nil {
        return nil, fmt.Errorf("error creating request: %v", err)
    }

    httpReq.Header.Set("Content-Type", "application/json")
    httpReq.Header.Set("Accept", "application/json")
    httpReq.Header.Set("Authorization", "Bearer "+bearerToken)
    httpReq.Header.Set("X-SKYFLOW-ACCOUNT-ID", os.Getenv("SKYFLOW_ACCOUNT_ID"))

    log.Printf("Making request to Skyflow API with %d tokens", len(req.DetokenizationParameters))

    client := &http.Client{}
    resp, err := client.Do(httpReq)
    if err != nil {
        return nil, fmt.Errorf("error making request: %v", err)
    }
    defer resp.Body.Close()

    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        return nil, fmt.Errorf("error reading response: %v", err)
    }

    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("unexpected status code %d: %s", resp.StatusCode, string(body))
    }

    var skyflowResp DetokenizeResponse
    if err := json.Unmarshal(body, &skyflowResp); err != nil {
        return nil, fmt.Errorf("error unmarshaling response: %v", err)
    }

    return &skyflowResp, nil
}
