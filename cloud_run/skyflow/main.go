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

// RoleConfig represents the role configuration loaded from Secret Manager
type RoleConfig struct {
    DefaultRoleID string        `json:"defaultRoleID"` // Default Skyflow role ID for unmapped roles
    RoleMappings  []RoleMapping `json:"roleMappings"`  // Direct mapping of Skyflow role IDs to Google roles
}

// RoleMapping represents a mapping between a Skyflow role ID and Google IAM roles
type RoleMapping struct {
    SkyflowRoleID string   `json:"skyflowRoleID"` // The Skyflow role ID to use
    GoogleRoles   []string `json:"googleRoles"`   // List of Google IAM roles that map to this Skyflow role
}

var (
    roleConfigCache struct {
        sync.RWMutex
        config    *RoleConfig
        timestamp time.Time
    }
)

const (
    // Cache duration for role configuration
    roleConfigCacheDuration = 30 * time.Second // Short duration to ensure updates are picked up quickly
)

// getRoleConfig safely retrieves the current role configuration, refreshing if needed
func getRoleConfig() *RoleConfig {
    roleConfigCache.RLock()
    if roleConfigCache.config != nil && time.Since(roleConfigCache.timestamp) < roleConfigCacheDuration {
        config := roleConfigCache.config
        roleConfigCache.RUnlock()
        log.Printf("[DEBUG] Using cached role configuration, age: %v", time.Since(roleConfigCache.timestamp))
        return config
    }
    roleConfigCache.RUnlock()

    // Cache miss or expired, acquire write lock
    roleConfigCache.Lock()
    defer roleConfigCache.Unlock()

    // Double check after acquiring write lock
    if roleConfigCache.config != nil && time.Since(roleConfigCache.timestamp) < roleConfigCacheDuration {
        log.Printf("[DEBUG] Using cached role configuration after write lock, age: %v", time.Since(roleConfigCache.timestamp))
        return roleConfigCache.config
    }

    // Load from Secret Manager
    sm, err := newSecretManager()
    if err != nil {
        log.Printf("[ERROR] Failed to create Secret Manager client: %v", err)
        if roleConfigCache.config != nil {
            log.Printf("[WARN] Using stale role configuration, age: %v", time.Since(roleConfigCache.timestamp))
            return roleConfigCache.config
        }
        log.Fatal("[FATAL] No role configuration available and failed to load from Secret Manager")
    }
    defer sm.Close()

    data, err := sm.getSecretData(context.Background(), "role_mappings")
    if err != nil {
        log.Printf("[ERROR] Failed to load role mappings from Secret Manager: %v", err)
        if roleConfigCache.config != nil {
            log.Printf("[WARN] Using stale role configuration, age: %v", time.Since(roleConfigCache.timestamp))
            return roleConfigCache.config
        }
        log.Fatal("[FATAL] No role configuration available and failed to load from Secret Manager")
    }

    var config RoleConfig
    if err := json.Unmarshal(data, &config); err != nil {
        log.Printf("[ERROR] Failed to unmarshal role configuration: %v", err)
        if roleConfigCache.config != nil {
            log.Printf("[WARN] Using stale role configuration, age: %v", time.Since(roleConfigCache.timestamp))
            return roleConfigCache.config
        }
        log.Fatal("[FATAL] No role configuration available and failed to unmarshal new configuration")
    }

    // Update cache
    roleConfigCache.config = &config
    roleConfigCache.timestamp = time.Now()

    log.Printf("[INFO] Successfully loaded role configuration from Secret Manager:")
    for i, roleMapping := range config.RoleMappings {
        log.Printf("[INFO] - Mapping %d: Skyflow role ID '%s' maps to Google roles: %v", 
            i+1, roleMapping.SkyflowRoleID, roleMapping.GoogleRoles)
    }

    return &config
}

// Operation types and constants
const (
    OpTokenizeValue = "tokenize_value"
    OpTokenizeTable = "tokenize_table"
    OpDetokenize    = "detokenize"

    // Minimum length for PII values
    minPiiLength = 7
)

// Operation to required roles mapping
var operationRoles = map[string][]string{
    OpTokenizeValue: {}, // Allow any role to run this BigQuery Function (controls only ability to run BigQuery function itself. PII access is controlled at Skyflow level via role mappings)
    OpTokenizeTable: {}, // Allow any role to run this BigQuery Function (controls only ability to run BigQuery function itself. PII access is controlled at Skyflow level via role mappings)
    OpDetokenize:    {}, // Allow any role to run this BigQuery Function (controls only ability to run BigQuery function itself. PII access is controlled at Skyflow level via role mappings)
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

// hasRequiredRole checks if the user has any of the required roles and returns the appropriate Skyflow role ID.
// For operations with no required roles (empty requiredRoles list), any role is allowed but will be mapped
// to its corresponding Skyflow role ID based on the role mappings configuration. Unmapped roles use the default role ID.
func hasRequiredRole(userRoles []string, requiredRoles []string) (string, bool) {
    config := getRoleConfig()

    // If no roles are required, we just need to map the user's role to a Skyflow role
    if len(requiredRoles) == 0 {
        log.Printf("[DEBUG] Mapping user roles to Skyflow role. User roles: %v", userRoles)
        // Check each of the user's Google IAM roles to see if any are mapped
        for _, userRole := range userRoles {
            log.Printf("[DEBUG] Checking role: %s", userRole)
            // Find which Skyflow role this Google role maps to
            for _, roleMapping := range config.RoleMappings {
                log.Printf("[DEBUG] Checking mapping with roles: %v", roleMapping.GoogleRoles)
                for _, googleRole := range roleMapping.GoogleRoles {
                    if googleRole == userRole {
                        log.Printf("[INFO] Found matching role! User role '%s' maps to Skyflow role ID: %s", userRole, roleMapping.SkyflowRoleID)
                        return roleMapping.SkyflowRoleID, true
                    }
                }
            }
        }
        // No mapped role found, use default role
        log.Printf("[WARN] No role mapping found for user roles: %v, using default role ID: %s", userRoles, config.DefaultRoleID)
        return config.DefaultRoleID, true
    }

    // For operations with required roles, check if user has any of them
    for _, userRole := range userRoles {
        for _, required := range requiredRoles {
            if userRole == required {
                // User has a required role, find its Skyflow mapping
                for _, roleMapping := range config.RoleMappings {
                    for _, googleRole := range roleMapping.GoogleRoles {
                        if googleRole == userRole {
                            return roleMapping.SkyflowRoleID, true
                        }
                    }
                }
                // Required role exists but isn't mapped, use default role
                log.Printf("[WARN] Required role %s exists but isn't mapped, using default role ID: %s", userRole, config.DefaultRoleID)
                return config.DefaultRoleID, true
            }
        }
    }
    
    // User has none of the required roles, use default role but return false to indicate lack of required role
    log.Printf("[WARN] User has none of the required roles, using default role ID: %s", config.DefaultRoleID)
    return config.DefaultRoleID, false
}

func main() {
    // Load initial role configuration
    getRoleConfig() // This will load and cache the initial configuration

    http.HandleFunc("/", handleRequest)
    port := os.Getenv("PORT")
    if port == "" {
        port = "8080"
    }
    log.Printf("[INFO] Starting unified Skyflow service on port %s", port)
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
    log.Printf("[INFO] Received request: Method=%s, ContentLength=%d", r.Method, r.ContentLength)
    log.Printf("[DEBUG] Request body: %s", string(body))

    // Parse request
    var bqReq BigQueryRequest
    if err := json.Unmarshal(body, &bqReq); err != nil {
        log.Printf("[ERROR] Failed to parse request body: %v", err)
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
        log.Printf("[ERROR] Failed to parse user defined context: %v", err)
        http.Error(w, fmt.Sprintf("Error parsing user defined context: %v", err), http.StatusBadRequest)
        return
    }
    operation := userContext.Operation
    log.Printf("[INFO] Processing %s operation for user: %s", operation, bqReq.SessionUser)
    if operation == "" {
        http.Error(w, "Operation not specified in user_defined_context", http.StatusBadRequest)
        return
    }

    // Get user roles
    log.Printf("[INFO] Getting roles for user: %s", bqReq.SessionUser)
    roles, err := getUserRoles(r.Context(), bqReq.SessionUser)
    log.Printf("[INFO] User roles: %v", roles)
    if err != nil {
        http.Error(w, fmt.Sprintf("Error getting user roles: %v", err), http.StatusInternalServerError)
        return
    }

    // Check if user has required role
    _, hasRole := hasRequiredRole(roles, operationRoles[operation])
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
        response, err = handleDetokenize(bqReq, roles)
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

    // Make request
    tokenResp, err := makeSkyflowAPIRequest[TokenizeValueRequest, TokenizeValueResponse]("/tokenize", skyflowReq, req.SessionUser, "")
    if err != nil {
        if strings.Contains(err.Error(), "404") {
            log.Printf("Skyflow returned 404 for value: %s, returning empty string", value)
            return completeTokenPromise(promise, value, "", nil)
        }
        return completeTokenPromise(promise, value, "", err)
    }

    if len(tokenResp.Records) == 0 {
        return completeTokenPromise(promise, value, "", fmt.Errorf("no records in response"))
    }

    return completeTokenPromise(promise, value, tokenResp.Records[0].Token, nil)
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

    // Get batch sizes
    skyflowBatchSize := getBatchSize("SKYFLOW_INSERT_BATCH_SIZE", 25)
    bigqueryBatchSize := getBatchSize("BIGQUERY_UPDATE_BATCH_SIZE", 1000)

    // Initialize column token maps
    columnTokenMaps := make(map[string]map[string]string) // column -> (original -> token)
    for _, column := range columnList {
        columnTokenMaps[column] = make(map[string]string)
    }

    // Prepare records for batch processing
    records := make([]Record, 0)
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

            records = append(records, Record{
                Fields: map[string]string{
                    "pii": strValue,
                },
                Table: column, // Use column name to track which column this record belongs to
            })
        }
    }

    // Process records in batches
    processor := func(batch []Record) ([]Record, error) {
        if err := processBatch(batch, columnTokenMaps, req.SessionUser); err != nil {
            return nil, fmt.Errorf("error processing batch: %v", err)
        }
        return batch, nil
    }

    _, err = batchProcessor(records, skyflowBatchSize, processor)
    if err != nil {
        return nil, err
    }

    // Process updates in batches
    for column, valueTokenMap := range columnTokenMaps {
        if len(valueTokenMap) == 0 {
            continue
        }

        // Convert map to slices for batch processing
        type updatePair struct {
            original string
            token    string
        }
        pairs := make([]updatePair, 0, len(valueTokenMap))
        for origValue, tokenVal := range valueTokenMap {
            pairs = append(pairs, updatePair{origValue, tokenVal})
        }

        // Process updates in batches
        processor := func(batch []updatePair) ([]updatePair, error) {
            cases := make([]string, 0, len(batch))
            for _, pair := range batch {
                cases = append(cases, fmt.Sprintf("WHEN %s = '%s' THEN '%s'",
                    column,
                    strings.ReplaceAll(pair.original, "'", "\\'"), // Escape single quotes
                    pair.token))
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
                    mapFromSlices(
                        func() ([]string, []string) {
                            orig := make([]string, len(batch))
                            tokens := make([]string, len(batch))
                            for i, pair := range batch {
                                orig[i] = pair.original
                                tokens[i] = pair.token
                            }
                            return orig, tokens
                        }())), ","))

            log.Printf("Executing batch update query for column %s (%d values)", column, len(batch))
            if err := executeUpdate(updateQuery); err != nil {
                return nil, fmt.Errorf("error updating table: %v", err)
            }
            return batch, nil
        }

        _, err = batchProcessor(pairs, bigqueryBatchSize, processor)
        if err != nil {
            return nil, err
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
func processBatch(batch []Record, columnTokenMaps map[string]map[string]string, userEmail string) error {
    skyflowReq := TokenizeTableRequest{
        Records:      batch,
        Tokenization: true,
    }

    // Make request
    skyflowResp, err := makeSkyflowAPIRequest[TokenizeTableRequest, struct {
        Records []struct {
            SkyflowID string            `json:"skyflow_id"`
            Tokens    map[string]string `json:"tokens"`
        } `json:"records"`
    }]("/"+os.Getenv("SKYFLOW_TABLE_NAME"), skyflowReq, userEmail, "")
    if err != nil {
        return fmt.Errorf("error making request: %v", err)
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
func handleDetokenize(req BigQueryRequest, userRoles []string) (*BigQueryResponse, error) {
    // Map user's Google roles to a Skyflow role ID
    roleID, hasRole := hasRequiredRole(userRoles, []string{})
    log.Printf("[INFO] Detokenize request from user with roles: %v, mapped to Skyflow role: %s", userRoles, roleID)
    if !hasRole {
        log.Printf("[WARN] User has no valid role mapping, defaulting to no access")
    }

    // Log current role configuration
    roleConfigCache.RLock()
    if roleConfigCache.config != nil {
        log.Printf("[DEBUG] Current role configuration (age: %v):", time.Since(roleConfigCache.timestamp))
        for i, roleMapping := range roleConfigCache.config.RoleMappings {
            log.Printf("[DEBUG] - Mapping %d: Skyflow role ID '%s' maps to Google roles: %v", 
                i+1, roleMapping.SkyflowRoleID, roleMapping.GoogleRoles)
        }
    } else {
        log.Printf("[WARN] No role configuration available")
    }
    roleConfigCache.RUnlock()
    batchSize := getBatchSize("SKYFLOW_DETOKENIZE_BATCH_SIZE", 25)

    // Process tokens in batches
    processor := func(batch [][]interface{}) ([]interface{}, error) {
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
        log.Printf("[INFO] Making request to Skyflow API with %d tokens using role ID: %s", len(detokenizeReq.DetokenizationParameters), roleID)
        resp, err := makeSkyflowAPIRequest[DetokenizeRequest, DetokenizeResponse]("/detokenize", detokenizeReq, req.SessionUser, roleID)
        if err != nil {
            log.Printf("[ERROR] Skyflow request failed: %v", err)
            return make([]interface{}, len(batch)), nil
        }

        // Map responses back to original order
        results := make([]interface{}, len(batch))
        for j := range batch {
            if j < len(resp.Records) {
                if resp.Records[j].Error != nil {
                    log.Printf("[ERROR] Skyflow error for token %s: %v", detokenizeReq.DetokenizationParameters[j].Token, resp.Records[j].Error)
                } else {
                    log.Printf("[DEBUG] Skyflow response for token %s: value=%s, type=%s", 
                        detokenizeReq.DetokenizationParameters[j].Token,
                        resp.Records[j].Value,
                        resp.Records[j].ValueType)
                    results[j] = resp.Records[j].Value
                }
            }
        }
        return results, nil
    }

    results, err := batchProcessor(req.Calls, batchSize, processor)
    if err != nil {
        return nil, err
    }

    return &BigQueryResponse{Replies: results}, nil
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
func getBearerToken(userEmail string, roleID string, userRoles []string) (string, error) {
    mutex.Lock()
    defer mutex.Unlock()

    // Generate cache key including user's Google roles
    rolesStr := strings.Join(userRoles, ",")
    key := userEmail
    if roleID != "" {
        key = fmt.Sprintf("%s:%s:%s", roleID, userEmail, rolesStr)
    }
    log.Printf("[DEBUG] Getting bearer token for cache key: %s", key)

    // Check cache
    if token, ok := bearerTokenCache.Load(key); ok {
        log.Printf("[DEBUG] Found cached bearer token for key: %s", key)
        return token.(string), nil
    }
    log.Printf("[DEBUG] No cached bearer token found, requesting new token")

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
        scope := fmt.Sprintf("role:%s", roleID)
        tokenData["scope"] = scope
        log.Printf("[DEBUG] Adding scope to token request: %s", scope)
    } else {
        log.Printf("[WARN] No role ID provided for token request")
    }

    tokenJSON, err := json.Marshal(tokenData)
    if err != nil {
        return "", err
    }

    // Make request
    log.Printf("[DEBUG] Requesting bearer token from %s", creds.TokenURI)
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
        log.Printf("[ERROR] Failed to get bearer token. Status: %d, Response: %s, Request data: %s", 
            resp.StatusCode, string(body), string(tokenJSON))
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
    log.Printf("[DEBUG] Successfully got bearer token with scope '%s', caching with key: %s", 
        tokenData["scope"], key)
    bearerTokenCache.Store(key, accessToken)

    return accessToken, nil
}

// secretManager provides access to Google Cloud Secret Manager
type secretManager struct {
    client    *secretmanager.Client
    projectID string
    prefix    string
}

// newSecretManager creates a new Secret Manager client
func newSecretManager() (*secretManager, error) {
    ctx := context.Background()
    client, err := secretmanager.NewClient(ctx)
    if err != nil {
        return nil, fmt.Errorf("failed to create Secret Manager client: %v", err)
    }

    projectID := os.Getenv("PROJECT_ID")
    if projectID == "" {
        return nil, fmt.Errorf("PROJECT_ID environment variable not set")
    }

    prefix := os.Getenv("PREFIX")
    if prefix == "" {
        return nil, fmt.Errorf("PREFIX environment variable not set")
    }

    return &secretManager{
        client:    client,
        projectID: projectID,
        prefix:    prefix,
    }, nil
}

// getSecretData gets a secret's data from Secret Manager
func (sm *secretManager) getSecretData(ctx context.Context, secretName string) ([]byte, error) {
    name := fmt.Sprintf("projects/%s/secrets/%s_%s/versions/latest",
        sm.projectID, sm.prefix, secretName)
    
    result, err := sm.client.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
        Name: name,
    })
    if err != nil {
        return nil, fmt.Errorf("failed to access secret version: %v", err)
    }

    return result.Payload.Data, nil
}

// Close closes the Secret Manager client
func (sm *secretManager) Close() error {
    return sm.client.Close()
}

// getCredentials loads credentials from Secret Manager
func getCredentials() (*SkyflowCredentials, error) {
    if credentials != nil {
        return credentials, nil
    }

    sm, err := newSecretManager()
    if err != nil {
        return nil, err
    }
    defer sm.Close()

    data, err := sm.getSecretData(context.Background(), "credentials")
    if err != nil {
        return nil, err
    }

    var creds SkyflowCredentials
    if err := json.Unmarshal(data, &creds); err != nil {
        return nil, fmt.Errorf("failed to unmarshal credentials: %v", err)
    }

    credentials = &creds
    return credentials, nil
}

// getSecret gets a secret from Secret Manager
func getSecret(secretName string) ([]byte, error) {
    sm, err := newSecretManager()
    if err != nil {
        return nil, err
    }
    defer sm.Close()

    return sm.getSecretData(context.Background(), secretName)
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

// bigQueryClient provides access to Google BigQuery
type bigQueryClient struct {
    client    *bigquery.Client
    projectID string
}

// newBigQueryClient creates a new BigQuery client
func newBigQueryClient() (*bigQueryClient, error) {
    projectID := os.Getenv("PROJECT_ID")
    if projectID == "" {
        return nil, fmt.Errorf("PROJECT_ID environment variable not set")
    }

    client, err := bigquery.NewClient(context.Background(), projectID)
    if err != nil {
        return nil, fmt.Errorf("failed to create BigQuery client: %v", err)
    }

    return &bigQueryClient{
        client:    client,
        projectID: projectID,
    }, nil
}

// Close closes the BigQuery client
func (bq *bigQueryClient) Close() error {
    return bq.client.Close()
}

// Query executes a query and returns the results
func (bq *bigQueryClient) Query(ctx context.Context, query string) ([][]interface{}, error) {
    q := bq.client.Query(query)
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

// Update executes an update query
func (bq *bigQueryClient) Update(ctx context.Context, query string) error {
    q := bq.client.Query(query)
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

// queryBigQuery executes a query and returns the results
func queryBigQuery(query string) ([][]interface{}, error) {
    bq, err := newBigQueryClient()
    if err != nil {
        return nil, err
    }
    defer bq.Close()

    return bq.Query(context.Background(), query)
}

// executeUpdate executes an update query
func executeUpdate(query string) error {
    bq, err := newBigQueryClient()
    if err != nil {
        return err
    }
    defer bq.Close()

    return bq.Update(context.Background(), query)
}

// batchProcessor is a generic function to process items in batches
func batchProcessor[T any, R any](items []T, batchSize int, processor func([]T) ([]R, error)) ([]R, error) {
    if batchSize <= 0 {
        batchSize = 25 // default batch size
    }

    results := make([]R, 0, len(items))
    for i := 0; i < len(items); i += batchSize {
        end := i + batchSize
        if end > len(items) {
            end = len(items)
        }

        batch := items[i:end]
        batchResults, err := processor(batch)
        if err != nil {
            return nil, fmt.Errorf("error processing batch: %v", err)
        }
        results = append(results, batchResults...)
    }

    return results, nil
}

// getBatchSize gets a batch size from environment variable with a default value
func getBatchSize(envVar string, defaultSize int) int {
    if batchStr := os.Getenv(envVar); batchStr != "" {
        if val, err := strconv.Atoi(batchStr); err == nil && val > 0 {
            return val
        }
    }
    return defaultSize
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

// skyflowClient represents a client for making Skyflow API requests
type skyflowClient struct {
    baseURL     string
    accountID   string
    httpClient  *http.Client
}

// newSkyflowClient creates a new Skyflow API client
func newSkyflowClient() *skyflowClient {
    return &skyflowClient{
        baseURL:    os.Getenv("SKYFLOW_VAULT_URL"),
        accountID:  os.Getenv("SKYFLOW_ACCOUNT_ID"),
        httpClient: &http.Client{},
    }
}

// makeRequest makes a request to the Skyflow API with proper headers and authentication
func (c *skyflowClient) makeRequest(method, endpoint string, body []byte, bearerToken string) (*http.Response, error) {
    req, err := http.NewRequest(method, c.baseURL+endpoint, bytes.NewBuffer(body))
    if err != nil {
        return nil, fmt.Errorf("error creating request: %v", err)
    }

    // Set standard headers
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("Accept", "application/json")
    req.Header.Set("Authorization", "Bearer "+bearerToken)
    req.Header.Set("X-SKYFLOW-ACCOUNT-ID", c.accountID)

    return c.httpClient.Do(req)
}

// completeTokenPromise completes a token promise and returns a BigQuery response
func completeTokenPromise(promise *tokenPromise, value string, token string, err error) (*BigQueryResponse, error) {
    promise.token = token
    promise.err = err
    close(promise.done)
    inFlightRequests.Delete(value)
    return &BigQueryResponse{Replies: []interface{}{token}}, err
}

// makeSkyflowAPIRequest makes a generic request to the Skyflow API
func makeSkyflowAPIRequest[Req any, Resp any](endpoint string, req Req, userEmail string, roleID string) (*Resp, error) {
    client := newSkyflowClient()

    // Get user roles from context
    ctx := context.Background()
    roles, err := getUserRoles(ctx, userEmail)
    if err != nil {
        return nil, fmt.Errorf("error getting user roles: %v", err)
    }

    // Get bearer token with user context and role ID
    bearerToken, err := getBearerToken(userEmail, roleID, roles)
    if err != nil {
        return nil, fmt.Errorf("error getting bearer token: %v", err)
    }

    jsonData, err := json.Marshal(req)
    if err != nil {
        return nil, fmt.Errorf("error marshaling request: %v", err)
    }

    resp, err := client.makeRequest("POST", endpoint, jsonData, bearerToken)
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

    var skyflowResp Resp
    if err := json.Unmarshal(body, &skyflowResp); err != nil {
        return nil, fmt.Errorf("error unmarshaling response: %v", err)
    }

    return &skyflowResp, nil
}
