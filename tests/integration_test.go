package tests

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"testing"
	"time"
)

// TokenManifest matches the structural specifications requested
type TokenManifest struct {
	ToolID         string   `json:"tool_id"`
	ToolName       string   `json:"tool_name"` // matches validator main.go requirement
	Version        string   `json:"version"`
	Runtime        string   `json:"runtime"`
	FileHashes     []string `json:"file_hashes"`
	AllowedDomains []string `json:"allowed_domains"`
	Nonce          string   `json:"nonce"`
	Timestamp      int64    `json:"timestamp"`
}

// ExecutionPayload matches the server intercept request model
type ExecutionPayload struct {
	Script    string                 `json:"script"`
	Variables map[string]interface{} `json:"variables"`
	Manifest  string                 `json:"manifest"`
	Signature string                 `json:"signature"`
}

func TestEndToEndInterceptPipeline(t *testing.T) {
	t.Log("=== NexisCore Integration Test Harness ===")

	// 1. Programmatically run tools/keygen.go to establish certs directory and keys
	certsDir := "./certs"
	_ = os.RemoveAll(certsDir) // Reset state

	t.Log("[+] Spawning keygen.go utility programmatically...")
	cmdKeygen := exec.Command("local_go/go/bin/go", "run", "tools/keygen.go")
	// Make sure we run in the right working directory to get keys at standard relative path
	cmdKeygen.Dir = "../"
	var outKeygen, errKeygen bytes.Buffer
	cmdKeygen.Stdout = &outKeygen
	cmdKeygen.Stderr = &errKeygen
	err := cmdKeygen.Run()
	if err != nil {
		t.Fatalf("Failed to run keygen tool: %v (stderr: %s)", err, errKeygen.String())
	}
	t.Log("[+] Keygen executed successfully.")

	// Verify key existence
	privKeyPath := "../certs/private.pem"
	pubKeyPath := "../certs/public.pem"
	if _, err := os.Stat(privKeyPath); os.IsNotExist(err) {
		t.Fatalf("Private key not found at %s", privKeyPath)
	}

	// We copy keys to current directory or we make sure our main program reads public_key.pem.
	// Since main.go reads "public_key.pem" from its local working directory, we can copy ../certs/public.pem to public_key.pem
	// in the parent directory so main.go loads it.
	pubKeyContent, err := os.ReadFile(pubKeyPath)
	if err != nil {
		t.Fatalf("Failed to read public key: %v", err)
	}
	err = os.WriteFile("../public_key.pem", pubKeyContent, 0644)
	if err != nil {
		t.Fatalf("Failed to write public_key.pem in parent dir: %v", err)
	}

	// 2. Launch the main server hub on port 9090 as a background goroutine loop
	t.Log("[+] Compiling and launching NexisCore Main Gateway Server on 127.0.0.1:9090...")
	serverCmd := exec.Command("local_go/go/bin/go", "run", "main.go")
	serverCmd.Dir = "../"
	
	// Create logs buffer
	var serverStderr bytes.Buffer
	serverCmd.Stderr = &serverStderr

	err = serverCmd.Start()
	if err != nil {
		t.Fatalf("Failed to start server process: %v", err)
	}

	// Ensure background server is terminated cleanly when test returns
	defer func() {
		t.Log("[+] Cleaning up background gateway server...")
		if serverCmd.Process != nil {
			_ = serverCmd.Process.Kill()
		}
	}()

	// Wait 2 seconds for server to start listening
	time.Sleep(2 * time.Second)

	// 3. Construct a valid mock JSON payload manifest matching the 'TokenManifest' structural schema
	nonce := fmt.Sprintf("nonce_test_%d", time.Now().UnixNano())
	manifest := TokenManifest{
		ToolID:         "python_interpreter",
		ToolName:       "python_interpreter",
		Version:        "1.0.0",
		Runtime:        "runsc",
		FileHashes:     []string{"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		AllowedDomains: []string{"localhost"},
		Nonce:          nonce,
		Timestamp:      time.Now().Unix(),
	}

	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("Failed to marshal manifest JSON: %v", err)
	}
	manifestStr := string(manifestBytes)
	t.Logf("[+] Constructed Manifest: %s", manifestStr)

	// 4. Invoke signing programmatically to extract a matching valid hex validation signature
	privKeyBytes, err := os.ReadFile(privKeyPath)
	if err != nil {
		t.Fatalf("Failed to read private.pem for signing: %v", err)
	}

	block, _ := pem.Decode(privKeyBytes)
	if block == nil {
		t.Fatalf("Failed to decode private key PEM block")
	}

	privKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse EC private key: %v", err)
	}

	hash := sha256.Sum256(manifestBytes)
	sigBytes, err := ecdsa.SignASN1(rand.Reader, privKey, hash[:])
	if err != nil {
		t.Fatalf("Failed to sign manifest: %v", err)
	}
	hexSignature := hex.EncodeToString(sigBytes)
	t.Logf("[+] Generated Hex Signature: %s", hexSignature)

	// 5. Assemble a complete 'ExecutionPayload' body containing benign Python script
	payload := ExecutionPayload{
		Script:    "print('Sanity Run - NexisCore Verification Successful!')",
		Variables: map[string]interface{}{"debug": true, "tags": []interface{}{"integration", "test"}},
		Manifest:  manifestStr,
		Signature: hexSignature,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Failed to marshal execution payload: %v", err)
	}

	// 6. Dispatch a live HTTP POST query to http://127.0.0.1:9090/api/v1/intercept
	t.Log("[+] Dispatching POST request to /api/v1/intercept...")
	resp, err := http.Post("http://127.0.0.1:9090/api/v1/intercept", "application/json", bytes.NewBuffer(payloadBytes))
	if err != nil {
		t.Fatalf("HTTP Post request failed: %v. Server logs: %s", err, serverStderr.String())
	}
	defer resp.Body.Close()

	// 7. Assert response status is 200 OK
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		t.Fatalf("Expected status 200 OK, got %d. Response: %s", resp.StatusCode, string(bodyBytes))
	}

	var responseData map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&responseData)
	if err != nil {
		t.Fatalf("Failed to parse response JSON: %v", err)
	}

	t.Logf("[+] Server Response: %+v", responseData)

	successVal, exists := responseData["success"]
	if !exists || successVal != true {
		t.Fatalf("Gateway response indicates failure: %+v", responseData)
	}

	t.Log("[SUCCESS] NexisCore End-to-End Integration Verification Passed Flawlessly!")
}
