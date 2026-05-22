package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"nexiscore/ebpf"
	"nexiscore/sandbox"
	"nexiscore/validator"
)

// InterceptRequest defines the structure for incoming intercept requests
type InterceptRequest struct {
	Script    string                 `json:"script"`
	Variables map[string]interface{} `json:"variables"`
	Manifest  string                 `json:"manifest"`
	Signature string                 `json:"signature"`
}

// ManifestStructure defines the schema of the manifest JSON
type ManifestStructure struct {
	ToolName  string `json:"tool_name"`
	Nonce     string `json:"nonce"`
	Timestamp int64  `json:"timestamp"`
}

// InterceptResponse defines the HTTP JSON response format
type InterceptResponse struct {
	Success   bool            `json:"success"`
	Message   string          `json:"message,omitempty"`
	Output    *sandbox.Result `json:"output,omitempty"`
	PIDLocked int             `json:"pid_locked,omitempty"`
}

// TelemetryMetrics defines analytics payload returned on /api/v1/metrics
type TelemetryMetrics struct {
	BlockedNetworkBreaches int64 `json:"blocked_network_breaches"`
	BlockedFileBypasses    int64 `json:"blocked_file_bypasses"`
	VerifiedSignatures     int64 `json:"verified_signatures"`
	ActiveSandboxes        int64 `json:"active_sandboxes"`
}

var (
	provValidator  *validator.ProvenanceValidator
	sandboxManager *sandbox.SandboxManager

	// Telemetry variables
	VerifiedSignaturesCount int64
	ActiveSandboxesCount    int64
)

// scrubInput cleans script contents and variables (recursively scrubbing strings and arrays)
func scrubInput(script string, variables map[string]interface{}) (string, map[string]interface{}, error) {
	if strings.Contains(script, "\x00") {
		return "", nil, errors.New("script contains dangerous null byte characters")
	}

	scrubbedVars := make(map[string]interface{})
	for k, v := range variables {
		cleanKey := sanitizeString(k)
		if cleanKey == "" {
			return "", nil, errors.New("variable key contains invalid control characters or is empty")
		}

		switch val := v.(type) {
		case string:
			if strings.Contains(val, "\x00") {
				return "", nil, fmt.Errorf("variable string value for key '%s' contains null bytes", k)
			}
			scrubbedVars[cleanKey] = sanitizeString(val)
		case []interface{}:
			var scrubbedArray []interface{}
			for i, item := range val {
				if strItem, ok := item.(string); ok {
					if strings.Contains(strItem, "\x00") {
						return "", nil, fmt.Errorf("array element at index %d in key '%s' contains null bytes", i, k)
					}
					scrubbedArray = append(scrubbedArray, sanitizeString(strItem))
				} else {
					scrubbedArray = append(scrubbedArray, item)
				}
			}
			scrubbedVars[cleanKey] = scrubbedArray
		default:
			scrubbedVars[cleanKey] = v
		}
	}

	return script, scrubbedVars, nil
}

// sanitizeString removes ASCII control characters
func sanitizeString(in string) string {
	var sb strings.Builder
	for _, r := range in {
		if r < 32 && r != '\t' && r != '\n' && r != '\r' {
			continue // ignore unsafe control chars
		}
		sb.WriteRune(r)
	}
	return sb.String()
}

func handleIntercept(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(InterceptResponse{Success: false, Message: "Method not allowed"})
		return
	}

	// Read raw request body
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(InterceptResponse{Success: false, Message: "Failed to read request body"})
		return
	}
	defer r.Body.Close()

	var req InterceptRequest
	err = json.Unmarshal(bodyBytes, &req)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(InterceptResponse{Success: false, Message: "Invalid JSON format"})
		return
	}

	// 1. Scrub script and payload arrays before processing
	scrubbedScript, scrubbedVars, err := scrubInput(req.Script, req.Variables)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(InterceptResponse{Success: false, Message: fmt.Sprintf("Scrubbing failed: %v", err)})
		return
	}

	log.Printf("[GATEWAY] Scrubbed variables count: %d", len(scrubbedVars))

	// 2. Parse inner JSON manifest parameters
	var manifest ManifestStructure
	err = json.Unmarshal([]byte(req.Manifest), &manifest)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(InterceptResponse{Success: false, Message: "Invalid inner manifest JSON structure"})
		return
	}

	// Assert bounds checks on manifest parameters
	if manifest.Nonce == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(InterceptResponse{Success: false, Message: "Manifest contains empty nonce field"})
		return
	}

	if time.Now().Unix()-manifest.Timestamp > 600 || manifest.Timestamp-time.Now().Unix() > 600 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(InterceptResponse{Success: false, Message: "Manifest timestamp has expired (> 10m drift)"})
		return
	}

	// 3. Cryptographic Proof Validation & Nonce check
	err = provValidator.Verify([]byte(req.Manifest), req.Signature, manifest.Nonce)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(InterceptResponse{Success: false, Message: fmt.Sprintf("Verification failed: %v", err)})
		return
	}

	atomic.AddInt64(&VerifiedSignaturesCount, 1)
	log.Printf("[GATEWAY] Provenance & Nonce verified successfully. Launching sandboxed worker...")

	// 4. Sandboxed Execution with eBPF lock trigger
	var targetPID int
	atomic.AddInt64(&ActiveSandboxesCount, 1)
	res, err := sandboxManager.Execute(scrubbedScript, func(pid int) error {
		targetPID = pid
		// Update native eBPF map programmatically via pure-Go controller
		return ebpf.RegisterSandboxPID(pid)
	})

	// Perform map cleanup after execution finishes
	if targetPID > 0 {
		_ = ebpf.RemoveSandboxPID(targetPID)
	}
	atomic.AddInt64(&ActiveSandboxesCount, -1)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(InterceptResponse{
			Success: false,
			Message: fmt.Sprintf("Sandbox execution engine failed: %v", err),
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(InterceptResponse{
		Success:   true,
		Output:    res,
		PIDLocked: targetPID,
	})
}

func handleMetrics(w http.ResponseWriter, r *http.Header) {
	// Dummy for route signature, will handle via helper in http routing
}

func main() {
	log.Println("=== Starting NexisCore Zero-Trust Gateway Server ===")

	// 1. Initialise the asymmetric cryptographic verifier using local PEM key
	var err error
	provValidator, err = validator.NewProvenanceValidator("public_key.pem", 5*time.Minute)
	if err != nil {
		log.Fatalf("Failed to initialize Provenance Validator: %v (Please run key generator generate_keys.go first)", err)
	}
	log.Println("[+] Provenance Validator initialized (public_key.pem loaded, 5m sliding window TTL).")

	// 2. Initialize Sandbox Manager using python-slim
	sandboxManager = sandbox.NewSandboxManager("python:3.10-slim")
	log.Println("[+] Sandbox Manager initialized targeting python:3.10-slim on gVisor runsc.")

	// 3. Launch native BPF ring buffer telemetry streaming listener as background daemon
	go ebpf.StreamKernelAlerts()

	// 4. Mount Routes
	http.HandleFunc("/api/v1/intercept", handleIntercept)
	http.HandleFunc("/api/v1/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed"})
			return
		}
		
		metrics := TelemetryMetrics{
			BlockedNetworkBreaches: atomic.LoadInt64(&ebpf.BlockedNetworkBreaches),
			BlockedFileBypasses:    atomic.LoadInt64(&ebpf.BlockedFileBypasses),
			VerifiedSignatures:     atomic.LoadInt64(&VerifiedSignaturesCount),
			ActiveSandboxes:        atomic.LoadInt64(&ActiveSandboxesCount),
		}
		
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(metrics)
	})

	// 5. Expose secure listener on 127.0.0.1:9090
	address := "127.0.0.1:9090"
	log.Printf("[+] Interception service listening on %s...", address)
	if err := http.ListenAndServe(address, nil); err != nil {
		log.Fatalf("Server aborted: %v", err)
	}
}
