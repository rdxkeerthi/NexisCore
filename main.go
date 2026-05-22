package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
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

// TelemetryMetrics defines analytics payload returned on /api/v1/telemetry
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

	// Precompiled optimized regex lexers to enforce strict alpha-numeric constraints
	variableKeyRegex   = regexp.MustCompile(`^[a-zA-Z0-9_\-]{1,64}$`)
	variableValueRegex = regexp.MustCompile(`^[\x20-\x7E\t\n\r]*$`)
)

// scrubInput cleans script contents and variables recursively using optimized regex lexers
func scrubInput(script string, variables map[string]interface{}) (string, map[string]interface{}, error) {
	if strings.Contains(script, "\x00") {
		return "", nil, errors.New("script contains dangerous null byte characters")
	}

	scrubbedVars := make(map[string]interface{})
	for k, v := range variables {
		// Enforce strict variable key checks using precompiled regex
		if !variableKeyRegex.MatchString(k) {
			return "", nil, fmt.Errorf("variable key '%s' violates strict security alphanumeric rules", k)
		}

		switch val := v.(type) {
		case string:
			if len(val) > 1024 {
				return "", nil, fmt.Errorf("variable string value for key '%s' exceeds maximum allowed length of 1024 bytes", k)
			}
			if strings.Contains(val, "\x00") {
				return "", nil, fmt.Errorf("variable string value for key '%s' contains null bytes", k)
			}
			if !variableValueRegex.MatchString(val) {
				return "", nil, fmt.Errorf("variable value for key '%s' contains disallowed control characters", k)
			}
			scrubbedVars[k] = val
		case []interface{}:
			var scrubbedArray []interface{}
			for i, item := range val {
				if strItem, ok := item.(string); ok {
					if len(strItem) > 1024 {
						return "", nil, fmt.Errorf("array element at index %d in key '%s' exceeds maximum allowed length of 1024 bytes", i, k)
					}
					if strings.Contains(strItem, "\x00") {
						return "", nil, fmt.Errorf("array element at index %d in key '%s' contains null bytes", i, k)
					}
					if !variableValueRegex.MatchString(strItem) {
						return "", nil, fmt.Errorf("array element at index %d in key '%s' violates strict character boundaries", i, k)
					}
					scrubbedArray = append(scrubbedArray, strItem)
				} else {
					scrubbedArray = append(scrubbedArray, item)
				}
			}
			scrubbedVars[k] = scrubbedArray
		default:
			scrubbedVars[k] = v
		}
	}

	return script, scrubbedVars, nil
}

func handleIntercept(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(InterceptResponse{Success: false, Message: "Method not allowed"})
		return
	}

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

	// 1. Scrub script and payload arrays using regex lexer
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

func main() {
	log.Println("=== Starting NexisCore Zero-Trust Gateway Server ===")

	// 1. Initialize programmatic native Go-eBPF mapping engine and link controllers
	if err := ebpf.InitNativeController(); err != nil {
		log.Printf("[WARNING] eBPF System Initialization bypassed (requires root context): %v", err)
	} else {
		log.Println("[+] Native eBPF System Controller initialized programmatically.")
		defer ebpf.CloseNativeController()
	}

	// 2. Initialise the asymmetric cryptographic verifier using local PEM key
	var err error
	provValidator, err = validator.NewProvenanceValidator("public_key.pem", 5*time.Minute)
	if err != nil {
		log.Fatalf("Failed to initialize Provenance Validator: %v (Please run key generator generate_keys.go first)", err)
	}
	log.Println("[+] Provenance Validator initialized (public_key.pem loaded, 5m sliding window TTL).")

	// 3. Initialize Sandbox Manager using python-slim
	sandboxManager = sandbox.NewSandboxManager("python:3.10-slim")
	log.Println("[+] Sandbox Manager initialized targeting python:3.10-slim on gVisor runsc.")

	// 4. Launch native BPF ring buffer telemetry streaming listener as background daemon
	go ebpf.StreamKernelAlerts()

	// 5. Mount Routes
	http.HandleFunc("/api/v1/intercept", handleIntercept)
	
	// Deprecated /api/v1/metrics in favor of /api/v1/telemetry
	telemetryHandler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed"})
			return
		}

		telemetry := TelemetryMetrics{
			BlockedNetworkBreaches: atomic.LoadInt64(&ebpf.BlockedNetworkBreaches),
			BlockedFileBypasses:    atomic.LoadInt64(&ebpf.BlockedFileBypasses),
			VerifiedSignatures:     atomic.LoadInt64(&VerifiedSignaturesCount),
			ActiveSandboxes:        atomic.LoadInt64(&ActiveSandboxesCount),
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(telemetry)
	}

	http.HandleFunc("/api/v1/metrics", telemetryHandler)
	http.HandleFunc("/api/v1/telemetry", telemetryHandler)

	// 6. Expose secure listener on 127.0.0.1:9090
	address := "127.0.0.1:9090"
	log.Printf("[+] Interception service listening on %s...", address)
	if err := http.ListenAndServe(address, nil); err != nil {
		log.Fatalf("Server aborted: %v", err)
	}
}
