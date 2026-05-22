package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os/exec"
	"strings"
	"time"

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
	Success    bool            `json:"success"`
	Message    string          `json:"message,omitempty"`
	Output     *sandbox.Result `json:"output,omitempty"`
	PIDLocked  int             `json:"pid_locked,omitempty"`
}

var (
	provValidator  *validator.ProvenanceValidator
	sandboxManager *sandbox.SandboxManager
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

// lockPIDInFirewall uses bpftool to insert the active sandbox process PID into the eBPF hash map
func lockPIDInFirewall(pid int) error {
	pid32 := uint32(pid)
	
	// Format PID bytes in Little Endian for bpftool hex arguments
	keyBytes := []string{
		fmt.Sprintf("0x%02x", byte(pid32)),
		fmt.Sprintf("0x%02x", byte(pid32>>8)),
		fmt.Sprintf("0x%02x", byte(pid32>>16)),
		fmt.Sprintf("0x%02x", byte(pid32>>24)),
	}

	// Execution args for bpftool map update
	// We use "sudo -n" to prevent blocking if sudo requires a password.
	args := []string{
		"-n",
		"bpftool",
		"map", "update",
		"pinned", "/sys/fs/bpf/nexiscore_maps/locked_sandboxes",
		"key", keyBytes[0], keyBytes[1], keyBytes[2], keyBytes[3],
		"value", "0x01", "0x00", "0x00", "0x00",
	}

	log.Printf("[FIREWALL] Intercepting! Calling: sudo %s", strings.Join(args, " "))
	
	cmd := exec.Command("sudo", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		log.Printf("[WARNING] eBPF firewall map update failed (proceeding without block): %v (stderr: %s)", err, strings.TrimSpace(stderr.String()))
		return nil
	}

	log.Printf("[FIREWALL] Locked container PID %d in kernel-level system call firewall map.", pid)
	return nil
}

// unlockPIDInFirewall deletes the PID key from the eBPF firewall map
func unlockPIDInFirewall(pid int) {
	pid32 := uint32(pid)
	keyBytes := []string{
		fmt.Sprintf("0x%02x", byte(pid32)),
		fmt.Sprintf("0x%02x", byte(pid32>>8)),
		fmt.Sprintf("0x%02x", byte(pid32>>16)),
		fmt.Sprintf("0x%02x", byte(pid32>>24)),
	}

	args := []string{
		"-n",
		"bpftool",
		"map", "delete",
		"pinned", "/sys/fs/bpf/nexiscore_maps/locked_sandboxes",
		"key", keyBytes[0], keyBytes[1], keyBytes[2], keyBytes[3],
	}

	cmd := exec.Command("sudo", args...)
	_ = cmd.Run() // silent deletion
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

	log.Printf("[GATEWAY] Provenance & Nonce verified successfully. Launching sandboxed worker...")

	// 4. Sandboxed Execution with eBPF lock trigger
	var targetPID int
	res, err := sandboxManager.Execute(scrubbedScript, func(pid int) error {
		targetPID = pid
		// Update eBPF map via bpftool prior to let the container execute tasks
		return lockPIDInFirewall(pid)
	})

	// Perform map cleanup after execution finishes
	if targetPID > 0 {
		defer unlockPIDInFirewall(targetPID)
	}

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

	// 3. Mount Routes
	http.HandleFunc("/api/v1/intercept", handleIntercept)

	// 4. Expose secure listener on 127.0.0.1:9090
	address := "127.0.0.1:9090"
	log.Printf("[+] Interception service listening on %s...", address)
	if err := http.ListenAndServe(address, nil); err != nil {
		log.Fatalf("Server aborted: %v", err)
	}
}
