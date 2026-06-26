package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"nexiscore/agent"
	"nexiscore/ebpf"
	"nexiscore/egress"
	"nexiscore/integrity"
	"nexiscore/sandbox"
	"nexiscore/telemetry"
	"nexiscore/validator"
)

// InterceptRequest defines the structure for incoming intercept requests
type InterceptRequest struct {
	Script    string                 `json:"script"`
	Variables map[string]interface{} `json:"variables"`
	Manifest  string                 `json:"manifest"`
	Signature string                 `json:"signature"`
	// AgentID is optionally supplied by the caller to associate the request with a registered agent.
	AgentID   string                 `json:"agent_id,omitempty"`
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
	// Module 1 — Agent metrics
	ActiveAgents           int64 `json:"active_agents"`
	// Module 3 — Anti-tamper metrics
	BlockedPtraceAttempts  int64 `json:"blocked_ptrace_attempts"`
	BlockedMprotectWX      int64 `json:"blocked_mprotect_wx"`
	BlockedShellSpawns     int64 `json:"blocked_shell_spawns"`
	IntegrityChecks        int64 `json:"integrity_checks"`
	// Module 4 — Egress metrics
	EgressAllowed          int64 `json:"egress_allowed"`
	EgressBlocked          int64 `json:"egress_blocked"`
	DLPRedactions          int64 `json:"dlp_redactions"`
	// OCSF Telemetry Engine metrics
	OCSFSubmitted          int64 `json:"ocsf_submitted"`
	OCSFProcessed          int64 `json:"ocsf_processed"`
	OCSFDropped            int64 `json:"ocsf_dropped"`
}

var (
	provValidator        *validator.ProvenanceValidator
	sandboxManager       *sandbox.SandboxManager
	playgroundPrivateKey *ecdsa.PrivateKey

	// Telemetry counters
	VerifiedSignaturesCount int64
	ActiveSandboxesCount    int64

	// Module 1 — Agent subsystem
	agentRegistry *agent.AgentRegistry
	agentPolicy   *agent.PolicyManager
	agentRouter   *agent.AgentRouter

	// Module 3 — Integrity subsystem
	killSwitch    *integrity.KillSwitch
	memMonitor    *integrity.MemoryIntegrityMonitor

	// Module 4 — Egress subsystem
	egressProxy   *egress.EgressProxy

	// Telemetry engine (Module 2)
	telemetryEngine *telemetry.TelemetryEngine

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

	// Resolve agent ID for telemetry (use supplied or fall back to a request-scoped default)
	effectiveAgentID := req.AgentID
	if effectiveAgentID == "" {
		effectiveAgentID = "gateway"
	}

	// 1. Scrub script and payload arrays using regex lexer
	scrubbedScript, scrubbedVars, err := scrubInput(req.Script, req.Variables)
	if err != nil {
		telemetry.SubmitGlobal(telemetry.NewValidationFailEvent(effectiveAgentID, r.RemoteAddr,
			"input_scrub_failed: "+err.Error(), bodyBytes))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(InterceptResponse{Success: false, Message: fmt.Sprintf("Scrubbing failed: %v", err)})
		return
	}

	log.Printf("[GATEWAY] Scrubbed variables count: %d", len(scrubbedVars))

	// 2. Parse inner JSON manifest parameters
	var manifest ManifestStructure
	err = json.Unmarshal([]byte(req.Manifest), &manifest)
	if err != nil {
		telemetry.SubmitGlobal(telemetry.NewValidationFailEvent(effectiveAgentID, r.RemoteAddr,
			"invalid_manifest_json", nil))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(InterceptResponse{Success: false, Message: "Invalid inner manifest JSON structure"})
		return
	}

	if manifest.Nonce == "" {
		telemetry.SubmitGlobal(telemetry.NewValidationFailEvent(effectiveAgentID, r.RemoteAddr,
			"empty_nonce", nil))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(InterceptResponse{Success: false, Message: "Manifest contains empty nonce field"})
		return
	}

	if time.Now().Unix()-manifest.Timestamp > 600 || manifest.Timestamp-time.Now().Unix() > 600 {
		telemetry.SubmitGlobal(telemetry.NewValidationFailEvent(effectiveAgentID, r.RemoteAddr,
			"timestamp_drift_exceeded", nil))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(InterceptResponse{Success: false, Message: "Manifest timestamp has expired (> 10m drift)"})
		return
	}

	// 3. Cryptographic Proof Validation & Nonce check
	err = provValidator.Verify([]byte(req.Manifest), req.Signature, manifest.Nonce)
	if err != nil {
		telemetry.SubmitGlobal(telemetry.NewValidationFailEvent(effectiveAgentID, r.RemoteAddr,
			"signature_verification_failed: "+err.Error(), []byte(req.Manifest)))
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(InterceptResponse{Success: false, Message: fmt.Sprintf("Verification failed: %v", err)})
		return
	}

	atomic.AddInt64(&VerifiedSignaturesCount, 1)
	// Emit OCSF attestation success event
	telemetry.SubmitGlobal(telemetry.NewAttestationEvent(effectiveAgentID, r.RemoteAddr, manifest.ToolName))
	log.Printf("[GATEWAY] Provenance & Nonce verified successfully. Launching sandboxed worker...")

	// 4. Emit tool call event
	telemetry.SubmitGlobal(telemetry.NewToolCallEvent(effectiveAgentID, r.RemoteAddr,
		manifest.ToolName, telemetry.StatusUnknown, "sandbox launch initiated"))

	// 5. Sandboxed Execution with eBPF lock trigger
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
		telemetry.SubmitGlobal(telemetry.NewSandboxLaunchEvent(effectiveAgentID, manifest.ToolName,
			targetPID, telemetry.StatusFailure, err.Error()))
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(InterceptResponse{
			Success: false,
			Message: fmt.Sprintf("Sandbox execution engine failed: %v", err),
		})
		return
	}

	telemetry.SubmitGlobal(telemetry.NewSandboxLaunchEvent(effectiveAgentID, manifest.ToolName,
		targetPID, telemetry.StatusSuccess, fmt.Sprintf("exit_code=%d", res.ExitCode)))

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(InterceptResponse{
		Success:   true,
		Output:    res,
		PIDLocked: targetPID,
	})
}

type PlaygroundRequest struct {
	Script string `json:"script"`
}

func handlePlaygroundRun(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Method not allowed"})
		return
	}

	if playgroundPrivateKey == nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Playground private key not loaded on server. Cannot sign manifest."})
		return
	}

	var req PlaygroundRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Invalid JSON payload"})
		return
	}

	// 1. Construct manifest map
	nonce := fmt.Sprintf("playground_nonce_%d", time.Now().UnixNano())
	manifestMap := map[string]interface{}{
		"tool_id":   "python_interpreter",
		"tool_name": "python_interpreter",
		"nonce":     nonce,
		"timestamp": time.Now().Unix(),
	}

	manifestBytes, err := json.Marshal(manifestMap)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Failed to marshal manifest"})
		return
	}

	// 2. Sign manifest bytes
	hash := sha256.Sum256(manifestBytes)
	sigBytes, err := ecdsa.SignASN1(rand.Reader, playgroundPrivateKey, hash[:])
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Failed to sign manifest"})
		return
	}
	hexSignature := hex.EncodeToString(sigBytes)

	// 3. Construct the InterceptRequest and execute internally
	scrubbedScript, _, err := scrubInput(req.Script, nil)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": fmt.Sprintf("Scrubbing failed: %v", err)})
		return
	}

	err = provValidator.Verify(manifestBytes, hexSignature, nonce)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": fmt.Sprintf("Verification failed: %v", err)})
		return
	}

	atomic.AddInt64(&VerifiedSignaturesCount, 1)

	var targetPID int
	atomic.AddInt64(&ActiveSandboxesCount, 1)
	res, err := sandboxManager.Execute(scrubbedScript, func(pid int) error {
		targetPID = pid
		return ebpf.RegisterSandboxPID(pid)
	})

	if targetPID > 0 {
		_ = ebpf.RemoveSandboxPID(targetPID)
	}
	atomic.AddInt64(&ActiveSandboxesCount, -1)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": fmt.Sprintf("Sandbox execution failed: %v", err)})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":    true,
		"output":     res,
		"pid_locked": targetPID,
	})
}

// handleListAgents returns a JSON list of all currently registered agent identities.
func handleListAgents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed"})
		return
	}
	type agentSummary struct {
		AgentID      string `json:"agent_id"`
		SPIFFEID     string `json:"spiffe_id"`
		RegisteredAt string `json:"registered_at"`
		ExpiresAt    string `json:"expires_at"`
	}
	var summaries []agentSummary
	if agentRegistry != nil {
		for _, id := range agentRegistry.ListActive() {
			summaries = append(summaries, agentSummary{
				AgentID:      id.AgentID,
				SPIFFEID:     id.SPIFFEID,
				RegisteredAt: id.RegisteredAt.UTC().Format(time.RFC3339),
				ExpiresAt:    id.ExpiresAt.UTC().Format(time.RFC3339),
			})
		}
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"active_agents": len(summaries),
		"agents":        summaries,
	})
}

func main() {
	log.Println("=== Starting NexisCore Zero-Trust Gateway Server ===")

	// ── Module 2: Telemetry Engine ────────────────────────────────────────────
	siemCfg := telemetry.DefaultSIEMConfig()
	siemForwarder, err := telemetry.NewSIEMForwarder(siemCfg)
	if err != nil {
		log.Printf("[WARNING] SIEM forwarder init failed: %v", err)
	}
	engCfg := telemetry.DefaultEngineConfig()
	telemetryEngine, err = telemetry.NewTelemetryEngine(engCfg, siemForwarder)
	if err != nil {
		log.Fatalf("Failed to initialise telemetry engine: %v", err)
	}
	telemetry.SetGlobalEngine(telemetryEngine)
	defer telemetryEngine.Shutdown()
	log.Println("[+] OCSF Telemetry Engine started (4 workers, 8192-event buffer).")

	// ── Module 3a: Kill-Switch ────────────────────────────────────────────────
	killSwitch = integrity.NewKillSwitch("nexiscore-gateway", telemetryEngine)
	integrity.RegisterGlobal(killSwitch)
	// Wire kill-switch into the eBPF anti-tamper ring buffer dispatcher
	ebpf.SetKillSwitchCallback(func(reason string, ctx map[string]string) {
		killSwitch.Trigger(reason, ctx)
	})
	log.Println("[+] Kill-switch protocol registered.")

	// ── Module 1: eBPF Controller ─────────────────────────────────────────────
	if err := ebpf.InitNativeController(); err != nil {
		log.Printf("[WARNING] eBPF System Initialization bypassed (requires root context): %v", err)
	} else {
		log.Println("[+] Native eBPF System Controller initialized programmatically.")
		defer ebpf.CloseNativeController()
		// Launch anti-tamper probes and alert streams
		if err := ebpf.InitAntiTamperProbes(); err != nil {
			log.Printf("[WARNING] Anti-tamper eBPF probes bypassed: %v", err)
		} else {
			log.Println("[+] Anti-tamper eBPF probes active (ptrace/mprotect/execve).")
			go ebpf.StreamAntiTamperAlerts()
		}
	}

	// ── Module 3b: Memory Integrity Monitor ───────────────────────────────────
	memMon, memErr := integrity.NewMemoryIntegrityMonitor("nexiscore-gateway", killSwitch, telemetryEngine)
	if memErr != nil {
		log.Printf("[WARNING] Memory integrity monitor unavailable: %v", memErr)
	} else {
		memMonitor = memMon
		memMonitor.StartPeriodicCheck(30 * time.Second)
		defer memMonitor.Stop()
		log.Println("[+] Memory integrity monitor started (30s interval, SHA-256 baseline).")
	}

	// ── Provenance Validator ──────────────────────────────────────────────────
	provValidator, err = validator.NewProvenanceValidator("public_key.pem", 5*time.Minute)
	if err != nil {
		log.Fatalf("Failed to initialize Provenance Validator: %v (Please run key generator generate_keys.go first)", err)
	}
	log.Println("[+] Provenance Validator initialized (public_key.pem loaded, 5m sliding window TTL).")

	// Load playground private key
	privKeyBytes, err := os.ReadFile("certs/private.pem")
	if err == nil {
		block, _ := pem.Decode(privKeyBytes)
		if block != nil {
			privKey, err := x509.ParseECPrivateKey(block.Bytes)
			if err == nil {
				playgroundPrivateKey = privKey
				log.Println("[+] Playground Private Key loaded. Live dashboard signature signing is enabled.")
			}
		}
	}

	// ── Module 1: Agent Registry, Policy & Router ─────────────────────────────
	agentRegistry = agent.NewAgentRegistry()
	agentPolicy, err = agent.NewPolicyManager("policy.yaml")
	if err != nil {
		log.Printf("[WARNING] Agent policy manager failed: %v", err)
	} else {
		defer agentPolicy.Shutdown()
	}
	agentRouter = agent.NewAgentRouter(agentRegistry, agentPolicy)
	log.Printf("[+] Agent Registry initialized. Router active with %d policy routes.",
		len(agentPolicy.Routes()))

	// ── Module 4: Egress Allowlist, DLP & Proxy ───────────────────────────────
	allowlistRouter, allowlistErr := egress.NewAllowlistRouter("egress_policy.yaml")
	if allowlistErr != nil {
		log.Printf("[WARNING] Egress allowlist init failed: %v", allowlistErr)
	} else {
		defer allowlistRouter.Shutdown()
		dlpPipeline, dlpErr := egress.NewDLPPipeline()
		if dlpErr != nil {
			log.Printf("[WARNING] DLP pipeline init failed: %v", dlpErr)
		} else {
			egressProxy = egress.NewEgressProxy(allowlistRouter, dlpPipeline, playgroundPrivateKey, "nexiscore-gateway")
			log.Printf("[+] Egress proxy armed: %d allowlisted domains, %d DLP patterns.",
				len(allowlistRouter.AllowedDomains()), len(dlpPipeline.PatternNames()))
		}
	}

	// ── Sandbox Manager ───────────────────────────────────────────────────────
	sandboxManager = sandbox.NewSandboxManager("python:3.10-slim")
	log.Println("[+] Sandbox Manager initialized targeting python:3.10-slim on gVisor runsc.")

	// ── Launch background telemetry streams ───────────────────────────────────
	go ebpf.StreamKernelAlerts()

	// ── Mount Routes ──────────────────────────────────────────────────────────
	http.HandleFunc("/api/v1/intercept", handleIntercept)
	http.HandleFunc("/api/v1/playground/run", handlePlaygroundRun)
	http.HandleFunc("/api/v1/agents", handleListAgents)

	// Deprecated /api/v1/metrics in favor of /api/v1/telemetry
	telemetryHandler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed"})
			return
		}

		var ocsfSubmitted, ocsfProcessed, ocsfDropped int64
		if telemetryEngine != nil {
			ocsfSubmitted, ocsfProcessed, ocsfDropped = telemetryEngine.Metrics()
		}
		var memChecks, memTampered int64
		if memMonitor != nil {
			memChecks, memTampered = memMonitor.Metrics()
			_ = memTampered // included in kill-switch fires
		}
		var egressAllowed, egressBlocked, dlpRedactions int64
		if egressProxy != nil {
			egressAllowed, egressBlocked, dlpRedactions = egressProxy.Metrics()
		}

		m := TelemetryMetrics{
			BlockedNetworkBreaches: atomic.LoadInt64(&ebpf.BlockedNetworkBreaches),
			BlockedFileBypasses:    atomic.LoadInt64(&ebpf.BlockedFileBypasses),
			VerifiedSignatures:     atomic.LoadInt64(&VerifiedSignaturesCount),
			ActiveSandboxes:        atomic.LoadInt64(&ActiveSandboxesCount),
			ActiveAgents:           int64(agentRegistry.Count()),
			BlockedPtraceAttempts:  atomic.LoadInt64(&ebpf.BlockedPtraceAttempts),
			BlockedMprotectWX:      atomic.LoadInt64(&ebpf.BlockedMprotectWX),
			BlockedShellSpawns:     atomic.LoadInt64(&ebpf.BlockedShellSpawns),
			IntegrityChecks:        memChecks,
			EgressAllowed:          egressAllowed,
			EgressBlocked:          egressBlocked,
			DLPRedactions:          dlpRedactions,
			OCSFSubmitted:          ocsfSubmitted,
			OCSFProcessed:          ocsfProcessed,
			OCSFDropped:            ocsfDropped,
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(m)
	}

	http.HandleFunc("/api/v1/metrics", telemetryHandler)
	http.HandleFunc("/api/v1/telemetry", telemetryHandler)

	// Serve HTML dashboard at /
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(dashboardHTML))
	})

	// 6. Expose secure listener on 127.0.0.1:9090
	address := "127.0.0.1:9090"
	log.Printf("[+] Interception service listening on %s...", address)
	if err := http.ListenAndServe(address, nil); err != nil {
		log.Fatalf("Server aborted: %v", err)
	}
}
