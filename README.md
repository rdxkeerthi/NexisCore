<div align="center">

<img src="https://img.shields.io/badge/Go-1.24-00ADD8?style=for-the-badge&logo=go&logoColor=white"/>
<img src="https://img.shields.io/badge/eBPF-Kernel%20Security-F0A500?style=for-the-badge&logo=linux&logoColor=white"/>
<img src="https://img.shields.io/badge/Zero%20Trust-Architecture-DC143C?style=for-the-badge"/>
<img src="https://img.shields.io/badge/OCSF-Telemetry-6A0DAD?style=for-the-badge"/>
<img src="https://img.shields.io/badge/mTLS-Ed25519-228B22?style=for-the-badge"/>
<img src="https://img.shields.io/badge/License-MIT-blue?style=for-the-badge"/>

# 🔐 NexisCore

### Zero-Trust Sandbox & Cryptographic Attestation Engine  
### for AI/MCP Agentic Workflows

*Enterprise-grade runtime security for cloud LLM orchestration — protecting against prompt injection, lateral movement, data exfiltration, and binary tampering.*

[🚀 Quick Start](#-quick-start) · [📐 Architecture](#-architecture) · [🔬 How It Works](#-how-it-works) · [📊 Output & Results](#-output--results) · [🗂️ File Structure](#️-file-structure)

</div>

---

## 📋 Problem Statement

Modern AI systems built on **Model Context Protocol (MCP)** and multi-agent LLM orchestration face a critical security gap that traditional enterprise tools cannot address:

| Threat | Traditional Security | NexisCore |
|--------|---------------------|-----------|
| **Prompt Injection** executing arbitrary code | ❌ No runtime isolation | ✅ gVisor + eBPF sandboxing |
| **Agent lateral movement** stealing context | ❌ No inter-agent auth | ✅ SPIFFE mTLS + ACL policy |
| **Data exfiltration** via LLM API calls | ❌ No outbound inspection | ✅ DLP pipeline + allowlist |
| **Debugger attachment** to attestation engine | ❌ No kernel monitoring | ✅ eBPF ptrace/mprotect/execve probes |
| **SOC blind spots** in AI workloads | ❌ No structured telemetry | ✅ OCSF + Splunk HEC pipeline |
| **Binary tampering** / memory injection | ❌ No integrity monitoring | ✅ SHA-256 periodic re-hash |

**The core problem:** When an AI agent receives a malicious prompt, it can:
1. Execute shell code in the host environment
2. Steal credentials from memory and exfiltrate via LLM API calls
3. Pivot to other agents in the same cluster and corrupt their context
4. Modify the security engine itself to bypass future checks

No existing product addresses all five attack vectors simultaneously within the Go runtime.

---

## 💡 Our Solution

**NexisCore** is a production-grade **Zero-Trust Security Gateway** that wraps every MCP tool invocation in a multi-layer security envelope:

```
[MCP Agent Request]
        │
        ▼
┌─────────────────────────────────┐
│   Cryptographic Attestation     │  ECDSA P-256 signature + nonce replay prevention
│   (Provenance Validator)        │
└───────────────┬─────────────────┘
                │
                ▼
┌─────────────────────────────────┐
│   Input Scrubbing + DLP         │  Regex lexer + 10-pattern DLP pipeline
│   (Egress Proxy Module)         │
└───────────────┬─────────────────┘
                │
                ▼
┌─────────────────────────────────┐
│   gVisor / Docker Sandbox       │  Kernel-isolated Python execution
│   (Sandbox Manager)             │
└───────────────┬─────────────────┘
                │
        ┌───────┴────────┐
        ▼                ▼
  eBPF Firewall    eBPF Anti-Tamper
  (connect/openat) (ptrace/mprotect/execve)
        │                │
        └───────┬─────────┘
                ▼
┌─────────────────────────────────┐
│   OCSF Telemetry Engine         │  Async 4-worker pool → Splunk HEC
│   + SIEM Forwarder              │
└─────────────────────────────────┘
```

---

## 🏢 Enterprise Benefits

| Benefit | Impact |
|---------|--------|
| **Zero lateral movement** | Agents cannot steal each other's context or credentials |
| **DLP before every LLM call** | AWS keys, SSH keys, credit cards redacted before leaving the network |
| **SOC visibility** | Every security event is OCSF-structured and forwarded to Splunk in real time |
| **Regulatory compliance** | Audit trail for every AI tool invocation with cryptographic proof |
| **Anti-forensics defense** | Binary tampering and debugger attachment detected and killed at kernel level |
| **Automatic key rotation** | Agent Ed25519 certs expire in 24h and auto-renew on registration |
| **Zero-config security** | Default-deny policy; allowlists written to disk on first run |

---

## 📐 Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         NexisCore Runtime                                │
│                                                                          │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐                │
│  │   Module 1   │   │   Module 2   │   │   Module 3   │                │
│  │  Multi-Agent │   │    OCSF      │   │   Memory     │                │
│  │  mTLS Router │   │  Telemetry   │   │  Integrity   │                │
│  │              │   │  + SIEM HEC  │   │  + Kill-Sw.  │                │
│  │ ┌──────────┐ │   │ ┌──────────┐ │   │ ┌──────────┐ │                │
│  │ │AgentReg. │ │   │ │OCSFEvent │ │   │ │MemCheck  │ │                │
│  │ │SPIFFE ID │ │   │ │ Engine   │ │   │ │/proc/self│ │                │
│  │ │Ed25519   │ │   │ │4 Workers │ │   │ │ SHA-256  │ │                │
│  │ │X.509cert │ │   │ │8k buffer │ │   │ │30s timer │ │                │
│  │ └──────────┘ │   │ └──────────┘ │   │ └──────────┘ │                │
│  │ ┌──────────┐ │   │ ┌──────────┐ │   │ ┌──────────┐ │                │
│  │ │PolicyMgr │ │   │ │Splunk HEC│ │   │ │KillSwitch│ │                │
│  │ │YAML ACL  │ │   │ │Batch POST│ │   │ │sync.Once │ │                │
│  │ │10s reload│ │   │ │TLS retry │ │   │ │Exit(137) │ │                │
│  │ └──────────┘ │   │ └──────────┘ │   │ └──────────┘ │                │
│  │ ┌──────────┐ │   └──────────────┘   │ ┌──────────┐ │                │
│  │ │mTLS Rtr. │ │                       │ │eBPF Anti │ │                │
│  │ │net.Pipe()│ │   ┌──────────────┐   │ │ Tamper   │ │                │
│  │ │TLS 1.3   │ │   │   Module 4   │   │ │ptrace/   │ │                │
│  │ └──────────┘ │   │  Egress DLP  │   │ │mprotect/ │ │                │
│  └──────────────┘   │  + Proxy     │   │ │execve    │ │                │
│                      │              │   │ └──────────┘ │                │
│  ┌──────────────────┐│ ┌──────────┐ │   └──────────────┘                │
│  │  HTTP Gateway    ││ │Allowlist │ │                                    │
│  │  :9090           ││ │6 domains │ │   ┌──────────────┐                │
│  │                  ││ │+CIDRs    │ │   │ eBPF Firewall│                │
│  │ /api/v1/intercept││ └──────────┘ │   │ connect/     │                │
│  │ /api/v1/agents   ││ ┌──────────┐ │   │ openat       │                │
│  │ /api/v1/telemetry││ │DLP       │ │   │ DNS filter   │                │
│  │ /               ││ │10 regex  │ │   │ Ring buffer  │                │
│  └──────────────────┘│ │Luhn CC   │ │   └──────────────┘                │
│                      │ └──────────┘ │                                    │
│                      │ ┌──────────┐ │   ┌──────────────┐                │
│                      │ │Egress Prx│ │   │   Sandbox    │                │
│                      │ │ECDSA-sign│ │   │   Manager    │                │
│                      │ │X-Payload │ │   │ Docker/gVisor│                │
│                      │ │-Sig hdr  │ │   │ 5s timeout   │                │
│                      │ └──────────┘ │   │ /tmp scratch │                │
│                      └──────────────┘   └──────────────┘                │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 🔬 How It Works

### 1️⃣ Module 1 — Multi-Agent Micro-Segmentation & mTLS

When an agent is spawned, NexisCore:
1. Generates a unique **Ed25519 key pair** and **SPIFFE URI** (`spiffe://nexiscore.local/agent/<uuid>`)
2. Issues a **self-signed X.509 certificate** (24h validity) embedding the SPIFFE URI as a SAN
3. Registers the identity in the **AgentRegistry** (thread-safe, in-memory)

When Agent-A wants to communicate with Agent-B:
1. **ACL check** against `policy.yaml` — if the route `spiffe://.../<A> → spiffe://.../<B>` is not explicitly allowed, the request is **denied** with an OCSF event
2. A **`net.Pipe()` connection** is created (zero network overhead, pure in-process)
3. Both sides perform a **TLS 1.3 handshake** with mutual certificate verification
4. A custom `VerifyPeerCertificate` hook enforces SPIFFE trust domain compliance
5. Payload flows through the encrypted pipe; the destination handler processes and responds

```
Agent-A                 AgentRouter                Agent-B
   │                        │                         │
   │─── RouteContext() ────►│                         │
   │                        │── ACL check ──────────►│
   │                        │   (policy.yaml)         │
   │                        │◄── PERMIT ─────────────│
   │                        │                         │
   │◄── TLS ClientHello ────┤──── TLS ServerHello ───►│
   │─── Certificate ───────►│◄─── Certificate ────────│
   │◄── Finished ───────────┤──── Finished ──────────►│
   │                        │                         │
   │─── [encrypted payload]─┤──────────────────────►  │
   │◄── [encrypted response]┤◄──────────────────────  │
```

### 2️⃣ Module 2 — OCSF Telemetry & Splunk/SIEM Pipeline

Every security decision generates a structured **OCSF JSON event**:

```json
{
  "class_uid": 2001,
  "class_name": "Security Finding",
  "activity_id": 7,
  "activity_name": "Deny",
  "time": 1750000000000,
  "severity_id": 4,
  "severity": "High",
  "status_id": 2,
  "status": "Failure",
  "status_detail": "Signature verification failed: invalid signature",
  "agent_id": "gateway",
  "actor": {"user": "127.0.0.1:54321", "process": "nexiscore"},
  "resource": {"name": "manifest", "type": "cryptographic_proof"},
  "action": "validation_fail",
  "signature_verification_status": "failed",
  "finding_type": "Signature Validation Failure",
  "finding_uid": "NEXIS-SIGFAIL-1750000000000",
  "metadata": {"version": "1.1.0", "product": "NexisCore", "vendor": "NexisCore Security"}
}
```

Events are dispatched via:
- **Local JSONL file** (`nexiscore_ocsf.jsonl`) — always written, zero dependencies
- **Splunk HEC** (when `NEXISCORE_SIEM_URL` is set) — batched POST over TLS with exponential backoff

### 3️⃣ Module 3 — Runtime Memory Protection & eBPF Anti-Tampering

**Memory Integrity Monitor:**
1. At startup, reads `/proc/self/maps` to identify executable segments
2. Computes **SHA-256** of `/proc/self/exe` as the baseline
3. Every **30 seconds**, re-hashes the binary
4. On mismatch → emits OCSF Critical event → triggers Kill-Switch → `os.Exit(137)`

**eBPF Anti-Tamper Probes** (attached to kernel tracepoints):

| Probe | Syscall | Detection | Action |
|-------|---------|-----------|--------|
| `sys_enter_ptrace` | `ptrace()` | `PTRACE_ATTACH` from sandboxed PID | SIGKILL + event |
| `sys_enter_mprotect` | `mprotect()` | `PROT_WRITE\|PROT_EXEC` (W^X) | SIGKILL + event |
| `sys_enter_execve` | `execve()` | `/bin/sh` or `/bin/bash` spawn | SIGKILL + event |

**Kill-Switch Protocol:**
```
Tamper Detected
      │
      ▼
sync.Once.Do() ← guaranteed single activation
      │
      ├── Print structured banner to stderr
      ├── Emit OCSF Critical Security Finding
      ├── telemetryEngine.Shutdown() ← flush events to disk
      └── os.Exit(137) ← SIGKILL convention exit code
```

### 4️⃣ Module 4 — Secure Cloud Egress Gateway & DLP

Every outbound HTTP request to an LLM API passes through 5 stages:

```
Stage 1: AllowlistRouter.IsAllowed(host)
         ├── Exact domain match
         ├── Suffix domain match (openai.com → api.openai.com ✓)
         ├── CIDR containment check
         └── DNS resolution fallback
         → 403 + OCSF EgressBlock event if not allowed

Stage 2: io.ReadAll(body, limit=10MiB)

Stage 3: DLPPipeline.Scrub(body)
         ├── aws_access_key_id     (AKIA...)
         ├── aws_secret_access_key
         ├── ssh_private_key_header
         ├── pem_private_key
         ├── generic_api_key
         ├── bearer_token
         ├── us_ssn
         ├── credit_card (Luhn-validated)
         ├── nexiscore_internal_uuid
         └── private_key_pem_content
         → [REDACTED:<type>] replacement + OCSF DLPFinding event

Stage 4: ECDSA-SHA256 sign scrubbed body
         → X-NexisCore-Payload-Sig: <hex-signature>
         → X-NexisCore-DLP-Version: 1.0
         → X-NexisCore-Agent-ID: <agent-id>

Stage 5: http.DefaultTransport.RoundTrip(sanitised request)
         → OCSF ToolCall event (success/failure)
```

---

## 🛠️ Technologies Used

| Technology | Version | Purpose |
|-----------|---------|---------|
| **Go** | 1.24 | Core runtime, HTTP gateway, concurrency |
| **cilium/ebpf** | v0.21.0 | BPF map management, tracepoint attachment |
| **LLVM/Clang** | 14+ | eBPF C compilation to BPF bytecode |
| **Linux eBPF** | Kernel 5.8+ | Syscall tracepoints, ring buffer, socket filter |
| **gVisor (runsc)** | Latest | Kernel isolation for sandboxed containers |
| **Docker** | 24+ | Container lifecycle management |
| **Ed25519** | stdlib | Agent identity key pairs |
| **ECDSA P-256** | stdlib | Provenance signing + egress attestation |
| **TLS 1.3** | stdlib | Inter-agent mTLS channel encryption |
| **OCSF** | 1.1.0 | Security event schema standard |
| **Splunk HEC** | - | SIEM event forwarding protocol |
| **gopkg.in/yaml.v3** | v3.0.1 | ACL/egress policy YAML parsing |
| **github.com/google/uuid** | v1.6.0 | Agent SPIFFE ID generation |
| **x509/SPIFFE** | stdlib | Certificate SANs for mutual TLS |

---

## 📊 Output & Results

### System Startup Log
```
2026/06/26 10:28:29 === Starting NexisCore Zero-Trust Gateway Server ===
2026/06/26 10:28:29 [SIEM] No SIEM endpoint configured. Running in local-log-only mode.
2026/06/26 10:28:29 [TELEMETRY] Engine started (4 workers, buffer=8192)
2026/06/26 10:28:29 [+] OCSF Telemetry Engine started (4 workers, 8192-event buffer).
2026/06/26 10:28:29 [+] Kill-switch protocol registered.
2026/06/26 10:28:29 [WARNING] eBPF System Initialization bypassed (requires root context)
2026/06/26 10:28:29 [MEMCHECK] Baseline SHA-256: 9807828fbb4a294a03d6125aa4fbb1d3...
2026/06/26 10:28:29 [MEMCHECK] Monitoring 3 executable text segments in /proc/self/maps
2026/06/26 10:28:29 [+] Memory integrity monitor started (30s interval, SHA-256 baseline).
2026/06/26 10:28:29 [+] Provenance Validator initialized (public_key.pem loaded, 5m TTL).
2026/06/26 10:28:29 [+] Playground Private Key loaded. Live dashboard signature signing enabled.
2026/06/26 10:28:29 [POLICY] Loaded 2 routes from "policy.yaml"
2026/06/26 10:28:29 [+] Agent Registry initialized. Router active with 2 policy routes.
2026/06/26 10:28:29 [EGRESS] AllowlistRouter started (6 domains, 2 CIDRs)
2026/06/26 10:28:29 [+] Egress proxy armed: 6 allowlisted domains, 10 DLP patterns.
2026/06/26 10:28:29 [+] Sandbox Manager initialized targeting python:3.10-slim on gVisor runsc.
2026/06/26 10:28:29 [+] Interception service listening on 127.0.0.1:9090...
```

### Telemetry API Response (`/api/v1/telemetry`)
```json
{
    "blocked_network_breaches": 0,
    "blocked_file_bypasses": 0,
    "verified_signatures": 3,
    "active_sandboxes": 0,
    "active_agents": 2,
    "blocked_ptrace_attempts": 0,
    "blocked_mprotect_wx": 0,
    "blocked_shell_spawns": 0,
    "integrity_checks": 5,
    "egress_allowed": 10,
    "egress_blocked": 1,
    "dlp_redactions": 2,
    "ocsf_submitted": 47,
    "ocsf_processed": 47,
    "ocsf_dropped": 0
}
```

### OCSF Event Sample (DLP Finding)
```json
{
  "class_uid": 2001,
  "class_name": "Security Finding",
  "action": "dlp_redact",
  "severity": "High",
  "status": "Success",
  "status_detail": "DLP pipeline redacted 1 sensitive finding(s) before egress",
  "finding_type": "Data Loss Prevention",
  "finding_uid": "NEXIS-DLP-1750000000000",
  "raw_data": {
    "target_domain": "api.openai.com",
    "finding_count": 1,
    "patterns_hit": ["aws_access_key_id"]
  }
}
```

### Kill-Switch Trigger (stderr output)
```
╔══════════════════════════════════════════════════════════════╗
║  NEXISCORE KILL-SWITCH TRIGGERED                             ║
╠══════════════════════════════════════════════════════════════╣
║  Reason  : ptrace_attach_detected                           ║
║  AgentID : nexiscore-gateway                                ║
║  pid     : 12345                                            ║
║  comm    : gdb                                              ║
╚══════════════════════════════════════════════════════════════╝
```

### Exploit Containment Test
```bash
make test-exploit
# [+] Sending exploit payload (socket connect to 1.1.1.1:80)...
# [+] Gateway Response: {"success":true,"output":{"exit_code":137}}
# [SUCCESS] Sandbox containment caught socket breach! Zero Data leaked!
```

---

## 🌍 Where This Problem Occurs

This solution addresses threats that arise in these enterprise scenarios:

| Scenario | Risk | NexisCore Protection |
|----------|------|---------------------|
| **Multi-tenant AI platforms** | Tenant A's agent attacks Tenant B | mTLS micro-segmentation + ACL |
| **AI code assistants** | Generated code exfiltrates secrets | DLP scrubbing before LLM call |
| **Autonomous AI agents** | Agent spawns shell to escape sandbox | eBPF execve probe + gVisor |
| **LLM-powered CI/CD pipelines** | Supply chain attack modifies binary | SHA-256 integrity monitor |
| **AI security tools** | Attacker debugs the security process | PTRACE_ATTACH eBPF block |
| **Financial AI platforms** | PII/credit card numbers in prompts | Luhn-validated CC DLP pattern |
| **Healthcare AI** | PHI (SSN) accidentally sent to OpenAI | SSN regex DLP pattern |
| **SOC AI assistants** | Unstructured logs, no SIEM integration | OCSF + Splunk HEC forwarder |

---

## ✅ What NexisCore Fulfils

| Requirement | Status |
|-------------|--------|
| Zero-Trust inter-agent communication | ✅ Ed25519 SPIFFE mTLS |
| Cryptographic proof of tool invocation | ✅ ECDSA P-256 attestation |
| Structured SOC telemetry | ✅ OCSF 1.1.0 class 6002 + 2001 |
| Kernel-level sandbox enforcement | ✅ eBPF tracepoints + gVisor |
| Data exfiltration prevention | ✅ 10-pattern DLP + egress allowlist |
| Runtime anti-tampering | ✅ ptrace/mprotect/execve eBPF + SHA-256 |
| SIEM integration | ✅ Splunk HEC with batching + retry |
| Zero-config security defaults | ✅ Default-deny ACL + allowlists on disk |
| High-throughput event processing | ✅ Non-blocking 4-worker 8192-buffer queue |
| Hot-reload configuration | ✅ Policy/allowlist reload every 10–15s |

---

## 🚀 Quick Start

### Prerequisites

```bash
# Required
sudo apt install -y clang llvm libelf-dev linux-headers-$(uname -r) docker.io
# Go 1.24+ (bundled in local_go/)
# Optional: gVisor for full kernel isolation
curl -fsSL https://gvisor.dev/archive.key | sudo gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg
```

### Run in 3 steps

```bash
# Step 1: Generate PKI keys
make generate-pki

# Step 2: Compile eBPF programs  
make build-ebpf
make build-antitamper-ebpf  # optional, requires recompile

# Step 3: Build and run
make run-system
# OR for full enterprise mode (all 4 modules):
make run-full
```

### Access the Dashboard
Open your browser at **http://127.0.0.1:9090**

### Configure SIEM (Optional)
```bash
export NEXISCORE_SIEM_URL="https://your-splunk:8088"
export NEXISCORE_SIEM_TOKEN="your-hec-token"
./nexiscore_bin
```

### eBPF (requires root)
```bash
sudo make load-ebpf   # pins maps to /sys/fs/bpf/
sudo ./nexiscore_bin  # full kernel enforcement
```

---

## 🌐 API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `GET /` | GET | Interactive security dashboard UI |
| `POST /api/v1/intercept` | POST | Submit MCP tool call for attestation + sandboxed execution |
| `POST /api/v1/playground/run` | POST | Test endpoint with auto-signed manifest |
| `GET /api/v1/agents` | GET | List all registered agent identities + SPIFFE IDs |
| `GET /api/v1/telemetry` | GET | Full 15-metric telemetry snapshot |
| `GET /api/v1/metrics` | GET | Alias for `/api/v1/telemetry` |

### Sample Intercept Request
```bash
NONCE="nonce_$(date +%s%N)"
MANIFEST="{\"tool_name\":\"python_interpreter\",\"nonce\":\"$NONCE\",\"timestamp\":$(date +%s)}"
SIGNATURE=$(./local_go/go/bin/go run tools/signer.go "$MANIFEST")

curl -X POST http://127.0.0.1:9090/api/v1/intercept \
  -H "Content-Type: application/json" \
  -d "{\"script\":\"print('Hello NexisCore')\",\"variables\":{},\"manifest\":\"$MANIFEST\",\"signature\":\"$SIGNATURE\"}"
```

---

## 🗂️ File Structure

```
NexisCore/
│
├── main.go                    # HTTP gateway + module wiring
├── dashboard.go               # Embedded HTML dashboard UI
├── generate_keys.go           # ECDSA P-256 key pair generator
├── go.mod / go.sum            # Go module dependencies
├── Makefile                   # Build automation (build/run/test/clean)
├── policy.yaml                # Inter-agent ACL routing policy
├── egress_policy.yaml         # Egress domain + CIDR allowlist
├── public_key.pem             # ECDSA public key (runtime copy)
├── nexiscore_ocsf.jsonl       # OCSF event log (auto-generated)
│
├── agent/                     # Module 1: Agent Identity & mTLS
│   ├── registry.go            # AgentRegistry, Ed25519, SPIFFE, X.509
│   ├── policy.go              # PolicyManager, YAML ACL, hot-reload
│   └── router.go              # AgentRouter, net.Pipe(), TLS 1.3 mTLS
│
├── telemetry/                 # Module 2: OCSF Telemetry & SIEM
│   ├── ocsf.go                # OCSFEvent struct + 9 constructors
│   ├── engine.go              # TelemetryEngine, 4-worker pool
│   └── siem.go                # SIEMForwarder, Splunk HEC, batching
│
├── integrity/                 # Module 3: Memory Integrity
│   ├── memcheck.go            # MemoryIntegrityMonitor, /proc/self/maps
│   └── killswitch.go          # KillSwitch, sync.Once, os.Exit(137)
│
├── egress/                    # Module 4: Egress Gateway & DLP
│   ├── allowlist.go           # AllowlistRouter, domain/CIDR matching
│   ├── dlp.go                 # DLPPipeline, 10 regex patterns, Luhn
│   └── proxy.go               # EgressProxy, http.RoundTripper, ECDSA sign
│
├── ebpf/                      # eBPF Controller (Go)
│   ├── controller.go          # Map management, tracepoints, ring buffer
│   └── kernel/
│       ├── firewall.bpf.c     # connect/openat/DNS filter probes
│       ├── antitamper.bpf.c   # ptrace/mprotect/execve probes
│       ├── bpf_helpers.h      # BPF helper function declarations
│       ├── monitor.o          # Compiled firewall bytecode (generated)
│       └── antitamper.o       # Compiled antitamper bytecode (generated)
│
├── sandbox/
│   └── sandbox.go             # SandboxManager, Docker/gVisor, 5s timeout
│
├── validator/
│   └── validator.go           # ProvenanceValidator, ECDSA verify, nonce
│
├── tools/
│   ├── signer.go              # CLI manifest signer (development tool)
│   └── keygen.go              # EC key pair generator
│
├── tests/
│   └── integration_test.go    # E2E integration test suite
│
├── certs/                     # Generated PKI keys (gitignored)
│   ├── private.pem
│   └── public.pem
│
└── local_go/                  # Bundled Go toolchain
    └── go/bin/go
```

---

## 📡 Data Flow

```
                          ┌─────────────────────┐
                          │   MCP Client / LLM  │
                          │   Orchestrator      │
                          └──────────┬──────────┘
                                     │ POST /api/v1/intercept
                                     │ {script, manifest, signature}
                                     ▼
                          ┌─────────────────────┐
                          │  main.go Gateway    │
                          │                     │
                          │ 1. JSON decode      │
                          │ 2. Regex scrub      │ ──────► OCSF event
                          │ 3. Manifest parse   │
                          │ 4. Timestamp check  │ ──────► OCSF event (fail)
                          │ 5. ECDSA verify     │ ──────► OCSF event
                          └──────────┬──────────┘
                                     │
                 ┌───────────────────┼───────────────────┐
                 │                   │                   │
                 ▼                   ▼                   ▼
      ┌──────────────────┐  ┌───────────────┐  ┌────────────────┐
      │  Sandbox Manager │  │ OCSF Engine   │  │ Egress Proxy   │
      │                  │  │               │  │                │
      │ docker run -d    │  │ Submit()      │  │ AllowlistCheck │
      │ --runtime=runsc  │  │ (non-blocking)│  │ DLP.Scrub()    │
      │ --network=none   │  │               │  │ ECDSA sign     │
      │ --memory=512m    │  │               │  │                │
      └────────┬─────────┘  └───────┬───────┘  └───────┬────────┘
               │                    │                   │
               ▼                    ▼                   ▼
      ┌──────────────────┐  ┌───────────────┐  ┌────────────────┐
      │   eBPF Kernel    │  │  SIEM/Splunk  │  │  LLM Provider  │
      │                  │  │  HEC Endpoint │  │  api.openai.com│
      │ connect → block  │  │               │  │  api.anthropic │
      │ openat → block   │  │ Batch POST    │  │                │
      │ ptrace → SIGKILL │  │ TLS + retry   │  │                │
      │ mprotect → kill  │  │               │  │                │
      │ execve → kill    │  │               │  │                │
      └──────────────────┘  └───────────────┘  └────────────────┘
               │
               ▼
      ┌──────────────────┐
      │ Anti-Tamper Ring │
      │ Buffer → Go      │
      │ → KillSwitch     │
      │ → os.Exit(137)   │
      └──────────────────┘
```

### Where Data Moves

| Data | From | To | Security Control |
|------|------|----|-----------------|
| MCP tool request | Client | Gateway | ECDSA signature verify |
| Script code | Gateway | Sandbox | Regex scrubbing first |
| Execution output | Sandbox container | Gateway | No network egress |
| OCSF events | All modules | Engine queue | Non-blocking channel |
| OCSF events | Engine | Local JSONL file | Always written |
| OCSF events | Engine | Splunk HEC | TLS + token auth |
| Egress payload | Agent | LLM provider | DLP scrub + ECDSA sign |
| Agent context | Agent-A | Agent-B | mTLS + ACL gated |
| Tamper signal | eBPF kernel | Go ring buffer | Kernel ring buffer |
| Kill signal | Kill-Switch | Process | `os.Exit(137)` |

---

## 🔧 Make Targets

```bash
make generate-pki           # Generate ECDSA P-256 key pair
make build-ebpf             # Compile firewall eBPF bytecode
make build-antitamper-ebpf  # Compile anti-tamper eBPF bytecode
make load-ebpf              # Pin eBPF to /sys/fs/bpf/ (requires root)
make run-system             # Standard build + run
make run-full               # All eBPF + full enterprise mode
make test                   # Run integration test suite
make test-exploit           # Simulate socket breach attack
make clean                  # Remove binaries, keys, logs
```

---

## 🤝 Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) and our [Code of Conduct](CODE_OF_CONDUCT.md) before submitting pull requests.

---

## 📄 License

This project is licensed under the **MIT License** — see [LICENSE](LICENSE) for details.

---

## 🔒 Security

If you discover a security vulnerability, please **do not open a public issue**. Instead, email `sambavam102@gmail.com` with the subject line `[SECURITY] NexisCore Vulnerability Report`.

See [SECURITY.md](SECURITY.md) for our full vulnerability disclosure policy.

---

<div align="center">

**Built with ❤️ for enterprise AI security**

*NexisCore — Because AI should be powerful AND safe.*

</div>
