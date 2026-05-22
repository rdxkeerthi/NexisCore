# 🛡️ NexisCore — Zero-Trust Agentic Runtime Security Gateway

NexisCore is an enterprise-grade, zero-trust runtime containment gateway designed to intercept, authorize, sandbox, and block outbound threat vectors during LLM agent tool calling operations. 

By leveraging **ECDSA Cryptographic Provenance**, **Dual-Isolate Sandboxing (gVisor/Docker)**, and **Kernel-Level tracepoints (eBPF)**, NexisCore guarantees that even if an agent falls victim to prompt-injection exploits, the untrusted tooling process cannot execute unauthorized system connections or trigger data exfiltration.

---

## 🏗️ Architectural Overview & Data Flow

NexisCore operates as a multi-tier interception system spanning User-space, Sandbox Containment, and Linux Kernel space:

```
[Agent Intercept Call]
        │
        ▼
 ┌──────────────┐      ┌───────────────┐
 │ API Intercept│ ───> │ Nonce Sliding │ (Detects & rejects replay attacks)
 │  Scrubber    │      │  TTL Cache    │
 └──────┬───────┘      └───────────────┘
        │ (Scrubbed inputs & validated ECDSA signature)
        ▼
 ┌──────────────┐      ┌───────────────┐
 │ Isolate Dir  │ ───> │ Write Script  │ (Scratch Directory 0500 / Script File 0400)
 │  Provisioner │      │  As Read-Only │
 └──────┬───────┘      └───────────────┘
        │
        ▼
 ┌──────────────┐      ┌───────────────┐
 │ Docker/gVisor│ ───> │ Intercept PID │ (Captures true Host PID of sandbox wrapper)
 │ Isolate Host │      │  Of Container │
 └──────┬───────┘      └───────┬───────┘
        │                      │
        │                      ▼
        │             ┌────────────────┐      ┌─────────────────┐
        │             │   bpftool map  │ ───> │ locked_sandboxes│ (eBPF Kernel Map)
        │             │  update (sudo) │      └────────┬────────┘
        │             └────────────────┘               │
        │                                              ▼
        │                                  ┌───────────────────────┐
        │                                  │ sys_enter_connect BPF │
        │                                  └───────────┬───────────┘
        ▼                                              │
 ┌──────────────┐                                      ▼
 │ Sandbox Exec │ ──(Attempts socket.connect)──> [Blocked instantly via]
 │  (runc/runsc)│                                [ bpf_send_signal(9)  ] (SIGKILL)
 └──────────────┘
```

### Component Details
1. **Cryptographic Provenance Validator (Go)**: Validates an incoming JSON token manifest containing tool credentials, allowed parameters, nonces, and timestamps against an ECDSA P-256 PEM public key using ASN.1 unmarshalled coordinates. Verified nonces are stored in a thread-safe, sliding-window cache with a dynamic background purger (5m TTL).
2. **Dual-Isolate Sandbox Manager (Go)**: Provisions dynamic workspace scratch directories inside `/tmp` with `0700` permission masks. Code files are written in read-only mode (`0400`) within a read-only folder configuration (`0500`). Execution proceeds inside a resource-constrained (`--memory=512m`, `--network=none`) container.
3. **eBPF Kernel Connect Blocker (C & Go)**: Installs a tracepoint program onto `tracepoint/syscalls/sys_enter_connect`. For every outbound socket connection attempt, the kernel program isolates the host user-space PID, inspects the `locked_sandboxes` BPF Map, and instantly halts the offending process via `bpf_send_signal(9)` (SIGKILL).
4. **Integration Interception Server (Go)**: Exposes a `/api/v1/intercept` REST API, sanitizes array and script arguments, programmatically manages BPF mapping states using non-blocking `sudo -n` commands, and returns execution metrics to the orchestrator.

---

## 📊 Project Completion Status

| Component | Target Specifications | Status | File Reference |
| :--- | :--- | :---: | :--- |
| **Enclave Keygen** | Asymmetric EC P-256 key pair generator with custom PEM writing. | **100% Complete** | [keygen.go](file:///home/sec/mini_project/Poject-1/tools/keygen.go) |
| **Token Signer** | Utility signer that performs SHA-256 hashing and ASN.1 marshaled ECDSA P-256 signing. | **100% Complete** | [signer.go](file:///home/sec/mini_project/Poject-1/tools/signer.go) |
| **Provenance Validator** | Thread-safe verifier with background sliding TTL nonce cache cleaning routines. | **100% Complete** | [validator.go](file:///home/sec/mini_project/Poject-1/validator/validator.go) |
| **Sandbox Manager** | Secure scratch directories, gVisor execution, PID extraction, and container teardown. | **100% Complete** | [sandbox.go](file:///home/sec/mini_project/Poject-1/sandbox/sandbox.go) |
| **Kernel Firewall** | eBPF connection blocker with tracepoint hooks (`sys_enter_connect`) and `SIGKILL` termination. | **100% Complete** | [firewall.bpf.c](file:///home/sec/mini_project/Poject-1/ebpf/firewall.bpf.c) |
| **Map Controller** | Pure Go eBPF user-space bpftool wrapper mapping PID to little-endian hex byte sequences. | **100% Complete** | [controller.go](file:///home/sec/mini_project/Poject-1/ebpf/controller.go) |
| **Interception Server** | REST HTTP server routing, scrubbing controls, and eBPF hook lock updates. | **100% Complete** | [main.go](file:///home/sec/mini_project/Poject-1/main.go) |
| **Integration Tests** | Concurrency-safe end-to-end integration tests mimicking full Intercept server payloads. | **100% Complete** | [integration_test.go](file:///home/sec/mini_project/Poject-1/tests/integration_test.go) |

---

## 🛡️ Robust Environmental Workarounds Implemented

To ensure flawless operation across production environments and localized developer machines, the project embeds professional fallback mechanisms:

1. **Docker gVisor Omission Fallback**:
   * *Problem*: Machines without gVisor (`runsc`) registered in their Docker daemons fail to launch gVisor-based containers.
   * *Solution*: The `sandbox` package dynamically inspects Docker runtimes via `docker info`. If `runsc` is unavailable, it gracefully runs the container using standard `runc` under strict networks (`--network=none`) and memory (`--memory=512m`) limits, logging a diagnostic warning to `Stderr`.
2. **Non-blocking Interactive Sudo Bypass**:
   * *Problem*: Executing map commands under `sudo` would block threads waiting for user password prompts on systems without passwordless sudo setup.
   * *Solution*: Uses `sudo -n` (non-interactive). If password-less authorization is blocked, or the host is not running as root, the system outputs warning diagnostics and proceeds with safe sandboxed execution rather than hard-crashing or hanging.
3. **Go Mod Isolation Boundary**:
   * *Problem*: Building in directories containing pre-extracted local Go distributions scans internal test files, generating compilation conflicts.
   * *Solution*: Placed a separate boundary `go.mod` file inside `local_go/go` to prevent recursive modules lookup scanning.

---

## 🚀 Execution & Runbook Guide

### 📋 Prerequisites
* Docker daemon running.
* Clang 14+ (if compiling kernel bytecode).
* Local Go toolchain installed in `local_go/` (automatically linked via Makefile).

---

### ⚙️ Command Lifecycles

All project lifecycle stages are managed using the central [Makefile](file:///home/sec/mini_project/Poject-1/Makefile):

#### 1. Cleaning up past artifacts
Remove all generated key certificates, logs, and binaries from prior runs:
```bash
make clean
```

#### 2. Compiling the eBPF Kernel Firewall
Compile the eBPF tracepoint driver from `ebpf/firewall.bpf.c` directly into BPF bytecode `ebpf/monitor.o`:
```bash
make build-ebpf
```

#### 3. Generating Security PKI Enclave Credentials
Invoke the key generator to create EC P-256 keypairs (`certs/private.pem` and `certs/public.pem` with `0600`/`0700` permission enforcement):
```bash
make generate-pki
```

#### 4. Running the End-to-End Test Suite
Trigger the full Go integration test suite. This programmatically compiles the server, generates valid credentials, crafts a signed manifest, routes a payload via the REST interception pipeline, spawns the sandboxed container, and assets successful validation checks:
```bash
make test
```

#### 5. Compiling and Starting the Production Interception Gateway
Start the zero-trust gateway hub listening securely on local address `127.0.0.1:9090`:
```bash
make run-system
```

---

## 🔮 Future Work & Roadmap Recommendations

1. **Persistent Daemon Ring-Buffer Auditing**:
   * *Recommendation*: Introduce an eBPF Ring Buffer (`BPF_MAP_TYPE_RINGBUF`) to transmit audit-trail blocked socket telemetry from the kernel to the user-space orchestrator asynchronously, bypassing standard kernel log parsing.
2. **Domain-Specific Name Whitelisting inside Kernel Space**:
   * *Recommendation*: Expand BPF filters to parse Socket Buffers (`__sk_buff`) during DNS resolution queries, verifying targets against a dynamic Domain BPF Map allowed table to support safe egress whitelisting.
3. **Structured Metrics Integration**:
   * *Recommendation*: Expose Prometheus `/metrics` reporting execution latency, blocked exfiltration attempts, active container sandboxes, and verification signature validation counters.
