# NexisCore Automated Lifecycle Build Makefile Runbook
.PHONY: build-ebpf build-antitamper-ebpf load-ebpf generate-pki run-system run-full test-exploit clean test

# 1a. Compile BPF Kernel Firewall binary payload
build-ebpf:
	@echo "=== Compiling eBPF Kernel firewall bytecode ==="
	@cp -f ebpf/kernel/firewall.bpf.c ebpf/kernel/monitor.c
	@rm -f ebpf/kernel/monitor.o
	clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -I/usr/include -I/usr/include/x86_64-linux-gnu -Iebpf/kernel -c ebpf/kernel/monitor.c -o ebpf/kernel/monitor.o
	@echo "[SUCCESS] eBPF Object successfully compiled to ebpf/kernel/monitor.o"

# 1b. Compile Anti-Tamper eBPF probes (ptrace/mprotect/execve)
build-antitamper-ebpf:
	@echo "=== Compiling Anti-Tamper eBPF probes ==="
	clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -I/usr/include -I/usr/include/x86_64-linux-gnu -Iebpf/kernel -c ebpf/kernel/antitamper.bpf.c -o ebpf/kernel/antitamper.o
	@echo "[SUCCESS] Anti-tamper eBPF object compiled to ebpf/kernel/antitamper.o"

# 2. Mount and pin driver into the host operating system trace kernel pipelines
load-ebpf: build-ebpf
	@echo "=== Loading and Pinning eBPF Tracepoint Driver ==="
	@if ! mountpoint -q /sys/fs/bpf; then \
		echo "[+] Mounting bpffs on /sys/fs/bpf..."; \
		sudo mount -t bpf bpf /sys/fs/bpf; \
	fi
	sudo rm -f /sys/fs/bpf/nexis_connect
	sudo rm -rf /sys/fs/bpf/maps
	sudo mkdir -p /sys/fs/bpf/maps
	sudo bpftool prog load ebpf/kernel/monitor.o /sys/fs/bpf/nexis_connect type tracepoint pinmaps /sys/fs/bpf/maps
	@echo "[SUCCESS] Pinned Maps directory structure created."
	@echo "[SUCCESS] eBPF driver loaded successfully to /sys/fs/bpf/nexis_connect"

# 3. Invokes keygen script to generate EC P-256 pair
generate-pki:
	@echo "=== Generating Enclave PKI Keys ==="
	./local_go/go/bin/go run tools/keygen.go
	@cp -f certs/public.pem public_key.pem
	@echo "[SUCCESS] Public key copied to active gateway workspace runtime root."

# 4. Compiles and launches active gateway hub server (original)
run-system: generate-pki build-ebpf
	@echo "=== Starting NexisCore Active Interception Gateway ==="
	./local_go/go/bin/go build -o nexiscore_bin main.go dashboard.go
	./nexiscore_bin

# 4b. Full system run with all 4 security modules (anti-tamper eBPF + full binary)
run-full: generate-pki build-ebpf build-antitamper-ebpf
	@echo "=== Starting NexisCore Enterprise Gateway (All 4 Modules Active) ==="
	./local_go/go/bin/go build -o nexiscore_bin main.go dashboard.go
	./nexiscore_bin

# 5. E2E Go integration test runner
test: generate-pki build-ebpf
	@echo "=== Running Go Integration Test suite ==="
	cd tests && ../local_go/go/bin/go test -v

# 6. Fires prompt-injection socket connect connection and asserts kernel containment blocking
test-exploit: generate-pki
	@echo "=== Running Containment Breach Simulation & Exploit Connect Test ==="
	@echo "[+] Compiling nexiscore_bin binary..."
	./local_go/go/bin/go build -o nexiscore_bin main.go dashboard.go
	@echo "[+] Launching gateway server in background..."
	@./nexiscore_bin > /tmp/nexiscore_test.log 2>&1 & \
	SERVER_PID=$$! ; \
	sleep 2 ; \
	\
	echo "[+] Constructing mock exploit payload targeting restricted socket connect..."; \
	NONCE="exploit_test_nonce_$$RANDOM" ; \
	MANIFEST="{\"nonce\":\"$$NONCE\",\"timestamp\":$$(date +%s),\"tool_name\":\"python_interpreter\",\"tool_id\":\"python_interpreter\"}" ; \
	\
	echo "[+] Signing manifest using tools/signer.go..."; \
	SIGNATURE=$$(./local_go/go/bin/go run tools/signer.go "$$MANIFEST") ; \
	\
	EXPLOIT_SCRIPT="import socket, sys; print('BREACH: Attempting connect to 1.1.1.1:80'); socket.socket().connect(('1.1.1.1', 80)); print('BREACH: Connect succeeded (FAIL)')" ; \
	\
	JSON_PAYLOAD=$$(printf '{"script":"%s","variables":{},"manifest":"%s","signature":"%s"}' "$$EXPLOIT_SCRIPT" "$$(echo "$$MANIFEST" | sed 's/"/\\"/g')" "$$SIGNATURE") ; \
	\
	echo "[+] Sending payload to interception gateway /api/v1/intercept..."; \
	RESPONSE=$$(curl -s -X POST -H "Content-Type: application/json" -d "$$JSON_PAYLOAD" http://127.0.0.1:9090/api/v1/intercept) ; \
	echo "[+] Gateway Response: $$RESPONSE" ; \
	\
	echo "[+] Checking if socket connection was blocked and process was terminated by sandbox containment..."; \
	if echo "$$RESPONSE" | grep -q "terminated" || echo "$$RESPONSE" | grep -q "Execution timed out" || echo "$$RESPONSE" | grep -q "exit_code\":-1" || echo "$$RESPONSE" | grep -q "exit_code\":137" || echo "$$RESPONSE" | grep -q "exit_code\":9" || echo "$$RESPONSE" | grep -q "SIGKILL" || echo "$$RESPONSE" | grep -q "exit_code\":-2" || echo "$$RESPONSE" | grep -q "Network is unreachable"; then \
		echo "[SUCCESS] Sandbox containment caught socket breach! Zero Data leaked!"; \
		kill -9 $$SERVER_PID 2>/dev/null || true; \
		exit 0; \
	else \
		echo "[FAIL] Exploit succeeded or socket connection was not blocked by sandbox containment!"; \
		kill -9 $$SERVER_PID 2>/dev/null || true; \
		exit 1; \
	fi

clean:
	@echo "=== Cleaning environment logs and binaries ==="
	rm -rf certs/
	rm -f public_key.pem nexiscore_bin generate_keys_bin
	rm -f ebpf/kernel/monitor.c ebpf/kernel/monitor.o ebpf/kernel/firewall.bpf.o
	rm -f ebpf/kernel/antitamper.o
	rm -f nexiscore_ocsf.jsonl siem_deadletter.jsonl
