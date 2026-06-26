package main

const dashboardHTML = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NexisCore Control Center</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=Outfit:wght@400;500;600;700&family=Fira+Code:wght@400;500&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-base: #0b0f19;
            --bg-surface: #131a2c;
            --bg-card: rgba(30, 41, 59, 0.4);
            --border-glow: rgba(99, 102, 241, 0.2);
            --color-primary: #6366f1; /* Indigo */
            --color-primary-glow: rgba(99, 102, 241, 0.4);
            --color-success: #10b981; /* Emerald */
            --color-success-glow: rgba(16, 185, 129, 0.2);
            --color-danger: #f43f5e; /* Rose */
            --color-danger-glow: rgba(244, 63, 94, 0.25);
            --color-warning: #f59e0b; /* Amber */
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            background-color: var(--bg-base);
            color: var(--text-main);
            font-family: 'Inter', sans-serif;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            overflow-x: hidden;
            background-image: 
                radial-gradient(circle at 10% 20%, rgba(99, 102, 241, 0.08) 0%, transparent 40%),
                radial-gradient(circle at 90% 80%, rgba(244, 63, 94, 0.05) 0%, transparent 40%);
        }

        header {
            background: rgba(19, 26, 44, 0.7);
            backdrop-filter: blur(12px);
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
            padding: 1.25rem 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            position: sticky;
            top: 0;
            z-index: 100;
        }

        .logo-container {
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }

        .logo-icon {
            background: linear-gradient(135deg, var(--color-primary), #8b5cf6);
            width: 2.25rem;
            height: 2.25rem;
            border-radius: 0.5rem;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 700;
            font-size: 1.25rem;
            color: white;
            box-shadow: 0 0 15px var(--color-primary-glow);
        }

        .logo-text {
            font-family: 'Outfit', sans-serif;
            font-size: 1.35rem;
            font-weight: 700;
            letter-spacing: -0.025em;
            background: linear-gradient(to right, #ffffff, #c7d2fe);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .status-badge {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            background: rgba(16, 185, 129, 0.1);
            border: 1px solid rgba(16, 185, 129, 0.2);
            padding: 0.35rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.85rem;
            font-weight: 500;
            color: var(--color-success);
        }

        .status-dot {
            width: 8px;
            height: 8px;
            background-color: var(--color-success);
            border-radius: 50%;
            box-shadow: 0 0 8px var(--color-success);
            animation: pulse 1.5s infinite;
        }

        @keyframes pulse {
            0% { opacity: 0.5; }
            50% { opacity: 1; }
            100% { opacity: 0.5; }
        }

        main {
            flex: 1;
            max-width: 1440px;
            width: 100%;
            margin: 0 auto;
            padding: 2rem;
            display: grid;
            grid-template-columns: 1fr 1.2fr;
            gap: 2rem;
        }

        @media (max-width: 1024px) {
            main {
                grid-template-columns: 1fr;
            }
        }

        .panel {
            background: var(--bg-card);
            backdrop-filter: blur(16px);
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-radius: 1rem;
            padding: 1.5rem;
            display: flex;
            flex-direction: column;
            gap: 1.5rem;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.2);
        }

        .panel-title {
            font-family: 'Outfit', sans-serif;
            font-size: 1.2rem;
            font-weight: 600;
            display: flex;
            align-items: center;
            justify-content: space-between;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
            padding-bottom: 0.75rem;
        }

        /* Metrics grid */
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 1rem;
        }

        .metric-card {
            background: rgba(19, 26, 44, 0.5);
            border: 1px solid rgba(255, 255, 255, 0.03);
            border-radius: 0.75rem;
            padding: 1.25rem;
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
            position: relative;
            overflow: hidden;
            transition: all 0.3s ease;
        }

        .metric-card:hover {
            border-color: rgba(255, 255, 255, 0.08);
            transform: translateY(-2px);
        }

        .metric-card.alert-active {
            border-color: var(--color-danger);
            background: rgba(244, 63, 94, 0.04);
            box-shadow: 0 0 15px rgba(244, 63, 94, 0.1);
        }

        .metric-card.alert-active .metric-value {
            color: var(--color-danger);
            text-shadow: 0 0 10px rgba(244, 63, 94, 0.3);
        }

        .metric-label {
            font-size: 0.85rem;
            font-weight: 500;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .metric-value {
            font-family: 'Outfit', sans-serif;
            font-size: 2.25rem;
            font-weight: 700;
            color: var(--text-main);
        }

        /* Logs feed */
        .logs-container {
            flex: 1;
            background: rgba(11, 15, 25, 0.6);
            border: 1px solid rgba(255, 255, 255, 0.03);
            border-radius: 0.75rem;
            min-height: 250px;
            max-height: 380px;
            overflow-y: auto;
            padding: 1rem;
            display: flex;
            flex-direction: column;
            gap: 0.75rem;
            font-family: 'Fira Code', monospace;
            font-size: 0.825rem;
        }

        .log-entry {
            padding: 0.5rem 0.75rem;
            border-radius: 0.35rem;
            line-height: 1.4;
            animation: fadeIn 0.3s ease-out;
            border-left: 3px solid transparent;
        }

        .log-entry.info {
            background: rgba(255, 255, 255, 0.02);
            color: #e2e8f0;
            border-left-color: var(--text-muted);
        }

        .log-entry.alert {
            background: rgba(244, 63, 94, 0.06);
            color: #fda4af;
            border-left-color: var(--color-danger);
        }

        .log-entry.success {
            background: rgba(16, 185, 129, 0.06);
            color: #a7f3d0;
            border-left-color: var(--color-success);
        }

        .log-timestamp {
            color: var(--text-muted);
            margin-right: 0.5rem;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(5px); }
            to { opacity: 1; transform: translateY(0); }
        }

        /* Playground panel */
        .playground-form {
            display: flex;
            flex-direction: column;
            gap: 1rem;
        }

        .form-group {
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }

        label {
            font-size: 0.875rem;
            font-weight: 500;
            color: var(--text-muted);
        }

        select, textarea {
            background: #0f172a;
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 0.5rem;
            color: var(--text-main);
            padding: 0.75rem;
            font-family: 'Fira Code', monospace;
            font-size: 0.9rem;
            outline: none;
            transition: all 0.3s ease;
        }

        select:focus, textarea:focus {
            border-color: var(--color-primary);
            box-shadow: 0 0 10px var(--border-glow);
        }

        textarea {
            resize: vertical;
            min-height: 160px;
        }

        .btn {
            background: linear-gradient(135deg, var(--color-primary) 0%, #4f46e5 100%);
            color: white;
            border: none;
            border-radius: 0.5rem;
            padding: 0.85rem;
            font-family: 'Outfit', sans-serif;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            box-shadow: 0 4px 12px var(--color-primary-glow);
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0.5rem;
        }

        .btn:hover {
            transform: translateY(-1px);
            box-shadow: 0 6px 16px rgba(99, 102, 241, 0.5);
        }

        .btn:active {
            transform: translateY(0);
        }

        .btn:disabled {
            background: rgba(255, 255, 255, 0.08);
            color: var(--text-muted);
            box-shadow: none;
            cursor: not-allowed;
        }

        .console-container {
            background: #090d16;
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-radius: 0.75rem;
            padding: 1rem;
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
            font-family: 'Fira Code', monospace;
            font-size: 0.85rem;
            min-height: 160px;
            max-height: 250px;
            overflow-y: auto;
        }

        .console-header {
            display: flex;
            justify-content: space-between;
            color: var(--text-muted);
            font-size: 0.75rem;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
            padding-bottom: 0.5rem;
            margin-bottom: 0.25rem;
        }

        .console-output {
            white-space: pre-wrap;
            line-height: 1.5;
        }

        .console-output.success {
            color: var(--color-success);
        }

        .console-output.error {
            color: var(--color-danger);
        }

        /* Scrollbar styles */
        ::-webkit-scrollbar {
            width: 6px;
        }

        ::-webkit-scrollbar-track {
            background: transparent;
        }

        ::-webkit-scrollbar-thumb {
            background: rgba(255, 255, 255, 0.1);
            border-radius: 3px;
        }

        ::-webkit-scrollbar-thumb:hover {
            background: rgba(255, 255, 255, 0.2);
        }
    </style>
</head>
<body>

    <header>
        <div class="logo-container">
            <div class="logo-icon">N</div>
            <div class="logo-text">NexisCore Gateway</div>
        </div>
        <div class="status-badge">
            <div class="status-dot"></div>
            <span>Kernel eBPF Shield Active</span>
        </div>
    </header>

    <main>
        <!-- Telemetry & Alerts -->
        <div class="panel">
            <div class="panel-title">
                <span>Security Telemetry</span>
                <span style="font-size: 0.8rem; font-weight: normal; color: var(--text-muted);">Real-Time Updates</span>
            </div>

            <div class="metrics-grid">
                <div class="metric-card">
                    <span class="metric-label">Active Sandboxes</span>
                    <span id="metric-sandboxes" class="metric-value">0</span>
                </div>
                <div class="metric-card">
                    <span class="metric-label">Verified Signatures</span>
                    <span id="metric-signatures" class="metric-value">0</span>
                </div>
                <div class="metric-card" id="card-network">
                    <span class="metric-label">Blocked Network Breaches</span>
                    <span id="metric-network" class="metric-value">0</span>
                </div>
                <div class="metric-card" id="card-file">
                    <span class="metric-label">Blocked File Bypasses</span>
                    <span id="metric-file" class="metric-value">0</span>
                </div>
            </div>

            <div class="panel-title">
                <span>Kernel Audit Log Stream</span>
            </div>

            <div class="logs-container" id="logs-feed">
                <div class="log-entry info">
                    <span class="log-timestamp">[System Ready]</span> Telemetry listener actively monitoring Kernel eBPF channels...
                </div>
            </div>
        </div>

        <!-- Playground -->
        <div class="panel">
            <div class="panel-title">
                <span>Containment Sandbox Playground</span>
            </div>

            <div class="playground-form">
                <div class="form-group">
                    <label for="template-select">Select Simulation Template</label>
                    <select id="template-select">
                        <option value="benign">1. Benign Tool Execution (Permitted)</option>
                        <option value="egress_raw">2. Exploit: Egress Breach via Direct IP Connect (Blocked by eBPF)</option>
                        <option value="dns_allowed">3. DNS Resolution: Whitelisted Domain (Allowed)</option>
                        <option value="dns_blocked">4. Exploit: DNS Exfiltration on Restricted Domain (Blocked by eBPF)</option>
                        <option value="file_boundary">5. Exploit: File Boundary Intrusion /etc/passwd (Blocked by eBPF)</option>
                    </select>
                </div>

                <div class="form-group">
                    <label for="script-editor">Python Tool Script</label>
                    <textarea id="script-editor" spellcheck="false"></textarea>
                </div>

                <button id="run-btn" class="btn">
                    <svg style="width: 1.2rem; height: 1.2rem;" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"></path>
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                    </svg>
                    Deploy & Execute in Isolate
                </button>
            </div>

            <div class="console-container">
                <div class="console-header">
                    <span>Isolate Output Console</span>
                    <span id="execution-status">Ready</span>
                </div>
                <div id="console-out" class="console-output">Select a template and click run.</div>
            </div>
        </div>
    </main>

    <script>
        const templates = {
            benign: '# Benign Tool execution inside Sandbox\nimport time\nprint("[+] Sandbox initialized successfully.")\nprint("[+] Reading local runtime properties...")\nprint("[SUCCESS] Tool task completed without egress tampering.")\n',
            egress_raw: '# Exploit Attempt: Direct TCP socket exfiltration\nimport socket\nprint("[+] Sandboxed task running...")\nprint("[+] Attempting raw connection to unauthorized IP 1.1.1.1:80...")\ntry:\n    socket.socket().connect((\'1.1.1.1\', 80))\n    print("[FAIL] Connection succeeded! Zero-Trust Bypass!")\nexcept Exception as e:\n    print(f"[ERROR] Connection failed: {e}")\n',
            dns_allowed: '# Safe DNS query to a whitelisted destination\nimport socket\nprint("[+] Safe script running...")\nprint("[+] Resolving whitelisted host: google.com...")\ntry:\n    ip = socket.gethostbyname(\'google.com\')\n    print(f"[SUCCESS] DNS resolved google.com to {ip}")\nexcept Exception as e:\n    print(f"[ERROR] Resolution failed: {e}")\n',
            dns_blocked: '# Exploit Attempt: Exfiltration query to unauthorized domain\nimport socket\nprint("[+] Sandboxed task running...")\nprint("[+] Resolving unauthorized host: malicious-exfil.com...")\ntry:\n    ip = socket.gethostbyname(\'malicious-exfil.com\')\n    print(f"[FAIL] Domain resolved to {ip}! Exfiltration channel open!")\nexcept Exception as e:\n    print(f"[SUCCESS] Resolution blocked or failed: {e}")\n',
            file_boundary: '# Exploit Attempt: Path traversal access to sensitive data\nprint("[+] Sandboxed task running...")\nprint("[+] Attempting to read restricted file /etc/passwd...")\ntry:\n    with open(\'/etc/passwd\', \'r\') as f:\n        print("[FAIL] Read /etc/passwd: " + f.read(50) + "...")\nexcept Exception as e:\n    print(f"[SUCCESS] Path boundary block active: {e}")\n'
        };

        const templateSelect = document.getElementById('template-select');
        const scriptEditor = document.getElementById('script-editor');
        const runBtn = document.getElementById('run-btn');
        const consoleOut = document.getElementById('console-out');
        const executionStatus = document.getElementById('execution-status');
        const logsFeed = document.getElementById('logs-feed');

        // Set default template
        scriptEditor.value = templates.benign;

        templateSelect.addEventListener('change', () => {
            scriptEditor.value = templates[templateSelect.value];
        });

        // Metrics tracking
        let lastMetrics = {
            blocked_network_breaches: 0,
            blocked_file_bypasses: 0,
            verified_signatures: 0
        };

        function addLog(message, type = 'info') {
            const entry = document.createElement('div');
            entry.className = 'log-entry ' + type;
            const timeStr = new Date().toLocaleTimeString();
            entry.innerHTML = '<span class="log-timestamp">[' + timeStr + ']</span> ' + message;
            logsFeed.appendChild(entry);
            logsFeed.scrollTop = logsFeed.scrollHeight;
        }

        async function updateTelemetry() {
            try {
                const response = await fetch('/api/v1/telemetry');
                if (!response.ok) return;
                const data = await response.json();

                document.getElementById('metric-sandboxes').textContent = data.active_sandboxes;
                document.getElementById('metric-signatures').textContent = data.verified_signatures;
                document.getElementById('metric-network').textContent = data.blocked_network_breaches;
                document.getElementById('metric-file').textContent = data.blocked_file_bypasses;

                // Toggle breach warning glow
                const cardNetwork = document.getElementById('card-network');
                if (data.blocked_network_breaches > 0) {
                    cardNetwork.classList.add('alert-active');
                } else {
                    cardNetwork.classList.remove('alert-active');
                }

                const cardFile = document.getElementById('card-file');
                if (data.blocked_file_bypasses > 0) {
                    cardFile.classList.add('alert-active');
                } else {
                    cardFile.classList.remove('alert-active');
                }

                // Detect increments and log to audit stream
                if (data.blocked_network_breaches > lastMetrics.blocked_network_breaches) {
                    const diff = data.blocked_network_breaches - lastMetrics.blocked_network_breaches;
                    addLog('🚨 KERNEL ALERT: Egress network breach attempt detected! Process terminated instantly via SIGKILL (9). Zero bytes leaked.', 'alert');
                }

                if (data.blocked_file_bypasses > lastMetrics.blocked_file_bypasses) {
                    addLog('🚨 KERNEL ALERT: Sandbox file boundary intrusion attempt blocked! Target thread killed via SIGKILL (9).', 'alert');
                }

                if (data.verified_signatures > lastMetrics.verified_signatures) {
                    addLog('🛡️ Signature verified. Validating cryptographic credentials for new sandbox.', 'success');
                }

                lastMetrics = data;
            } catch (err) {
                console.error("Telemetry update error:", err);
            }
        }

        // Poll telemetry
        setInterval(updateTelemetry, 1000);
        updateTelemetry();

        // Run script
        runBtn.addEventListener('click', async () => {
            const script = scriptEditor.value;
            runBtn.disabled = true;
            executionStatus.textContent = "Deploying...";
            consoleOut.textContent = "Provisioning secure dual-isolate container (runsc/runc)...";
            consoleOut.className = "console-output";

            try {
                const response = await fetch('/api/v1/playground/run', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ script: script })
                });

                const result = await response.json();
                runBtn.disabled = false;

                if (!result.success) {
                    executionStatus.textContent = "Error";
                    consoleOut.className = "console-output error";
                    consoleOut.textContent = result.message || "Failed to execute sandbox script.";
                    addLog('❌ Sandbox launch failed: ' + (result.message || 'Error'), 'info');
                    return;
                }

                const output = result.output;
                executionStatus.textContent = "Completed";
                
                let outText = "";
                if (output.stdout) {
                    outText += output.stdout;
                }
                if (output.stderr) {
                    outText += output.stderr;
                }

                if (output.exit_code === 9 || output.exit_code === 137 || output.exit_code === -1 || output.exit_code === -2 || outText.includes("Network is unreachable") || outText.includes("SIGKILL") || outText.includes("killed")) {
                    consoleOut.className = "console-output error";
                    if (outText.includes("Network is unreachable")) {
                        outText += "\n[SECURITY CONTAINMENT] Outbound connection dropped at sandbox network bridge context.";
                    } else {
                        outText += "\n[SECURITY WARNING] Isolate terminated with code " + output.exit_code + " (SIGKILL). eBPF containment successfully triggered.";
                    }
                    addLog('🛡️ Isolation security policy enforced.', 'success');
                } else {
                    consoleOut.className = "console-output success";
                }

                consoleOut.textContent = outText || "[No output]";

            } catch (err) {
                runBtn.disabled = false;
                executionStatus.textContent = "Failed";
                consoleOut.className = "console-output error";
                consoleOut.textContent = "Failed to dispatch request: " + err;
            }
        });
    </script>
</body>
</html>
`
