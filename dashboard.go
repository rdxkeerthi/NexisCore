package main

const dashboardHTML = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NexisCore Enterprise Security</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=Outfit:wght@300;400;500;600;700;800&family=Fira+Code:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-base: #060913;
            --bg-surface: #0f1524;
            --bg-card: rgba(15, 23, 42, 0.6);
            --border-subtle: rgba(255, 255, 255, 0.08);
            --border-glow: rgba(99, 102, 241, 0.4);
            --color-primary: #8b5cf6; /* Violet */
            --color-primary-glow: rgba(139, 92, 246, 0.5);
            --color-secondary: #3b82f6; /* Blue */
            --color-success: #10b981; /* Emerald */
            --color-success-bg: rgba(16, 185, 129, 0.1);
            --color-danger: #ef4444; /* Red */
            --color-danger-bg: rgba(239, 68, 68, 0.1);
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
                radial-gradient(circle at 15% 50%, rgba(59, 130, 246, 0.12) 0%, transparent 50%),
                radial-gradient(circle at 85% 30%, rgba(139, 92, 246, 0.12) 0%, transparent 50%),
                radial-gradient(circle at 50% 90%, rgba(16, 185, 129, 0.05) 0%, transparent 50%);
            background-attachment: fixed;
        }

        /* Glassmorphism Header */
        header {
            background: rgba(6, 9, 19, 0.7);
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            border-bottom: 1px solid var(--border-subtle);
            padding: 1rem 2.5rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            position: sticky;
            top: 0;
            z-index: 100;
            box-shadow: 0 4px 30px rgba(0, 0, 0, 0.3);
        }

        .logo-container {
            display: flex;
            align-items: center;
            gap: 1rem;
        }

        .logo-icon {
            background: linear-gradient(135deg, #60a5fa, #8b5cf6);
            width: 2.75rem;
            height: 2.75rem;
            border-radius: 0.75rem;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 800;
            font-size: 1.5rem;
            color: white;
            box-shadow: 0 0 20px var(--color-primary-glow);
            position: relative;
        }
        
        .logo-icon::after {
            content: '';
            position: absolute;
            inset: -2px;
            border-radius: inherit;
            background: inherit;
            filter: blur(8px);
            opacity: 0.6;
            z-index: -1;
        }

        .logo-text {
            font-family: 'Outfit', sans-serif;
            font-size: 1.5rem;
            font-weight: 700;
            letter-spacing: -0.02em;
            background: linear-gradient(to right, #ffffff, #93c5fd);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .status-badge {
            display: flex;
            align-items: center;
            gap: 0.6rem;
            background: rgba(16, 185, 129, 0.05);
            border: 1px solid rgba(16, 185, 129, 0.3);
            padding: 0.5rem 1rem;
            border-radius: 9999px;
            font-size: 0.9rem;
            font-weight: 600;
            color: var(--color-success);
            box-shadow: 0 0 15px rgba(16, 185, 129, 0.1);
        }

        .status-dot {
            width: 10px;
            height: 10px;
            background-color: var(--color-success);
            border-radius: 50%;
            box-shadow: 0 0 10px var(--color-success);
            animation: pulse 2s infinite cubic-bezier(0.4, 0, 0.6, 1);
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.4; transform: scale(0.8); }
        }

        main {
            flex: 1;
            max-width: 1600px;
            width: 100%;
            margin: 0 auto;
            padding: 2.5rem;
            display: grid;
            grid-template-columns: 1fr 1.1fr;
            gap: 2.5rem;
        }

        @media (max-width: 1200px) {
            main {
                grid-template-columns: 1fr;
            }
        }

        /* Glass panels */
        .panel {
            background: var(--bg-card);
            backdrop-filter: blur(16px);
            -webkit-backdrop-filter: blur(16px);
            border: 1px solid var(--border-subtle);
            border-radius: 1.25rem;
            padding: 1.75rem;
            display: flex;
            flex-direction: column;
            gap: 1.5rem;
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.4), inset 0 1px 0 rgba(255,255,255,0.05);
            position: relative;
            overflow: hidden;
        }
        
        .panel::before {
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0; height: 1px;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.1), transparent);
        }

        .panel-title {
            font-family: 'Outfit', sans-serif;
            font-size: 1.4rem;
            font-weight: 600;
            display: flex;
            align-items: center;
            justify-content: space-between;
            border-bottom: 1px solid var(--border-subtle);
            padding-bottom: 1rem;
            color: #ffffff;
        }

        /* Highly stylized metrics grid */
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 1rem;
        }

        @media (max-width: 768px) {
            .metrics-grid {
                grid-template-columns: repeat(2, 1fr);
            }
        }

        .metric-card {
            background: linear-gradient(145deg, rgba(30, 41, 59, 0.6), rgba(15, 23, 42, 0.8));
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-radius: 1rem;
            padding: 1.25rem;
            display: flex;
            flex-direction: column;
            gap: 0.75rem;
            position: relative;
            overflow: hidden;
            transition: transform 0.3s cubic-bezier(0.4, 0, 0.2, 1), box-shadow 0.3s ease;
        }

        .metric-card::before {
            content: '';
            position: absolute;
            top: 0; left: 0; width: 100%; height: 100%;
            background: linear-gradient(135deg, rgba(255,255,255,0.05) 0%, transparent 100%);
            pointer-events: none;
        }

        .metric-card:hover {
            transform: translateY(-4px);
            box-shadow: 0 12px 24px rgba(0,0,0,0.4);
            border-color: rgba(255,255,255,0.15);
        }

        .metric-card.alert-active {
            border-color: var(--color-danger);
            background: linear-gradient(145deg, rgba(239, 68, 68, 0.1), rgba(15, 23, 42, 0.8));
            box-shadow: 0 0 20px rgba(239, 68, 68, 0.2);
            animation: breathe 2s infinite alternate;
        }

        @keyframes breathe {
            0% { box-shadow: 0 0 15px rgba(239, 68, 68, 0.1); }
            100% { box-shadow: 0 0 25px rgba(239, 68, 68, 0.3); }
        }

        .metric-card.alert-active .metric-value {
            color: #fca5a5;
            text-shadow: 0 0 12px rgba(239, 68, 68, 0.5);
        }

        .metric-label {
            font-size: 0.75rem;
            font-weight: 600;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.08em;
            z-index: 1;
        }

        .metric-value {
            font-family: 'Outfit', sans-serif;
            font-size: 2.5rem;
            font-weight: 800;
            color: var(--text-main);
            z-index: 1;
            line-height: 1;
        }

        /* Logs feed */
        .logs-container {
            flex: 1;
            background: #050810;
            border: 1px solid var(--border-subtle);
            border-radius: 1rem;
            min-height: 280px;
            max-height: 400px;
            overflow-y: auto;
            padding: 1.25rem;
            display: flex;
            flex-direction: column;
            gap: 0.85rem;
            font-family: 'Fira Code', monospace;
            font-size: 0.85rem;
            box-shadow: inset 0 0 20px rgba(0,0,0,0.5);
        }

        .log-entry {
            padding: 0.75rem 1rem;
            border-radius: 0.5rem;
            line-height: 1.5;
            animation: slideIn 0.4s cubic-bezier(0.16, 1, 0.3, 1);
            border-left: 4px solid transparent;
            backdrop-filter: blur(4px);
        }

        .log-entry.info {
            background: rgba(255, 255, 255, 0.03);
            color: #cbd5e1;
            border-left-color: #475569;
        }

        .log-entry.warning {
            background: rgba(245, 158, 11, 0.08);
            color: #fcd34d;
            border-left-color: var(--color-warning);
        }

        .log-entry.alert {
            background: rgba(239, 68, 68, 0.08);
            color: #fca5a5;
            border-left-color: var(--color-danger);
            box-shadow: 0 0 15px rgba(239, 68, 68, 0.1);
        }

        .log-entry.success {
            background: rgba(16, 185, 129, 0.08);
            color: #6ee7b7;
            border-left-color: var(--color-success);
        }

        .log-timestamp {
            color: #64748b;
            margin-right: 0.75rem;
            font-size: 0.8rem;
        }

        @keyframes slideIn {
            from { opacity: 0; transform: translateX(-10px); }
            to { opacity: 1; transform: translateX(0); }
        }

        /* Form elements */
        .playground-form {
            display: flex;
            flex-direction: column;
            gap: 1.25rem;
        }

        .form-group {
            display: flex;
            flex-direction: column;
            gap: 0.6rem;
        }

        label {
            font-size: 0.9rem;
            font-weight: 500;
            color: #cbd5e1;
        }

        select, textarea {
            background: rgba(15, 23, 42, 0.8);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 0.75rem;
            color: var(--text-main);
            padding: 1rem;
            font-family: 'Fira Code', monospace;
            font-size: 0.9rem;
            outline: none;
            transition: all 0.3s ease;
            box-shadow: inset 0 2px 4px rgba(0,0,0,0.2);
        }

        select:focus, textarea:focus {
            border-color: var(--color-secondary);
            box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.2), inset 0 2px 4px rgba(0,0,0,0.2);
            background: rgba(15, 23, 42, 0.95);
        }

        textarea {
            resize: vertical;
            min-height: 200px;
            line-height: 1.5;
        }

        /* Stylized Button */
        .btn {
            background: linear-gradient(135deg, var(--color-primary) 0%, #4f46e5 100%);
            color: white;
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 0.75rem;
            padding: 1rem;
            font-family: 'Outfit', sans-serif;
            font-size: 1.1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            box-shadow: 0 8px 20px rgba(79, 70, 229, 0.3), inset 0 1px 0 rgba(255,255,255,0.2);
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0.75rem;
            position: relative;
            overflow: hidden;
        }

        .btn::after {
            content: '';
            position: absolute;
            top: -50%; left: -50%; width: 200%; height: 200%;
            background: linear-gradient(to bottom right, rgba(255,255,255,0.2), transparent, transparent);
            transform: rotate(45deg);
            transition: all 0.5s ease;
        }

        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 12px 25px rgba(79, 70, 229, 0.4), inset 0 1px 0 rgba(255,255,255,0.3);
        }
        
        .btn:hover::after {
            left: 100%; top: 100%;
        }

        .btn:active {
            transform: translateY(1px);
            box-shadow: 0 4px 10px rgba(79, 70, 229, 0.3);
        }

        .btn:disabled {
            background: #1e293b;
            color: #64748b;
            box-shadow: none;
            cursor: not-allowed;
            border-color: transparent;
        }

        .console-container {
            background: #000000;
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 1rem;
            padding: 1.25rem;
            display: flex;
            flex-direction: column;
            gap: 0.75rem;
            font-family: 'Fira Code', monospace;
            font-size: 0.85rem;
            min-height: 200px;
            max-height: 300px;
            overflow-y: auto;
            position: relative;
        }

        .console-header {
            display: flex;
            justify-content: space-between;
            color: #94a3b8;
            font-size: 0.8rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            border-bottom: 1px dashed rgba(255, 255, 255, 0.2);
            padding-bottom: 0.75rem;
            margin-bottom: 0.25rem;
        }

        .console-output {
            white-space: pre-wrap;
            line-height: 1.6;
        }

        .console-output.success { color: #34d399; }
        .console-output.error { color: #f87171; }

        /* Custom Scrollbar */
        ::-webkit-scrollbar { width: 8px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb {
            background: rgba(255, 255, 255, 0.15);
            border-radius: 4px;
        }
        ::-webkit-scrollbar-thumb:hover { background: rgba(255, 255, 255, 0.25); }
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
                <span style="font-size: 0.85rem; font-weight: 500; color: #64748b; background: rgba(255,255,255,0.05); padding: 0.3rem 0.8rem; border-radius: 1rem;">Live Updates</span>
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
                    <span class="metric-label">Network Breaches</span>
                    <span id="metric-network" class="metric-value">0</span>
                </div>
                <div class="metric-card" id="card-file">
                    <span class="metric-label">File Bypasses</span>
                    <span id="metric-file" class="metric-value">0</span>
                </div>
                <div class="metric-card" id="card-dlp">
                    <span class="metric-label">DLP Redactions</span>
                    <span id="metric-dlp" class="metric-value">0</span>
                </div>
                <div class="metric-card" id="card-shell">
                    <span class="metric-label">Blocked Shells</span>
                    <span id="metric-shell" class="metric-value">0</span>
                </div>
                <div class="metric-card" id="card-ptrace">
                    <span class="metric-label">Ptrace Denied</span>
                    <span id="metric-ptrace" class="metric-value">0</span>
                </div>
                <div class="metric-card">
                    <span class="metric-label">OCSF Submitted</span>
                    <span id="metric-ocsf" class="metric-value">0</span>
                </div>
            </div>

            <div class="panel-title" style="margin-top: 1rem;">
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
                        <option value="file_boundary">5. Exploit: File Boundary Intrusion /etc/passwd (Blocked by Sandbox)</option>
                        <option value="dlp_credit_card">6. Exploit: Exfiltrate Credit Card Data (Blocked by DLP)</option>
                        <option value="anti_tamper_shell">7. Exploit: Spawn Shell /bin/sh (Blocked by Kernel Anti-Tamper)</option>
                        <option value="memory_ptrace">8. Exploit: Attach Debugger (Blocked by Kernel Anti-Tamper)</option>
                    </select>
                </div>

                <div class="form-group">
                    <label for="script-editor">Python Tool Script</label>
                    <textarea id="script-editor" spellcheck="false"></textarea>
                </div>

                <button id="run-btn" class="btn">
                    <svg style="width: 1.4rem; height: 1.4rem;" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path>
                    </svg>
                    Deploy & Execute in Isolate
                </button>
            </div>

            <div class="console-container">
                <div class="console-header">
                    <span>Isolate Output Console</span>
                    <span id="execution-status" style="color: #cbd5e1;">Ready</span>
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
            file_boundary: '# Exploit Attempt: Path traversal access to sensitive data\nprint("[+] Sandboxed task running...")\nprint("[+] Attempting to read restricted file /etc/passwd...")\ntry:\n    with open(\'/etc/passwd\', \'r\') as f:\n        print("[FAIL] Read /etc/passwd: " + f.read(50) + "...")\nexcept Exception as e:\n    print(f"[SUCCESS] Path boundary block active: {e}")\n',
            dlp_credit_card: '# Exploit Attempt: Egress Credit Card Data (DLP Redaction)\nprint("[+] Tool attempting to leak customer CC data to output...")\n# Emitting payload that triggers Luhn validation\nprint("Customer Details: John Doe")\nprint("Card Number: 4532 1234 5678 9010 CVV 123")\nprint("[+] Check DLP intercept logs. If the payload is blocked/scrubbed, DLP works.")\n',
            anti_tamper_shell: '# Exploit Attempt: Spawning an interactive shell\nimport os\nprint("[+] Attempting to spawn /bin/sh...")\ntry:\n    os.system("/bin/sh -c \'echo Pwned!\'")\n    print("[FAIL] Shell spawned successfully. eBPF bypassed.")\nexcept Exception as e:\n    print(f"[SUCCESS] Shell blocked: {e}")\n',
            memory_ptrace: '# Exploit Attempt: Debugger attachment (PTRACE_ATTACH)\nimport ctypes, os\nprint("[+] Attempting to attach ptrace to process...")\ntry:\n    libc = ctypes.CDLL("libc.so.6")\n    # PTRACE_ATTACH = 16\n    libc.ptrace(16, os.getppid(), 0, 0)\n    print("[FAIL] Ptrace attachment succeeded. Anti-Tamper bypassed.")\nexcept Exception as e:\n    print(f"[SUCCESS] Ptrace blocked: {e}")\n'
        };

        const templateSelect = document.getElementById('template-select');
        const scriptEditor = document.getElementById('script-editor');
        const runBtn = document.getElementById('run-btn');
        const consoleOut = document.getElementById('console-out');
        const executionStatus = document.getElementById('execution-status');
        const logsFeed = document.getElementById('logs-feed');

        scriptEditor.value = templates.benign;

        templateSelect.addEventListener('change', () => {
            scriptEditor.value = templates[templateSelect.value];
        });

        let lastMetrics = {
            blocked_network_breaches: 0,
            blocked_file_bypasses: 0,
            verified_signatures: 0,
            dlp_redactions: 0,
            blocked_shell_spawns: 0,
            blocked_ptrace_attempts: 0,
            ocsf_submitted: 0
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
                document.getElementById('metric-dlp').textContent = data.dlp_redactions;
                document.getElementById('metric-shell').textContent = data.blocked_shell_spawns;
                document.getElementById('metric-ptrace').textContent = data.blocked_ptrace_attempts;
                document.getElementById('metric-ocsf').textContent = data.ocsf_submitted;

                const toggleAlert = (id, currentVal) => {
                    const card = document.getElementById(id);
                    if (currentVal > 0) card.classList.add('alert-active');
                    else card.classList.remove('alert-active');
                };

                toggleAlert('card-network', data.blocked_network_breaches);
                toggleAlert('card-file', data.blocked_file_bypasses);
                toggleAlert('card-dlp', data.dlp_redactions);
                toggleAlert('card-shell', data.blocked_shell_spawns);
                toggleAlert('card-ptrace', data.blocked_ptrace_attempts);

                if (data.blocked_network_breaches > lastMetrics.blocked_network_breaches) {
                    addLog('🚨 KERNEL ALERT: Egress network breach attempt detected! Process terminated instantly via SIGKILL (9). Zero bytes leaked.', 'alert');
                }
                if (data.blocked_file_bypasses > lastMetrics.blocked_file_bypasses) {
                    addLog('🚨 KERNEL ALERT: Sandbox file boundary intrusion attempt blocked! Target thread killed via SIGKILL (9).', 'alert');
                }
                if (data.dlp_redactions > lastMetrics.dlp_redactions) {
                    addLog('🛡️ DLP ALERT: Sensitive data (CC/PII) redacted from egress payload before transmission.', 'warning');
                }
                if (data.blocked_shell_spawns > lastMetrics.blocked_shell_spawns) {
                    addLog('🚨 KERNEL eBPF: Anti-Tamper blocked an unauthorized /bin/sh shell spawn! Triggering Kill-Switch.', 'alert');
                }
                if (data.blocked_ptrace_attempts > lastMetrics.blocked_ptrace_attempts) {
                    addLog('🚨 KERNEL eBPF: Debugger attachment (PTRACE) attempt blocked! Threat neutralized.', 'alert');
                }
                if (data.verified_signatures > lastMetrics.verified_signatures) {
                    addLog('🛡️ Signature verified. Validating cryptographic credentials for new sandbox.', 'success');
                }

                lastMetrics = data;
            } catch (err) {
                console.error("Telemetry update error:", err);
            }
        }

        setInterval(updateTelemetry, 1000);
        updateTelemetry();

        runBtn.addEventListener('click', async () => {
            const script = scriptEditor.value;
            runBtn.disabled = true;
            executionStatus.textContent = "Deploying...";
            executionStatus.style.color = "#fcd34d";
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
                    executionStatus.style.color = "#f87171";
                    consoleOut.className = "console-output error";
                    consoleOut.textContent = result.message || "Failed to execute sandbox script.";
                    addLog('❌ Sandbox launch failed: ' + (result.message || 'Error'), 'info');
                    return;
                }

                const output = result.output;
                executionStatus.textContent = "Completed";
                executionStatus.style.color = "#34d399";
                
                let outText = "";
                if (output.stdout) outText += output.stdout;
                if (output.stderr) outText += output.stderr;

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
                executionStatus.style.color = "#f87171";
                consoleOut.className = "console-output error";
                consoleOut.textContent = "Failed to dispatch request: " + err;
            }
        });
    </script>
</body>
</html>
`
