#!/bin/bash

set -e

echo "================================================="
echo "   🚀 Starting NexisCore Enterprise Gateway 🚀"
echo "================================================="

# Change to the project directory just in case
cd "$(dirname "$0")"

echo "1. Generating PKI Keys and Compiling eBPF Probes..."
make generate-pki
make build-ebpf
make build-antitamper-ebpf

echo "2. Compiling the Go server binary..."
./local_go/go/bin/go build -o nexiscore_bin main.go dashboard.go

echo "3. Stopping any existing NexisCore instances..."
pkill -f nexiscore_bin || true
sleep 1

echo "4. Starting the server in the background..."
nohup ./nexiscore_bin > nexiscore_server.log 2>&1 &
SERVER_PID=$!

echo "   Server started with PID: $SERVER_PID"
echo "   Waiting for server to initialize and bind to port 9090..."

# Wait until the server is listening on port 9090 (max 10 seconds)
timeout 10 bash -c 'until ss -tlnp | grep -q 9090; do sleep 1; done' || true

if ss -tlnp | grep -q 9090; then
    echo "✅ Server is up and running!"
    echo "5. Opening Dashboard in your default web browser..."
    
    # Try different methods to open the browser
    if command -v xdg-open > /dev/null; then
        xdg-open http://127.0.0.1:9090/ > /dev/null 2>&1 &
    elif command -v python3 > /dev/null; then
        python3 -m webbrowser http://127.0.0.1:9090/ > /dev/null 2>&1 &
    else
        echo "⚠️ Could not auto-open browser. Please manually navigate to http://127.0.0.1:9090/"
    fi
    
    echo "================================================="
    echo "🌐 Dashboard URL: http://127.0.0.1:9090/"
    echo "📜 To view live logs: tail -f nexiscore_server.log"
    echo "🛑 To stop the server: kill $SERVER_PID"
    echo "================================================="
else
    echo "❌ Server failed to start or bind to port 9090 within 10 seconds."
    echo "Check the logs for details:"
    tail -n 20 nexiscore_server.log
    exit 1
fi
