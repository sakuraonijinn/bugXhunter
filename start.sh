#!/usr/bin/env bash
# Quick deployment script for BugXhunter
# Usage: curl -sL https://raw.githubusercontent.com/your-repo/bugxhunter/main/start.sh | bash
set -e

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$NAME
else
    OS=$(uname -s)
fi

echo "Detected OS: $OS"

# Install Python and dependencies
if [[ "$OS" == *"Ubuntu"* ]] || [[ "$OS" == *"Debian"* ]]; then
    echo "Installing Python and dependencies..."
    sudo apt-get update -qq
    sudo apt-get install -y -qq python3 python3-pip curl > /dev/null
    pip3 install uvicorn starlette aiohttp
elif [[ "$OS" == *"Alpine"* ]]; then
    echo "Installing Python and dependencies..."
    apk add --no-cache python3 py3-pip curl
    pip3 install uvicorn starlette aiohttp
fi

# Create config
echo "Creating configuration..."
cat > config.json << CONFIG
{
  "auth_token": "${AUTH_TOKEN:-changeme}",
  "frida": {
    "host": "127.0.0.1",
    "port": 27042,
    "remotes": []
  },
  "xhunter": {
    "listen_port": 9090,
    "gateway_ports": true
  }
}
CONFIG

# Start server
echo "Starting BugXhunter server on port 7080..."
echo "Auth token: ${AUTH_TOKEN:-changeme}"
echo "Configure BugDeck with: http://\$YOUR_IP:7080"
AUTH_TOKEN="${AUTH_TOKEN:-changeme}" python3 -m uvicorn bugxhunter_server:app --host 0.0.0.0 --port 7080
