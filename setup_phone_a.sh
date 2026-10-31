#!/bin/bash
# Phone A (Operator) setup
set -e
pip install -r requirements.txt 2>/dev/null || true
# Configure auth token
export AUTH_TOKEN="${AUTH_TOKEN:-change-me-real-token}"
# Start server
python3 -m bugxhunter.server --host 0.0.0.0 --port 7080
echo "Phone A server running on :7080"
echo "Reverse tunnel expected on :7081 (from Phone C)"
