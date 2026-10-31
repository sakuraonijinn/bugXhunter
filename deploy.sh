#!/usr/bin/env bash
# Quick deploy bugXhunter to a free VPS
# Usage: ./deploy.sh [railway|render|docker|manual]

set -e

PLATFORM="${1:-manual}"
AUTH_TOKEN="${AUTH_TOKEN:-testtoken12345}"

echo "=== BugXhunter Deployment ==="
echo "Platform: $PLATFORM"
echo "Auth token: $AUTH_TOKEN"
echo ""

case $PLATFORM in
    railway)
        echo "Deploying to Railway..."
        if ! command -v railway &> /dev/null; then
            echo "Installing Railway CLI..."
            curl -fsSL https://railway.com/new.sh | sh
        fi
        railway login --browserless
        railway new bugxhunter
        railway add dockerfile --path bugxhunter/Dockerfile
        railway env set AUTH_TOKEN=$AUTH_TOKEN
        railway up
        echo ""
        echo "✅ Deployed! Check: https://railway.app"
        ;;
        
    render)
        echo "Deploying to Render..."
        echo "1. Go to https://render.com"
        echo "2. Click 'New Web Service'"
        echo "3. Connect your GitHub repo"
        echo "4. Set:"
        echo "   - Dockerfile path: bugxhunter/Dockerfile"
        echo "   - Port: 7080"
        echo "5. Deploy!"
        echo ""
        echo "Or use the Render CLI:"
        echo "curl -fsSL https://render.com/docs/deploy-php-github | sh"
        ;;
        
    docker)
        echo "Building Docker image..."
        cd "$(dirname "$0")"
        docker build -t bugxhunter -f Dockerfile .
        echo ""
        echo "✅ Docker image built!"
        echo "Run with:"
        echo "  docker run -p 7080:7080 -e AUTH_TOKEN=$AUTH_TOKEN bugxhunter"
        ;;
        
    manual)
        echo "=== Manual Deployment ==="
        echo ""
        echo "1. Install dependencies:"
        echo "   pip3 install uvicorn starlette aiohttp"
        echo ""
        echo "2. Copy files to your server:"
        echo "   scp -r bugxhunter/ user@your-server:/opt/bugxhunter/"
        echo ""
        echo "3. Update config.json with your server details"
        echo ""
        echo "4. Start the server:"
        echo "   cd /opt/bugxhunter/"
        echo "   AUTH_TOKEN=$AUTH_TOKEN python3 -m uvicorn bugxhunter_server:app --host 0.0.0.0 --port 7080"
        echo ""
        echo "5. Configure BugDeck:"
        echo "   Server URL: http://your-server-ip:7080"
        echo "   Auth token: $AUTH_TOKEN"
        ;;
        
    *)
        echo "Usage: $0 [railway|render|docker|manual]"
        exit 1
        ;;
esac

echo ""
echo "=== After Deployment ==="
echo "Test the server:"
echo "  curl -H 'X-Auth-Token: $AUTH_TOKEN' http://your-server:7080/status"
echo ""
echo "Configure BugDeck Android app:"
echo "  Server URL: http://your-server:7080"
echo "  Auth token: $AUTH_TOKEN"
