#!/bin/bash
# Start the Document Fraud Detector with Anthropic API key

# Extract API key from OpenClaw config
export ANTHROPIC_API_KEY=$(grep -o 'sk-ant[^"]*' ~/.openclaw/agents/main/agent/auth-profiles.json | head -1)

if [ -z "$ANTHROPIC_API_KEY" ]; then
    echo "⚠️  Warning: Could not find Anthropic API key. AI analysis will be disabled."
else
    echo "✓ Anthropic API key loaded"
fi

cd "$(dirname "$0")"

# Kill any existing instance
pkill -f "streamlit run app.py" 2>/dev/null

# Start streamlit
echo "Starting Document Fraud Detector..."
/Users/mattvisser/Library/Python/3.9/bin/streamlit run app.py \
    --server.headless true \
    --server.port 8503 \
    --server.address 0.0.0.0

