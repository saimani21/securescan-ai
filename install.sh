#!/bin/bash

# ╔════════════════════════════════════════════════════════════╗
# ║  SecureScan AI - Installation Script                      ║
# ║  GitHub: https://github.com/saimani21/securescan-ai        ║
# ╚════════════════════════════════════════════════════════════╝

set -e

echo "╔════════════════════════════════════════════════════════════╗"
echo "║         Installing SecureScan AI v0.1.0                    ║"
echo "║  AI-powered security scanner with CVE intelligence         ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Check Python
echo "1️⃣  Checking prerequisites..."
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 not found!"
    exit 1
fi
echo "✅ Python $(python3 --version)"

# Install pipx
echo ""
echo "2️⃣  Installing pipx..."
if ! command -v pipx &> /dev/null; then
    if command -v apt &> /dev/null; then
        sudo apt update -qq
        sudo apt install -y pipx
    else
        python3 -m pip install --user pipx
    fi
    pipx ensurepath
    export PATH="$HOME/.local/bin:$PATH"
fi
echo "✅ pipx installed"

# Install Semgrep
echo ""
echo "3️⃣  Installing Semgrep..."
if ! command -v semgrep &> /dev/null; then
    pipx install semgrep
    echo "✅ Semgrep installed"
else
    echo "✅ Semgrep already installed"
fi

# Install SecureScan AI
echo ""
echo "4️⃣  Installing SecureScan AI..."
pipx uninstall securescan-ai 2>/dev/null || true
pipx install git+https://github.com/saimani21/securescan-ai.git
echo "✅ SecureScan AI installed"

# Update PATH
export PATH="$HOME/.local/bin:$PATH"

# Run setup wizard
echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║  ✅ Installation Complete!                                 ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "5️⃣  Starting setup wizard..."
echo ""

# Check if running interactively
if [ -t 0 ]; then
    secscan setup
else
    echo "⚠️  Non-interactive mode detected"
    echo "   Run 'secscan setup' manually to configure API keys"
fi

echo ""
echo "🎉 Setup complete! Run 'secscan --help' to get started"
