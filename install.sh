#!/bin/bash

# ╔════════════════════════════════════════════════════════════╗
# ║  SecureScan AI - Installation Script                      ║
# ║  GitHub: https://github.com/saimani21/securescan-ai        ║
# ╚════════════════════════════════════════════════════════════╝

set -e  # Exit on error

echo "╔════════════════════════════════════════════════════════════╗"
echo "║         Installing SecureScan AI v0.1.0                    ║"
echo "║  AI-powered security scanner with CVE intelligence         ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# STEP 1: Check Prerequisites
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

echo "1️⃣  Checking prerequisites..."
echo ""

# Check Python version
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 not found!"
    echo "   Install: sudo apt install python3 python3-pip"
    exit 1
fi

PYTHON_VERSION=$(python3 --version | awk '{print $2}')
echo "✅ Python version: $PYTHON_VERSION"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# STEP 2: Install pipx
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

echo ""
echo "2️⃣  Installing pipx..."
echo ""

if ! command -v pipx &> /dev/null; then
    echo "Installing pipx..."
    
    if command -v apt &> /dev/null; then
        sudo apt update -qq
        sudo apt install -y pipx
    elif command -v brew &> /dev/null; then
        brew install pipx
    else
        python3 -m pip install --user pipx
    fi
    
    pipx ensurepath
    export PATH="$HOME/.local/bin:$PATH"
    echo "✅ pipx installed"
else
    echo "✅ pipx already installed"
fi

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# STEP 3: Install Semgrep
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

echo ""
echo "3️⃣  Installing Semgrep..."
echo ""

if command -v semgrep &> /dev/null; then
    echo "✅ Semgrep already installed ($(semgrep --version))"
else
    pipx install semgrep
    echo "✅ Semgrep installed"
fi

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# STEP 4: Install SecureScan AI
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

echo ""
echo "4️⃣  Installing SecureScan AI..."
echo ""

pipx uninstall securescan-ai 2>/dev/null || true
pipx install git+https://github.com/saimani21/securescan-ai.git

echo "✅ SecureScan AI installed"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# STEP 5: Verify Installation
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

echo ""
echo "5️⃣  Verifying installation..."
echo ""

if command -v secscan &> /dev/null; then
    echo "✅ secscan command available"
    secscan --version
else
    echo "⚠️  Run: source ~/.bashrc"
fi

if command -v semgrep &> /dev/null; then
    echo "✅ semgrep command available ($(semgrep --version))"
fi

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║  ✅ ✅ ✅  INSTALLATION COMPLETE!  ✅ ✅ ✅               ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "📋 Quick Start:"
echo ""
echo "  # Basic scan (free)"
echo "  secscan scan /path/to/code"
echo ""
echo "  # With AI validation"
echo "  export OPENAI_API_KEY='sk-proj-...'"
echo "  secscan scan /path/to/code --llm openai --severity HIGH --severity CRITICAL"
echo ""
echo "📚 Full docs: https://github.com/saimani21/securescan-ai"
echo ""
