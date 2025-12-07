#!/bin/bash

echo "🔍 Verifying GitHub Action setup..."

# Check action.yml exists
if [ -f ".github/actions/securescan/action.yml" ]; then
    echo "✅ action.yml exists"
else
    echo "❌ action.yml missing"
    exit 1
fi

# Check workflows exist
if [ -f ".github/workflows/security-scan-basic.yml" ]; then
    echo "✅ Basic workflow exists"
else
    echo "❌ Basic workflow missing"
fi

if [ -f ".github/workflows/security-scan-full.yml" ]; then
    echo "✅ Full workflow exists"
else
    echo "❌ Full workflow missing"
fi

# Check documentation
if [ -f "docs/github-action.md" ]; then
    echo "✅ Documentation exists"
else
    echo "❌ Documentation missing"
fi

# Validate action.yml syntax
echo "Validating action.yml syntax..."
if python3 -c "import yaml; yaml.safe_load(open('.github/actions/securescan/action.yml'))" 2>/dev/null; then
    echo "✅ action.yml is valid YAML"
else
    echo "❌ action.yml has syntax errors"
    exit 1
fi

echo ""
echo "✅ All checks passed!"
echo ""
echo "Next steps:"
echo "1. Set secrets: OPENAI_API_KEY, NVD_API_KEY"
echo "2. Push changes: git push"
echo "3. Test action: Create a PR"
echo "4. Check Security tab for SARIF upload"
