# SecureScan AI - Installation & Usage Guide

## 🚀 Quick Install (One Command)

curl -fsSL https://raw.githubusercontent.com/saimani21/securescan-ai/main/install.sh | bash

text

Or download and run:

wget https://raw.githubusercontent.com/saimani21/securescan-ai/main/install.sh
chmod +x install.sh
./install.sh

text

## 📦 Manual Installation

### Prerequisites

- Python 3.11+ recommended
- Linux, macOS, or WSL2

### Step-by-Step

1. Install pipx
sudo apt install pipx # Ubuntu/Debian

or: brew install pipx # macOS
pipx ensurepath
source ~/.bashrc

2. Install Semgrep
pipx install semgrep

3. Install SecureScan AI
pipx install git+https://github.com/saimani21/securescan-ai.git

4. Verify
secscan --version

text

## 🎯 Usage

### Basic Scan (Free, No API keys)

secscan scan /path/to/your/code

text

**What it does:**
- SAST scanning with 2000+ rules
- Secrets detection
- Takes ~10-30 seconds
- Completely free

### With AI Validation

export OPENAI_API_KEY="sk-proj-..."
secscan scan /path/to/code --llm openai --severity HIGH --severity CRITICAL

text

**What it adds:**
- AI-powered false positive filtering (40-60% reduction)
- 86% average confidence scores
- Detailed reasoning for each finding
- Cost: ~$0.10-0.20 per scan

### Full Pipeline (AI + CVE)

export OPENAI_API_KEY="sk-proj-..."
export NVD_API_KEY="your-key" # Optional but recommended
secscan scan /path/to/code --llm openai --enrich-cve --severity HIGH --severity CRITICAL

text

**What it adds:**
- CVE threat intelligence (200K+ CVEs)
- CISA KEV database integration
- Exploit availability checking
- Multi-factor risk scoring
- Cost: ~$0.10-0.20 per scan

## 🔑 Getting API Keys

### OpenAI (Required for AI features)

1. Visit: https://platform.openai.com/api-keys
2. Sign up and add payment method ($5 minimum)
3. Create API key
4. Cost: ~$0.003 per finding (~$0.10-0.20 per scan)

### NVD (Optional but recommended)

1. Visit: https://nvd.nist.gov/developers/request-an-api-key
2. Submit request with your email
3. Check email for API key (usually instant)
4. **Free**, increases rate limit from 5 to 50 requests/30s

## 📖 Command Reference

### Basic Commands

Show version
secscan --version

Show help
secscan --help
secscan scan --help

Scan current directory
secscan scan .

Scan specific file
secscan scan app.py

Scan specific directory
secscan scan ./src

text

### Severity Filtering

Only CRITICAL
secscan scan . --severity CRITICAL

HIGH and CRITICAL
secscan scan . --severity HIGH --severity CRITICAL

All severities (default)
secscan scan .

text

### Output Formats

SARIF (for GitHub Security tab)
secscan scan . --output sarif --output-file results.sarif

JSON (for automation)
secscan scan . --output json --output-file results.json

Console only (default, with colors)
secscan scan .

text

### Advanced Options

Fail on HIGH or higher (for CI/CD)
secscan scan . --fail-on HIGH

Set LLM confidence threshold
secscan scan . --llm openai --llm-confidence 0.8

Limit CVEs per finding
secscan scan . --enrich-cve --cve-max 5

Verbose output
secscan scan . --verbose

text

## 🔧 Troubleshooting

### Command not found

Fix PATH
pipx ensurepath
source ~/.bashrc

Or restart terminal
text

### Semgrep not found

Install semgrep
pipx install semgrep

Verify
which semgrep
semgrep --version

text

### OpenAI API errors

Check key is set
echo $OPENAI_API_KEY

Set temporarily
export OPENAI_API_KEY="sk-proj-..."

Set permanently
echo 'export OPENAI_API_KEY="sk-proj-..."' >> ~/.bashrc
source ~/.bashrc

text

### Permission denied

Make sure you have permissions
chmod +r /path/to/code

Or run from owned directory
text

## 💡 Examples

### Example 1: Scan GitHub Repository

git clone https://github.com/user/vulnerable-repo
cd vulnerable-repo
secscan scan . --llm openai --severity HIGH --severity CRITICAL

text

### Example 2: Pre-commit Check

Before committing
secscan scan . --severity HIGH --severity CRITICAL --fail-on HIGH

If exit code 0 or 1, safe to commit
if [ $? -le 1 ]; then
git commit -m "Security checked"
fi

text

### Example 3: CI/CD Integration

See: https://github.com/saimani21/securescan-ai/blob/main/docs/github-action-documentation.md

### Example 4: Weekly Audit

#!/bin/bash

weekly-audit.sh
export OPENAI_API_KEY="sk-proj-..."
export NVD_API_KEY="your-key"

secscan scan /path/to/codebase
--llm openai
--enrich-cve
--output json
--output-file "audit-$(date +%Y%m%d).json"

text

## 📊 Understanding Results

### Exit Codes

- `0` - No issues or only LOW/MEDIUM
- `1` - HIGH severity found
- `2` - CRITICAL severity found
- `3` - Scan failed (error)

### Output Example

╭───────────────────────────────╮
│ SecureScan AI v0.1.0 │
│ Target: ./src │
╰───────────────────────────────╯

🔍 Severity filter: HIGH, CRITICAL
🤖 LLM validation: openai/gpt-4o
📋 CVE enrichment: Enabled

SCAN SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Duration: 49.63s
Files Scanned: 2
Total Findings: 17

Findings by Severity
┏━━━━━━━━━━┳━━━━━━━┓
┃ Severity ┃ Count ┃
┡━━━━━━━━━━╇━━━━━━━┩
│ CRITICAL │ 3 │
│ HIGH │ 14 │
└──────────┴───────┘

TOP FINDINGS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

CRITICAL AWS Access Key Exposed
File: app.py:26
CWE: CWE-798

CRITICAL SQL Injection
File: app.py:45
CWE: CWE-89

text

## 🆘 Support

- **GitHub:** https://github.com/saimani21/securescan-ai
- **Issues:** https://github.com/saimani21/securescan-ai/issues
- **Email:** psmk212004@gmail.com

## 📄 License

MIT License - See [LICENSE](LICENSE) file

## 🙏 Credits

- [Semgrep](https://semgrep.dev/) - SAST engine
- [OpenAI](https://openai.com/) - GPT-4 API
- [NIST NVD](https://nvd.nist.gov/) - CVE database
- [CISA](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) - KEV database

---

**Built with ❤️ by [Sai Mani](https://github.com/saimani21)**
