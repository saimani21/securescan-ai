# SecureScan AI - GitHub Action Documentation

## Table of Contents
- [Quick Start](#quick-start)
- [Features](#features)
- [Usage Examples](#usage-examples)
- [Inputs](#inputs)
- [Outputs](#outputs)
- [API Keys Setup](#api-keys-setup)
- [Cost Estimation](#cost-estimation)
- [Troubleshooting](#troubleshooting)

## Quick Start

Add to `.github/workflows/security.yml`:

```yaml
name: Security Scan
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
  pull-requests: write
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: your-org/securescan-ai@v1
        with:
          openai-api-key: ${{ secrets.OPENAI_API_KEY }}
```

## Features

- ✅ SAST Scanning (Semgrep 2000+ rules)
- ✅ Secrets Detection
- ✅ AI Validation (GPT-4 reduces false positives 40-60%)
- ✅ CVE Enrichment (NVD + CISA KEV)
- ✅ SARIF Upload (GitHub Security tab)
- ✅ PR Comments (Automated review)

## Usage Examples

### Example 1: Basic Scan (Free)
```yaml
name: Basic Scan
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: your-org/securescan-ai@v1
        with:
          target: './src'
          enable-llm: 'false'
          enable-cve: 'false'
          fail-on: 'CRITICAL'
```

### Example 2: Full Pipeline (AI + CVE)
```yaml
name: Full Security Scan
on:
  push:
    branches: [ main ]
  pull_request:
  schedule:
    - cron: '0 0 * * 0'
permissions:
  contents: read
  security-events: write
  pull-requests: write
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: your-org/securescan-ai@v1
        with:
          target: '.'
          severity: 'HIGH,CRITICAL'
          fail-on: 'HIGH'
          enable-llm: 'true'
          llm-model: 'gpt-4o'
          openai-api-key: ${{ secrets.OPENAI_API_KEY }}
          enable-cve: 'true'
          nvd-api-key: ${{ secrets.NVD_API_KEY }}
          output-format: 'both'
          upload-sarif: 'true'
          comment-on-pr: 'true'
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: security-results
          path: securescan-results.*
```

### Example 3: PR-Only Scan
```yaml
name: PR Security Review
on:
  pull_request:
    types: [opened, synchronize, reopened]
permissions:
  contents: read
  security-events: write
  pull-requests: write
jobs:
  pr-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: your-org/securescan-ai@v1
        with:
          severity: 'MEDIUM,HIGH,CRITICAL'
          fail-on: 'NONE'
          enable-llm: 'true'
          openai-api-key: ${{ secrets.OPENAI_API_KEY }}
          comment-on-pr: 'true'
```

### Example 4: Multi-Directory Scan
```yaml
jobs:
  scan-backend:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: your-org/securescan-ai@v1
        with:
          target: './backend'
          openai-api-key: ${{ secrets.OPENAI_API_KEY }}
  scan-frontend:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: your-org/securescan-ai@v1
        with:
          target: './frontend'
          openai-api-key: ${{ secrets.OPENAI_API_KEY }}
```

### Example 5: Strict Security
```yaml
- uses: your-org/securescan-ai@v1
  with:
    severity: 'LOW,MEDIUM,HIGH,CRITICAL'
    fail-on: 'MEDIUM'
    llm-confidence: '0.85'
    openai-api-key: ${{ secrets.OPENAI_API_KEY }}
```

### Example 6: Weekly Audit
```yaml
name: Weekly Security Audit
on:
  schedule:
    - cron: '0 2 * * 1'
permissions:
  contents: read
  security-events: write
  issues: write
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - id: scan
        uses: your-org/securescan-ai@v1
        with:
          severity: 'LOW,MEDIUM,HIGH,CRITICAL'
          enable-llm: 'true'
          openai-api-key: ${{ secrets.OPENAI_API_KEY }}
          enable-cve: 'true'
          fail-on: 'NONE'
      - if: steps.scan.outputs.critical-count > 0
        uses: actions/github-script@v7
        with:
          script: |
            github.rest.issues.create({
              owner: context.repo.owner,
              repo: context.repo.repo,
              title: '🚨 Security Alert: ${{ steps.scan.outputs.critical-count }} CRITICAL',
              body: 'Security scan found vulnerabilities. Check Security tab.',
              labels: ['security']
            });
```

## Inputs

### Scan Configuration
| Input | Description | Default |
|-------|-------------|---------|
| `target` | Directory/file to scan | `.` |
| `severity` | Severities (LOW,MEDIUM,HIGH,CRITICAL) | `HIGH,CRITICAL` |
| `fail-on` | Fail if severity found | `HIGH` |
| `max-findings` | Max findings to display | `50` |

### LLM Configuration
| Input | Description | Default |
|-------|-------------|---------|
| `enable-llm` | Enable AI validation | `true` |
| `llm-provider` | Provider (openai/ollama) | `openai` |
| `llm-model` | Model (gpt-4o/gpt-4/gpt-3.5-turbo) | `gpt-4o` |
| `llm-confidence` | Min confidence (0.0-1.0) | `0.7` |
| `openai-api-key` | OpenAI API key | - |

### CVE Configuration
| Input | Description | Default |
|-------|-------------|---------|
| `enable-cve` | Enable CVE enrichment | `true` |
| `nvd-api-key` | NVD API key (optional) | - |
| `cve-max-per-finding` | Max CVEs per finding | `10` |

### Output Configuration
| Input | Description | Default |
|-------|-------------|---------|
| `output-format` | Format (json/sarif/both) | `sarif` |
| `sarif-file` | SARIF output path | `securescan-results.sarif` |
| `json-file` | JSON output path | `securescan-results.json` |
| `upload-sarif` | Upload to Security tab | `true` |
| `comment-on-pr` | Post PR comment | `true` |
| `github-token` | GitHub token | `${{ github.token }}` |

## Outputs

| Output | Description |
|--------|-------------|
| `findings-count` | Total findings |
| `critical-count` | Critical findings |
| `high-count` | High findings |
| `medium-count` | Medium findings |
| `low-count` | Low findings |
| `sarif-file` | SARIF file path |
| `json-file` | JSON file path |
| `scan-duration` | Duration in seconds |
| `llm-cost` | AI cost in USD |

### Using Outputs
```yaml
- id: scan
  uses: your-org/securescan-ai@v1
  with:
    openai-api-key: ${{ secrets.OPENAI_API_KEY }}
- run: |
    echo "Findings: ${{ steps.scan.outputs.findings-count }}"
    echo "Critical: ${{ steps.scan.outputs.critical-count }}"
    echo "Duration: ${{ steps.scan.outputs.scan-duration }}s"
    echo "Cost: \$${{ steps.scan.outputs.llm-cost }}"
- if: steps.scan.outputs.critical-count > 5
  run: echo "Too many critical issues!" && exit 1
```

## API Keys Setup

### OpenAI API Key (Required for AI)

1. Get key: https://platform.openai.com/api-keys
2. Add to GitHub: Settings → Secrets → Actions → New secret
3. Name: `OPENAI_API_KEY`
4. Value: `sk-proj-your-key-here`

### NVD API Key (Optional, Recommended)

1. Get key: https://nvd.nist.gov/developers/request-an-api-key
2. Add to GitHub: Settings → Secrets → Actions → New secret
3. Name: `NVD_API_KEY`
4. Value: Your NVD key

**Benefits:**
- Without key: 5 requests/30s
- With key: 50 requests/30s (10x faster)

### GitHub Token (Automatic)

Already available as `${{ secrets.GITHUB_TOKEN }}` - no setup needed.

## Permissions

Required in workflow:

```yaml
permissions:
  contents: read          # Read code
  security-events: write  # Upload SARIF
  pull-requests: write    # Post comments
```

## Cost Estimation

### SAST Scanning
- **Cost:** $0 (Free)
- **Duration:** 20-30s

### AI Validation
- **Provider:** OpenAI GPT-4o
- **Cost per finding:** ~$0.003
- **Cost per scan (30 findings):** ~$0.10
- **Monthly (100 scans):** ~$10

### CVE Enrichment
- **Cost:** $0 (Free NVD API)
- **Duration:** <1s (cached)

### Total Monthly Cost Examples

| Usage | Scans/Month | Cost |
|-------|-------------|------|
| Small project | 50 | $5 |
| Medium project | 200 | $20 |
| Large project | 500 | $50 |
| Enterprise (10 repos) | 2000 | $200 |

**Savings vs Commercial Tools:** $500-5000/year

## Advanced Configuration

### Custom Severity Thresholds
```yaml
with:
  severity: 'CRITICAL'              # Only critical
  severity: 'HIGH,CRITICAL'         # High + Critical
  severity: 'MEDIUM,HIGH,CRITICAL'  # Medium and above
  severity: 'LOW,MEDIUM,HIGH,CRITICAL'  # All severities
```

### Custom Fail Conditions
```yaml
with:
  fail-on: 'NONE'      # Never fail
  fail-on: 'CRITICAL'  # Fail only on critical
  fail-on: 'HIGH'      # Fail on high or critical
  fail-on: 'MEDIUM'    # Fail on medium or above
```

### LLM Model Selection
```yaml
with:
  llm-model: 'gpt-4o'           # Best accuracy (recommended)
  llm-model: 'gpt-4'            # High accuracy, slower
  llm-model: 'gpt-3.5-turbo'    # Fast, cheaper
```

### Confidence Tuning
```yaml
with:
  llm-confidence: '0.6'   # More findings (some FP)
  llm-confidence: '0.7'   # Balanced (default)
  llm-confidence: '0.8'   # High confidence
  llm-confidence: '0.9'   # Very strict
```

### Output Format Options
```yaml
with:
  output-format: 'sarif'  # GitHub Security tab
  output-format: 'json'   # Machine-readable
  output-format: 'both'   # Both formats
```

### Disable Features
```yaml
with:
  enable-llm: 'false'     # No AI (faster, free)
  enable-cve: 'false'     # No CVE enrichment
  upload-sarif: 'false'   # No Security tab upload
  comment-on-pr: 'false'  # No PR comments
```

## Troubleshooting

### Issue: "OpenAI API key not found"
**Solution:**
```yaml
# Add to workflow
with:
  openai-api-key: ${{ secrets.OPENAI_API_KEY }}

# Add secret: Settings → Secrets → Actions → OPENAI_API_KEY
```

### Issue: "Permission denied"
**Solution:**
```yaml
# Add permissions to workflow
permissions:
  contents: read
  security-events: write
  pull-requests: write
```

### Issue: "Scan too slow"
**Options:**
```yaml
# Option 1: Disable AI
with:
  enable-llm: 'false'

# Option 2: Use faster model
with:
  llm-model: 'gpt-3.5-turbo'

# Option 3: Scan specific directory
with:
  target: './src'

# Option 4: Reduce severity
with:
  severity: 'CRITICAL'
```

### Issue: "Too many findings"
**Solution:**
```yaml
# Filter by severity
with:
  severity: 'HIGH,CRITICAL'

# Increase AI confidence
with:
  llm-confidence: '0.85'

# Limit output
with:
  max-findings: 20
```

### Issue: "CVE enrichment timeout"
**Solution:**
```yaml
# Add NVD API key for higher rate limits
with:
  nvd-api-key: ${{ secrets.NVD_API_KEY }}

# Or disable CVE
with:
  enable-cve: 'false'
```

### Issue: "Action fails but no vulnerabilities"
**Solution:**
```yaml
# Check fail-on setting
with:
  fail-on: 'CRITICAL'  # Only fail on critical

# Or never fail (just report)
with:
  fail-on: 'NONE'
```

### Issue: "Out of OpenAI credits"
**Solution:**
1. Add credits: https://platform.openai.com/account/billing
2. Or use free mode:
```yaml
with:
  enable-llm: 'false'
```

### Debug Mode
```yaml
- uses: your-org/securescan-ai@v1
  env:
    ACTIONS_STEP_DEBUG: true
  with:
    openai-api-key: ${{ secrets.OPENAI_API_KEY }}
```

## Performance Tips

### Fast Scans (<30s)
```yaml
with:
  target: './src'
  enable-llm: 'false'
  enable-cve: 'false'
  severity: 'CRITICAL'
```

### Balanced Scans (~60s)
```yaml
with:
  enable-llm: 'true'
  llm-model: 'gpt-3.5-turbo'
  enable-cve: 'true'
  severity: 'HIGH,CRITICAL'
```

### Comprehensive Scans (~90s)
```yaml
with:
  enable-llm: 'true'
  llm-model: 'gpt-4o'
  enable-cve: 'true'
  severity: 'MEDIUM,HIGH,CRITICAL'
```

## Support

- Documentation: https://github.com/your-org/securescan-ai
- Issues: https://github.com/your-org/securescan-ai/issues
- Examples: https://github.com/your-org/securescan-ai/tree/main/examples

## License

MIT License - See [LICENSE](../LICENSE) for details
