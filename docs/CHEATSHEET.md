# SolGuard Cheat Sheet

## Quick Commands

```bash
# Audit local program
solguard audit ./my-program

# Audit from GitHub
solguard github coral-xyz/anchor
solguard github user/repo --pr 123

# Quick pass/fail check
solguard check . --fail-on high

# Watch mode
solguard watch ./program

# Generate HTML report
solguard report ./program -o audit.html

# CI mode with SARIF
solguard ci . --fail-on high --sarif results.sarif
```

## Output Formats

```bash
solguard audit . --output terminal  # Default
solguard audit . --output json
solguard audit . --output markdown
```

## Vulnerability Patterns

| ID | Name | Severity |
|----|------|----------|
| SOL001 | Missing Owner Check | Critical |
| SOL002 | Missing Signer Check | Critical |
| SOL003 | Integer Overflow | High |
| SOL004 | PDA Validation Gap | High |
| SOL005 | Authority Bypass | Critical |
| SOL006 | Missing Init Check | Critical |
| SOL007 | CPI Vulnerability | High |
| SOL008 | Rounding Error | Medium |
| SOL009 | Account Confusion | High |
| SOL010 | Account Closing | Critical |
| SOL011 | Reentrancy | High |
| SOL012 | Arbitrary CPI | Critical |
| SOL013 | Duplicate Mutable | High |
| SOL014 | Rent Exemption | Medium |
| SOL015 | Type Cosplay | Critical |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Pass / No critical issues |
| 1 | Fail / Issues found |
| 2 | Error (path not found, etc.) |

## Git Hooks

```bash
# Install pre-commit hook
cp examples/hooks/pre-commit .git/hooks/
chmod +x .git/hooks/pre-commit

# Install pre-push hook
cp examples/hooks/pre-push .git/hooks/
chmod +x .git/hooks/pre-push
```

## GitHub Actions

```yaml
- name: Install SolGuard
  run: npm install -g @solguard/cli

- name: Run Audit
  run: solguard ci . --fail-on high --sarif results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## API (Web)

```bash
# POST /api/v1/audit
curl -X POST https://solguard.io/api/v1/audit \
  -H "Content-Type: application/json" \
  -d '{"code": "use anchor_lang::prelude::*; ..."}'
```

## Links

- GitHub: https://github.com/oh-ashen-one/solguard
- Docs: https://solguard.io/docs
- Discord: Coming soon
