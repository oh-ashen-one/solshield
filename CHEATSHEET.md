# 📋 SolShield CLI Cheatsheet

Quick reference for all commands and options.

---

## Installation

```bash
# From source (npm package coming soon)
git clone https://github.com/oh-ashen-one/solshield.git
cd solshield/packages/cli
npm install && npm run build && npm link
```

---

## Commands

### `audit` — Analyze code for vulnerabilities

```bash
# Basic usage
solshield audit ./path/to/program

# Current directory
solshield audit .

# Multiple paths
solshield audit ./program1 ./program2

# Options
solshield audit . --verbose          # Detailed output
solshield audit . --format json      # JSON output
solshield audit . --format markdown  # Markdown report
solshield audit . --min-severity high # Only high+ findings
solshield audit . --patterns SOL001,SOL002  # Specific patterns
solshield audit . --exclude SOL028   # Skip patterns
```

### `github` — Audit from GitHub

```bash
# Audit a repo
solshield github owner/repo

# Specific branch
solshield github owner/repo --branch develop

# Specific PR
solshield github owner/repo --pr 123

# Subdirectory
solshield github owner/repo --path programs/my-program
```

### `fetch` — Audit on-chain programs

```bash
# Mainnet
solshield fetch <PROGRAM_ID>

# Devnet
solshield fetch <PROGRAM_ID> --rpc https://api.devnet.solana.com

# Custom RPC
solshield fetch <PROGRAM_ID> --rpc https://my-rpc.com
```

### `watch` — Continuous monitoring

```bash
# Watch directory
solshield watch ./program

# Watch with options
solshield watch . --min-severity critical
```

### `ci` — CI/CD mode

```bash
# Fail on critical
solshield ci . --fail-on critical

# Fail on high or above
solshield ci . --fail-on high

# Generate SARIF for GitHub
solshield ci . --sarif results.sarif

# Combined
solshield ci . --fail-on high --sarif results.sarif
```

### `list` — Show all patterns

```bash
# All patterns
solshield list

# Filter by severity
solshield list --severity critical
solshield list --severity high

# Filter by category
solshield list --category cpi
```

### `stats` — Show statistics

```bash
solshield stats
```

---

## Output Formats

| Format | Use Case |
|--------|----------|
| `--format terminal` | Human-readable (default) |
| `--format json` | Programmatic access |
| `--format markdown` | Documentation |
| `--sarif file.sarif` | GitHub Code Scanning |

---

## Severity Levels

| Level | Flag | Meaning |
|-------|------|---------|
| 🔴 Critical | `--min-severity critical` | Immediate exploit risk |
| 🟠 High | `--min-severity high` | Significant vulnerability |
| 🟡 Medium | `--min-severity medium` | Potential issue |
| 🔵 Low | `--min-severity low` | Best practice |

---

## Common Patterns

| ID | Name | Quick Check |
|----|------|-------------|
| SOL001 | Missing Owner | `owner = program::ID` |
| SOL002 | Missing Signer | `Signer<'info>` |
| SOL003 | Overflow | `checked_add/sub/mul` |
| SOL005 | Authority Bypass | `has_one = authority` |
| SOL012 | Arbitrary CPI | Hardcode program IDs |
| SOL018 | Oracle | Check staleness + TWAP |

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No issues (or below threshold) |
| 1 | Issues found above threshold |
| 2 | Error (parse failure, etc.) |

---

## Environment Variables

```bash
# Custom RPC
SOLANA_RPC_URL=https://my-rpc.com solshield fetch <ID>

# Verbose by default
SOLSHIELD_VERBOSE=1 solshield audit .
```

---

## Examples

```bash
# Quick audit before commit
solshield audit . --min-severity high

# Full audit with report
solshield audit . --format markdown > audit-report.md

# CI pipeline
solshield ci . --fail-on critical --sarif results.sarif

# Audit competitor's code
solshield github coral-xyz/anchor --path programs/
```

---

*Full docs: [README.md](README.md) | Patterns: [PATTERNS.md](PATTERNS.md)*
