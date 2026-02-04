# SolGuard

AI-powered smart contract auditor for Solana. Scan your Anchor/Solana programs for 130+ vulnerability patterns.

## Quick Start

### CLI (npx)

```bash
# Scan your project
npx solguard scan ./my-program

# Quick check (exit code 1 if critical issues)
npx solguard check ./my-program

# Full audit with AI explanations
npx solguard audit ./my-program

# Watch mode
npx solguard watch ./my-program
```

### SDK (Programmatic)

```bash
npm install solguard
```

```typescript
import { scan, check } from 'solguard';

// Full scan with results
const results = await scan('./programs/my-vault');
console.log(`Found ${results.summary.total} issues`);
console.log(`Critical: ${results.summary.critical}`);
console.log(`High: ${results.summary.high}`);

// Quick pass/fail check
if (!await check('./my-program')) {
  console.error('Security check failed!');
  process.exit(1);
}

// With options
const results = await scan('./my-program', {
  failOn: 'high',  // 'critical' | 'high' | 'medium' | 'low' | 'any'
});
```

### Pre-commit Hook

```bash
# .husky/pre-commit
npx solguard check ./programs --fail-on critical
```

### GitHub Actions

```yaml
- name: Security Audit
  run: npx solguard ci ./programs --fail-on high --sarif results.sarif
  
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: results.sarif
```

## Commands

| Command | Description |
|---------|-------------|
| `scan <path>` | Quick vulnerability scan |
| `audit <path>` | Full audit with AI explanations |
| `check <path>` | Pass/fail check for CI |
| `watch <path>` | Watch mode for development |
| `github <repo>` | Audit from GitHub URL |
| `fetch <program-id>` | Audit on-chain program |
| `list` | Show all 130+ vulnerability patterns |
| `learn <pattern>` | Learn about specific vulnerabilities |

## Vulnerability Patterns

SolGuard checks for 130+ patterns including:

- **Critical:** Missing signer checks, authority bypass, flash loan exploits
- **High:** Integer overflow, CPI without verification, reentrancy
- **Medium:** Precision loss, stale data, fee manipulation
- **Low:** Missing events, Token-2022 compatibility

Run `solguard list` to see all patterns.

## Links

- [Documentation](https://github.com/oh-ashen-one/solguard)
- [Patterns Reference](https://github.com/oh-ashen-one/solguard/blob/main/PATTERNS.md)
- [Examples](https://github.com/oh-ashen-one/solguard/tree/main/examples)

## License

MIT
