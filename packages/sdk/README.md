# SolShield SDK

AI-Powered Smart Contract Security Scanner for Solana.

[![npm version](https://img.shields.io/npm/v/solshield)](https://www.npmjs.com/package/solshield)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Installation

```bash
npm install solshield
```

## Quick Start

```typescript
import { scan, listPatterns } from 'solshield';

// Scan code for vulnerabilities
const result = await scan(`
  pub fn transfer(ctx: Context<Transfer>, amount: u64) -> Result<()> {
    let from = &ctx.accounts.from;
    let to = &ctx.accounts.to;
    
    // Vulnerable: no overflow check
    from.balance = from.balance - amount;
    to.balance = to.balance + amount;
    
    Ok(())
  }
`);

console.log(result.summary);
// { critical: 0, high: 1, medium: 0, low: 0, info: 0, total: 1 }

console.log(result.findings[0]);
// { id: 'SOL003', pattern: 'Integer Overflow', severity: 'high', ... }
```

## API

### `scan(code, options?)`

Scan Solana/Anchor code for vulnerabilities.

```typescript
const result = await scan(code, {
  patterns: ['SOL001', 'SOL002'], // Only run specific patterns
  minSeverity: 'high',           // Minimum severity to report
  includeInfo: false,            // Include info-level findings
});
```

**Returns:**

```typescript
interface ScanResult {
  timestamp: string;
  findings: Finding[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    total: number;
  };
  passed: boolean;      // True if no critical/high findings
  patternsUsed: number;
}
```

### `listPatterns()`

Get all available vulnerability patterns.

```typescript
const patterns = listPatterns();
console.log(patterns.length); // 150
```

### `getPattern(id)`

Get a specific pattern by ID.

```typescript
const pattern = getPattern('SOL001');
// { id: 'SOL001', name: 'Missing Owner Check', severity: 'critical', ... }
```

### `getPatternsBySeverity(severity)`

Get patterns filtered by severity.

```typescript
const critical = getPatternsBySeverity('critical');
console.log(critical.length); // 51
```

## Pattern Coverage

SolShield detects **150 vulnerability patterns** including:

| Category | Examples |
|----------|----------|
| **Access Control** | Missing owner/signer checks, authority bypass |
| **Arithmetic** | Integer overflow, rounding errors, precision loss |
| **Account Security** | Type cosplay, discriminator issues, PDA validation |
| **CPI Safety** | Arbitrary CPI, reentrancy, account injection |
| **DeFi-Specific** | Flash loans, oracle manipulation, sandwich attacks |
| **Token Security** | Mint authority, burn safety, freeze operations |

### Real-World Exploits Detected

- ✅ **Wormhole** ($326M) - Signature verification bypass
- ✅ **Cashio** ($52M) - Mint authority not checked
- ✅ **Mango Markets** ($114M) - Oracle manipulation
- ✅ **Slope** ($8M) - Private key exposure
- ✅ And 140+ more patterns...

## Use Cases

### CI/CD Integration

```typescript
import { scan } from 'solshield';
import { readFileSync } from 'fs';

const code = readFileSync('./programs/my_program/src/lib.rs', 'utf8');
const result = await scan(code);

if (!result.passed) {
  console.error('Security audit failed!');
  console.error(result.findings);
  process.exit(1);
}
```

### IDE Extension

```typescript
import { scan } from 'solshield';

async function onDocumentChange(code: string) {
  const { findings } = await scan(code, { minSeverity: 'medium' });
  
  // Show findings as diagnostics
  return findings.map(f => ({
    line: f.location.line,
    message: `[${f.id}] ${f.title}: ${f.description}`,
    severity: f.severity,
  }));
}
```

### Custom Pattern Selection

```typescript
// Only run critical patterns for fast scanning
const result = await scan(code, {
  patterns: listPatterns()
    .filter(p => p.severity === 'critical')
    .map(p => p.id)
});
```

## TypeScript Support

Full TypeScript support with exported types:

```typescript
import type { 
  Finding, 
  ScanResult, 
  Pattern, 
  Severity,
  ScanOptions 
} from 'solshield';
```

## Links

- **CLI:** `npm install -g @solshield/cli`
- **Web Demo:** https://solshieldai.netlify.app
- **GitHub:** https://github.com/oh-ashen-one/solshield
- **Docs:** https://github.com/oh-ashen-one/solshield#readme

## License

MIT © SolShield Team
