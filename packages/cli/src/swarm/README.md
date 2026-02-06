# SolGuard Multi-Agent Security Swarm

> 🔬 Parallel, specialized security auditing using Claude AI agents

## Overview

The swarm module enables multi-agent security auditing of Solana/Anchor programs. Instead of a single AI analyzing everything, multiple specialist agents work in parallel, each focusing on a specific vulnerability category.

## Quick Start

```typescript
import { swarmAudit } from '@solguard/cli/swarm';

const result = await swarmAudit({
  target: './programs/my-vault/src/lib.rs',
  mode: 'api',  // or 'agent-teams' inside Claude Code
});

console.log(`Found ${result.findings.length} issues`);
console.log(result.markdownReport);
```

## Specialist Agents

| Agent | Focus Area | Key Patterns |
|-------|-----------|--------------|
| 🔄 Reentrancy | CPI state bugs, callback attacks | State after invoke, return data |
| 🔐 Access Control | Permissions, authorities | Owner check, signer, has_one |
| 🔢 Arithmetic | Overflow, precision loss | Checked math, division by zero |
| 📊 Oracle | Price manipulation, staleness | TWAP, confidence, validation |

## Execution Modes

### 1. Claude API Mode (Recommended for CI)

```bash
export ANTHROPIC_API_KEY=your-key
```

```typescript
const result = await swarmAudit({
  target: './program',
  mode: 'api',
});
```

### 2. Agent Teams Mode (Interactive)

Requires Claude Code with Agent Teams enabled:

```json
// settings.json
{
  "env": {
    "CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS": "1"
  }
}
```

When running inside Claude Code, agents spawn in tmux/iTerm2 panes for visual debugging.

### 3. Subprocess Mode (Fallback)

Uses `claude` CLI with `--print` flag. Slower but works without API key.

## Output

The swarm produces:
- Deduplicated findings with severity ratings
- Executive summary with top risks
- Recommendations based on patterns found
- Markdown report for documentation

### Example Report

```markdown
# SolGuard Multi-Agent Security Audit Report

## Executive Summary

| Severity | Count |
|----------|-------|
| Critical | 1     |
| High     | 3     |
| Medium   | 5     |

### Top Risks
- Missing signer check in withdraw function
- Integer overflow in fee calculation
- Oracle staleness not validated

### Recommendations
- URGENT: Address all critical vulnerabilities before deployment
- Implement checked arithmetic throughout codebase
```

## Configuration

```typescript
interface SwarmConfig {
  mode: 'agent-teams' | 'api' | 'subprocess' | 'auto';
  specialists?: ('reentrancy' | 'access-control' | 'arithmetic' | 'oracle')[];
  model?: string;  // Default: claude-sonnet-4-20250514
  maxParallel?: number;  // Default: 4
  timeout?: number;  // Default: 120000ms
  outputDir?: string;  // For saving reports
  verbose?: boolean;
}
```

## How It Works

1. **Parse** - Read the target Rust/Anchor code
2. **Dispatch** - Send code to each specialist agent in parallel
3. **Analyze** - Each agent applies domain-specific security checks
4. **Synthesize** - Combine, deduplicate, and cross-reference findings
5. **Report** - Generate unified security report

## Integration with SolGuard

The swarm module complements the pattern-based scanner:

```typescript
import { scan } from '@solguard/cli';
import { swarmAudit } from '@solguard/cli/swarm';

// Run pattern-based scan first
const patternResults = await scan('./program');

// Then run AI swarm for deeper analysis
const swarmResults = await swarmAudit({
  target: './program',
  mode: 'api',
});

// Combine findings
const allFindings = [
  ...patternResults.findings,
  ...swarmResults.findings,
];
```

## Agent Teams Example

When running inside Claude Code with Agent Teams enabled:

```
// The orchestrator generates TeammateTool operations:

Teammate({ operation: "spawnTeam", team_name: "solguard-audit" })

Task({
  team_name: "solguard-audit",
  name: "reentrancy-specialist",
  prompt: "Analyze for CPI state bugs...",
  run_in_background: true
})

Task({
  team_name: "solguard-audit",
  name: "access-control-specialist",
  prompt: "Check permissions and authorities...",
  run_in_background: true
})

// Agents work in parallel, send findings via Teammate.write()
// Lead synthesizes and generates report
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    SwarmOrchestrator                        │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐       │
│  │Reentrancy│ │ Access   │ │Arithmetic│ │  Oracle  │       │
│  │Specialist│ │ Control  │ │Specialist│ │Specialist│       │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘       │
│       │            │            │            │              │
│       └────────────┴─────┬──────┴────────────┘              │
│                          │                                  │
│                    ┌─────▼─────┐                            │
│                    │Synthesizer│                            │
│                    └─────┬─────┘                            │
│                          │                                  │
│                    ┌─────▼─────┐                            │
│                    │  Report   │                            │
│                    └───────────┘                            │
└─────────────────────────────────────────────────────────────┘
```

## License

MIT - Part of SolGuard security toolkit
