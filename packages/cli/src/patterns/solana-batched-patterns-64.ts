/**
 * SolGuard Pattern Batch 64: Infrastructure & Off-Chain Security
 * 
 * Based on:
 * - Web3.js supply chain attack (Dec 2024)
 * - Parcl Front-End attack (Nov 2024)
 * - io.net GPU metadata attack (Apr 2024)
 * - Aurory SyncSpace race condition (Dec 2023)
 * - Solana Core Protocol vulnerabilities
 * 
 * Patterns: SOL2801-SOL2900
 */

import type { Finding, PatternInput } from './index.js';

// Web3.js Supply Chain Attack Patterns (SOL2801-SOL2820)
const SUPPLY_CHAIN_PATTERNS = [
  {
    id: 'SOL2801',
    name: 'NPM Package Exact Version Not Pinned',
    severity: 'high' as const,
    pattern: /"@solana\/web3\.js"\s*:\s*"\^/i,
    description: 'Using caret version allows auto-update to compromised versions. Web3.js 1.95.5-1.95.7 were malicious.',
    recommendation: 'Pin exact versions: "@solana/web3.js": "1.95.4" (no caret).'
  },
  {
    id: 'SOL2802',
    name: 'Package Lock File Missing',
    severity: 'high' as const,
    pattern: /npm\s+install(?![\s\S]{0,50}--package-lock)/i,
    description: 'Installing without lockfile can pull malicious versions.',
    recommendation: 'Always commit package-lock.json and use npm ci in CI/CD.'
  },
  {
    id: 'SOL2803',
    name: 'Postinstall Script Not Reviewed',
    severity: 'medium' as const,
    pattern: /"postinstall"\s*:\s*"/i,
    description: 'Postinstall scripts can execute malicious code during install.',
    recommendation: 'Review all postinstall scripts. Use --ignore-scripts if needed.'
  },
  {
    id: 'SOL2804',
    name: 'Environment Variable Key Exposure',
    severity: 'critical' as const,
    pattern: /process\.env\.(PRIVATE_KEY|SECRET_KEY|MNEMONIC)/i,
    description: 'Malicious packages can read environment variables with keys.',
    recommendation: 'Never store keys in env vars. Use hardware signers or KMS.'
  },
  {
    id: 'SOL2805',
    name: 'Dependency Confusion Attack Vector',
    severity: 'high' as const,
    pattern: /@(internal|private|company)\//i,
    description: 'Private package names can be hijacked on public registry.',
    recommendation: 'Use scoped packages with organization ownership verification.'
  },
  {
    id: 'SOL2806',
    name: 'Transitive Dependency Not Audited',
    severity: 'medium' as const,
    pattern: /"dependencies"\s*:\s*\{[\s\S]*\}/i,
    description: 'Transitive dependencies can introduce vulnerabilities.',
    recommendation: 'Run npm audit regularly and review deep dependency tree.'
  },
  {
    id: 'SOL2807',
    name: 'GitHub Action Workflow Injection',
    severity: 'high' as const,
    pattern: /\$\{\{\s*github\.event\.[\s\S]*\}\}/i,
    description: 'Unsanitized GitHub context in workflows enables code injection.',
    recommendation: 'Never use github.event directly in run commands.'
  },
  {
    id: 'SOL2808',
    name: 'CI/CD Secret Exposure',
    severity: 'critical' as const,
    pattern: /echo[\s\S]*\$\{\{\s*secrets\./i,
    description: 'Secrets printed in CI logs can be captured.',
    recommendation: 'Never echo secrets. Use secret masking in CI/CD.'
  },
];

// Aurory-Style Off-Chain Race Condition Patterns (SOL2821-SOL2840)
const RACE_CONDITION_PATTERNS = [
  {
    id: 'SOL2821',
    name: 'Off-Chain Balance Without Lock',
    severity: 'critical' as const,
    pattern: /(balance|amount)[\s\S]{0,50}(increment|add|update)(?![\s\S]{0,100}(lock|mutex|transaction))/i,
    description: 'Balance updates without locking enable race condition exploits. Aurory lost $830K.',
    recommendation: 'Use database transactions with row-level locking for balance updates.'
  },
  {
    id: 'SOL2822',
    name: 'Parallel Request No Deduplication',
    severity: 'critical' as const,
    pattern: /(buy|sell|transfer|withdraw)[\s\S]{0,50}(handler|endpoint)(?![\s\S]{0,100}(dedupe|idempotent|nonce))/i,
    description: 'Parallel requests can be replayed. Use idempotency keys.',
    recommendation: 'Require unique idempotency key per request with deduplication.'
  },
  {
    id: 'SOL2823',
    name: 'Read-Modify-Write Without Atomic',
    severity: 'high' as const,
    pattern: /(get|read|fetch)[\s\S]{0,30}(balance|amount)[\s\S]{0,50}(set|update|save)/i,
    description: 'Non-atomic read-modify-write sequence has race window.',
    recommendation: 'Use atomic operations: UPDATE balance = balance + x WHERE...'
  },
  {
    id: 'SOL2824',
    name: 'Hybrid On-Off Chain State Mismatch',
    severity: 'critical' as const,
    pattern: /(sync|bridge|transfer)[\s\S]{0,50}(chain|on.?chain)[\s\S]{0,50}(off.?chain|database)/i,
    description: 'State synchronization between on-chain and off-chain can desync.',
    recommendation: 'Implement two-phase commit or use on-chain as source of truth.'
  },
  {
    id: 'SOL2825',
    name: 'Event Ordering Not Guaranteed',
    severity: 'high' as const,
    pattern: /event[\s\S]{0,30}(process|handle)(?![\s\S]{0,100}(sequence|order|serial))/i,
    description: 'Out-of-order event processing can corrupt state.',
    recommendation: 'Process events sequentially using sequence numbers.'
  },
  {
    id: 'SOL2826',
    name: 'Optimistic Update Without Rollback',
    severity: 'high' as const,
    pattern: /optimistic[\s\S]{0,50}(update|write)(?![\s\S]{0,100}(rollback|revert|compensate))/i,
    description: 'Optimistic updates without rollback capability lose consistency.',
    recommendation: 'Implement compensating transactions for failed operations.'
  },
];

// io.net-Style DePIN Security Patterns (SOL2841-SOL2860)
const DEPIN_SECURITY_PATTERNS = [
  {
    id: 'SOL2841',
    name: 'Worker Registration No Verification',
    severity: 'critical' as const,
    pattern: /worker[\s\S]{0,30}(register|add)(?![\s\S]{0,100}(verify|proof|attestation))/i,
    description: 'Workers can register with fake capabilities. io.net had 400K spoofed GPUs.',
    recommendation: 'Require hardware attestation or proof-of-work for worker registration.'
  },
  {
    id: 'SOL2842',
    name: 'Resource Metadata Unverified',
    severity: 'high' as const,
    pattern: /metadata[\s\S]{0,30}(gpu|cpu|memory|storage)(?![\s\S]{0,100}(verify|check|validate))/i,
    description: 'Self-reported metadata can be spoofed.',
    recommendation: 'Verify resource claims through benchmark tests or attestation.'
  },
  {
    id: 'SOL2843',
    name: 'Sybil Attack No Prevention',
    severity: 'critical' as const,
    pattern: /(node|worker|peer)[\s\S]{0,30}(join|register)(?![\s\S]{0,100}(stake|identity|proof))/i,
    description: 'No cost to create nodes enables Sybil attacks.',
    recommendation: 'Require stake, verified identity, or proof-of-resource.'
  },
  {
    id: 'SOL2844',
    name: 'Decentralized Network Eclipse Attack',
    severity: 'high' as const,
    pattern: /peer[\s\S]{0,30}(select|connect)(?![\s\S]{0,100}(random|diverse|limit))/i,
    description: 'Biased peer selection enables eclipse attacks.',
    recommendation: 'Use random peer selection with diversity requirements.'
  },
  {
    id: 'SOL2845',
    name: 'Reward Distribution Gameable',
    severity: 'high' as const,
    pattern: /reward[\s\S]{0,30}(distribute|calculate)[\s\S]{0,50}(uptime|availability)/i,
    description: 'Uptime-based rewards can be gamed with minimal actual contribution.',
    recommendation: 'Base rewards on verified work output, not just availability.'
  },
];

// Front-End Security Patterns - Parcl Style (SOL2861-SOL2880)
const FRONTEND_SECURITY_PATTERNS = [
  {
    id: 'SOL2861',
    name: 'Transaction Preview Missing',
    severity: 'critical' as const,
    pattern: /sign(Transaction|AllTransactions)(?![\s\S]{0,100}(preview|confirm|display))/i,
    description: 'No transaction preview before signing. Users sign blind.',
    recommendation: 'Always show human-readable transaction preview before signing.'
  },
  {
    id: 'SOL2862',
    name: 'Address Comparison Case Sensitive',
    severity: 'high' as const,
    pattern: /address[\s\S]{0,20}(==|===)[\s\S]{0,20}(address|pubkey)/i,
    description: 'Case-sensitive address comparison can be bypassed.',
    recommendation: 'Normalize addresses before comparison (lowercase or base58 canonical).'
  },
  {
    id: 'SOL2863',
    name: 'Domain Verification Missing',
    severity: 'critical' as const,
    pattern: /(wallet[\s_]?connect|sign)(?![\s\S]{0,100}(domain|origin|verify))/i,
    description: 'No domain verification for wallet connections. Enables phishing.',
    recommendation: 'Verify domain against whitelist before wallet interaction.'
  },
  {
    id: 'SOL2864',
    name: 'CDN Resource Without SRI',
    severity: 'medium' as const,
    pattern: /<script[\s\S]*src=["']https?:\/\/[\s\S]*(?!integrity)/i,
    description: 'External scripts without Subresource Integrity can be hijacked.',
    recommendation: 'Add integrity attribute with SHA-384/512 hash for CDN resources.'
  },
  {
    id: 'SOL2865',
    name: 'Local Storage for Sensitive Data',
    severity: 'high' as const,
    pattern: /localStorage\.(setItem|getItem)[\s\S]{0,50}(key|secret|token)/i,
    description: 'Sensitive data in localStorage is accessible to any script.',
    recommendation: 'Never store keys in localStorage. Use session storage or memory only.'
  },
  {
    id: 'SOL2866',
    name: 'CORS Wildcard Origin',
    severity: 'high' as const,
    pattern: /Access-Control-Allow-Origin[\s\S]{0,10}\*/i,
    description: 'Wildcard CORS allows any site to make requests.',
    recommendation: 'Specify allowed origins explicitly, never use wildcard.'
  },
  {
    id: 'SOL2867',
    name: 'Unsigned WebSocket Messages',
    severity: 'high' as const,
    pattern: /websocket[\s\S]{0,50}(message|send)(?![\s\S]{0,100}(sign|verify|auth))/i,
    description: 'Unsigned WebSocket messages can be spoofed or tampered.',
    recommendation: 'Sign all WebSocket messages and verify on receipt.'
  },
];

// Solana Core Protocol Vulnerability Patterns (SOL2881-SOL2900)
const CORE_PROTOCOL_PATTERNS = [
  {
    id: 'SOL2881',
    name: 'BPF Loader Upgrade Without Guard',
    severity: 'critical' as const,
    pattern: /bpf_loader[\s\S]{0,30}upgrade(?![\s\S]{0,100}(guard|verify|auth))/i,
    description: 'BPF program upgrade without proper authority verification.',
    recommendation: 'Always verify upgrade authority before allowing program upgrades.'
  },
  {
    id: 'SOL2882',
    name: 'Compute Unit Estimation Wrong',
    severity: 'medium' as const,
    pattern: /compute[\s_]?unit[\s\S]{0,30}(set|request)[\s\S]{0,20}\d{3,5}(?!\d)/i,
    description: 'Fixed compute units may be insufficient for complex transactions.',
    recommendation: 'Use simulation to estimate compute units, add buffer for variance.'
  },
  {
    id: 'SOL2883',
    name: 'Priority Fee Zero',
    severity: 'low' as const,
    pattern: /priority[\s_]?fee[\s\S]{0,10}(=|:)[\s\S]{0,5}0/i,
    description: 'Zero priority fee may cause transaction delays in congestion.',
    recommendation: 'Set dynamic priority fees based on network conditions.'
  },
  {
    id: 'SOL2884',
    name: 'Durable Nonce Without Advance',
    severity: 'high' as const,
    pattern: /nonce[\s_]?account(?![\s\S]{0,100}advance)/i,
    description: 'Durable nonce without advance instruction. JIT cache bug affected this.',
    recommendation: 'Always include NonceAdvance as first instruction.'
  },
  {
    id: 'SOL2885',
    name: 'Blockhash Caching Too Long',
    severity: 'medium' as const,
    pattern: /blockhash[\s\S]{0,30}(cache|store)[\s\S]{0,50}(minute|hour|day)/i,
    description: 'Blockhashes expire after ~2 minutes. Caching causes failures.',
    recommendation: 'Fetch fresh blockhash for each transaction or use durable nonces.'
  },
  {
    id: 'SOL2886',
    name: 'Transaction Size Unbounded',
    severity: 'high' as const,
    pattern: /instruction[\s\S]{0,30}(push|add)(?![\s\S]{0,100}(size|len|limit))/i,
    description: 'Transaction size limit is 1232 bytes. Unbounded adds fail.',
    recommendation: 'Check transaction size before adding instructions.'
  },
  {
    id: 'SOL2887',
    name: 'Account Realloc Without Rent',
    severity: 'high' as const,
    pattern: /realloc[\s\S]{0,50}(increase|grow)(?![\s\S]{0,100}rent)/i,
    description: 'Account reallocation needs rent top-up for larger size.',
    recommendation: 'Calculate and transfer additional rent on realloc.'
  },
  {
    id: 'SOL2888',
    name: 'Lookup Table Stale Reference',
    severity: 'medium' as const,
    pattern: /lookup[\s_]?table[\s\S]{0,30}(use|get)(?![\s\S]{0,100}(fresh|reload|verify))/i,
    description: 'Stale address lookup table can cause transaction failures.',
    recommendation: 'Refresh lookup table state before critical transactions.'
  },
  {
    id: 'SOL2889',
    name: 'Versioned Transaction Compatibility',
    severity: 'medium' as const,
    pattern: /Transaction[\s\S]{0,20}::new(?![\s\S]{0,100}Version)/i,
    description: 'Legacy transactions dont support lookup tables.',
    recommendation: 'Use VersionedTransaction for modern features.'
  },
  {
    id: 'SOL2890',
    name: 'CPI Depth Limit Exceeded',
    severity: 'high' as const,
    pattern: /invoke[\s\S]{0,50}invoke[\s\S]{0,50}invoke[\s\S]{0,50}invoke/i,
    description: 'CPI depth limit is 4. Deep nesting fails.',
    recommendation: 'Flatten CPI chains or use different architectural approach.'
  },
];

export function checkBatch64Patterns(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (!input.rust?.content) {
    return findings;
  }

  const content = input.rust.content;
  const lines = content.split('\n');

  const allPatterns = [
    ...SUPPLY_CHAIN_PATTERNS,
    ...RACE_CONDITION_PATTERNS,
    ...DEPIN_SECURITY_PATTERNS,
    ...FRONTEND_SECURITY_PATTERNS,
    ...CORE_PROTOCOL_PATTERNS,
  ];

  for (const pattern of allPatterns) {
    const match = pattern.pattern.exec(content);
    if (match) {
      const lineNumber = content.substring(0, match.index).split('\n').length;
      findings.push({
        id: pattern.id,
        title: pattern.name,
        severity: pattern.severity,
        description: pattern.description,
        location: { file: input.path, line: lineNumber },
        recommendation: pattern.recommendation,
      });
    }
  }

  // Additional context-aware checks
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const context = lines.slice(Math.max(0, i - 10), Math.min(lines.length, i + 10)).join('\n');

    // SOL2891: Unsanitized User Input in Error
    if (line.includes('msg!') && (line.includes('{}') || line.includes('{:?}'))) {
      if (context.includes('input') || context.includes('user') || context.includes('data')) {
        findings.push({
          id: 'SOL2891',
          title: 'User Input in Error Message',
          severity: 'low',
          description: 'User-controlled data in error messages can leak information.',
          location: { file: input.path, line: i + 1 },
          recommendation: 'Sanitize or redact user input in error messages.',
        });
      }
    }

    // SOL2892: Hardcoded Address
    if (line.match(/Pubkey::from_str\(["'][A-HJ-NP-Za-km-z1-9]{32,44}["']\)/)) {
      findings.push({
        id: 'SOL2892',
        title: 'Hardcoded Public Key',
        severity: 'medium',
        description: 'Hardcoded addresses reduce flexibility and can be deployment issues.',
        location: { file: input.path, line: i + 1 },
        recommendation: 'Use configurable addresses or derive from seeds.',
      });
    }

    // SOL2893: Unchecked Array Access
    if (line.match(/\[\s*\d+\s*\]/) && !context.includes('len()') && !context.includes('.get(')) {
      if (!line.includes('[0]') && !line.includes('// safe')) {
        findings.push({
          id: 'SOL2893',
          title: 'Unchecked Array Index Access',
          severity: 'high',
          description: 'Direct array index without bounds check can panic.',
          location: { file: input.path, line: i + 1 },
          recommendation: 'Use .get() with proper error handling instead.',
        });
      }
    }

    // SOL2894: Floating Point in Financial Calc
    if ((line.includes('f32') || line.includes('f64')) && 
        (context.includes('price') || context.includes('amount') || context.includes('fee'))) {
      findings.push({
        id: 'SOL2894',
        title: 'Floating Point in Financial Calculation',
        severity: 'high',
        description: 'Floating point has precision issues. Use fixed-point for money.',
        location: { file: input.path, line: i + 1 },
        recommendation: 'Use u64/u128 with fixed decimal places for financial math.',
      });
    }

    // SOL2895: String Operations in Hot Path
    if ((line.includes('format!') || line.includes('to_string()')) && 
        context.includes('fn process') || context.includes('#[instruction]')) {
      findings.push({
        id: 'SOL2895',
        title: 'String Allocation in Hot Path',
        severity: 'medium',
        description: 'String operations consume significant compute units.',
        location: { file: input.path, line: i + 1 },
        recommendation: 'Avoid string ops in instruction handlers. Use msg! directly.',
      });
    }
  }

  return findings;
}
