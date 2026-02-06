/**
 * Batch 106: Feb 2026 Latest - Response Evolution + Helius Updated + Emerging 2026 Patterns
 * 
 * Sources:
 * 1. Helius Complete History (Updated Feb 2026) - 38 verified incidents, ~$600M gross
 * 2. Response Evolution Analysis - Thunder Terminal 9-min response benchmark
 * 3. 2026 Emerging Threats - AI agents, quantum, infrastructure concentration
 * 4. arXiv:2504.07419 - Academic vulnerability taxonomy
 * 5. Sec3 2025 Final - 163 audits, 1,669 vulnerabilities
 * 
 * Pattern IDs: SOL6801-SOL6900
 */

import type { PatternInput, Finding } from './index.js';

interface PatternDef {
  id: string;
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  pattern: RegExp;
  description: string;
  recommendation: string;
}

const BATCH_106_PATTERNS: PatternDef[] = [
  // ============================================
  // RESPONSE EVOLUTION PATTERNS (SOL6801-SOL6810)
  // From Helius: Response times improved from hours/days → minutes
  // ============================================
  {
    id: 'SOL6801',
    name: 'Missing Rapid Response Circuit Breaker',
    severity: 'high',
    pattern: /(?:transfer|withdraw|swap|liquidat)(?![\s\S]{0,200}(?:pause|circuit_breaker|emergency_stop|halt))/i,
    description: 'Critical operations without circuit breaker. Thunder Terminal halted in 9 minutes - your protocol should too.',
    recommendation: 'Implement emergency pause mechanism for all value-transfer operations.'
  },
  {
    id: 'SOL6802',
    name: 'No Real-Time Monitoring Hook',
    severity: 'medium',
    pattern: /(?:fn\s+(?:transfer|withdraw|deposit))(?![\s\S]{0,300}(?:emit!|msg!|log_))/i,
    description: 'Value operations without event emission for monitoring. CertiK/ZachXBT alerts depend on on-chain events.',
    recommendation: 'Emit events for all critical operations to enable real-time monitoring.'
  },
  {
    id: 'SOL6803',
    name: 'Missing Anomaly Detection Data',
    severity: 'low',
    pattern: /(?:amount|value|balance)[\s\S]{0,50}(?:checked_add|checked_sub)(?![\s\S]{0,100}(?:threshold|limit|max_))/i,
    description: 'Arithmetic without threshold checks for anomaly detection.',
    recommendation: 'Add threshold-based checks to detect anomalous amounts.'
  },
  {
    id: 'SOL6804',
    name: 'No Community Alert Integration',
    severity: 'info',
    pattern: /(?:admin|authority|owner)[\s\S]{0,100}(?:update|modify|change)(?![\s\S]{0,200}(?:timelock|delay|notify))/i,
    description: 'Admin operations without delay for community verification.',
    recommendation: 'Add timelock to admin operations for community verification.'
  },
  {
    id: 'SOL6805',
    name: 'Missing Incident Response Timelock',
    severity: 'medium',
    pattern: /(?:upgrade|migrate|emergency)(?![\s\S]{0,150}(?:timelock|delay_seconds|cool_down))/i,
    description: 'Emergency operations without response timelock. Best protocols respond in minutes.',
    recommendation: 'Implement tiered timelocks: instant for pause, delayed for upgrades.'
  },

  // ============================================
  // HELIUS UPDATED PATTERNS (SOL6811-SOL6830)
  // From latest incident analysis
  // ============================================
  {
    id: 'SOL6811',
    name: 'Wormhole Pattern: Guardian Set Validation Gap',
    severity: 'critical',
    pattern: /(?:guardian|validator|signer)[\s\S]{0,100}(?:set|list|array)(?![\s\S]{0,100}(?:threshold|quorum|minimum))/i,
    description: 'Guardian/validator set without quorum threshold. Wormhole lost $326M to signature forgery.',
    recommendation: 'Always verify guardian quorum threshold before processing.'
  },
  {
    id: 'SOL6812',
    name: 'Cashio Pattern: Root of Trust Chain Broken',
    severity: 'critical',
    pattern: /(?:collateral|backing|reserve)[\s\S]{0,100}(?:mint|token)(?![\s\S]{0,150}(?:verify_mint|whitelist|trusted))/i,
    description: 'Collateral validation without mint verification. Cashio lost $52.8M to fake collateral.',
    recommendation: 'Establish root of trust chain for all collateral validation.'
  },
  {
    id: 'SOL6813',
    name: 'Crema Pattern: CLMM Tick Account Spoofing',
    severity: 'critical',
    pattern: /(?:tick|position|pool)[\s\S]{0,100}(?:account|info)(?![\s\S]{0,100}(?:owner\s*==|has_one|verify_owner))/i,
    description: 'Tick/position account without owner verification. Crema lost $8.8M to fake tick accounts.',
    recommendation: 'Verify tick account ownership against pool authority.'
  },
  {
    id: 'SOL6814',
    name: 'Mango Pattern: Oracle Price Manipulation via Perps',
    severity: 'critical',
    pattern: /(?:perp|perpetual|futures)[\s\S]{0,100}(?:price|mark|index)(?![\s\S]{0,150}(?:twap|window|staleness))/i,
    description: 'Perp pricing without TWAP protection. Mango lost $116M to oracle manipulation.',
    recommendation: 'Use TWAP for perpetual mark price with confidence intervals.'
  },
  {
    id: 'SOL6815',
    name: 'Slope Pattern: Private Key Logging',
    severity: 'critical',
    pattern: /(?:private_key|secret_key|mnemonic|seed)[\s\S]{0,50}(?:log|sentry|track|send)/i,
    description: 'Private key material near logging functions. Slope leaked $8M via Sentry.',
    recommendation: 'Never log, transmit, or store private key material.'
  },
  {
    id: 'SOL6816',
    name: 'DEXX Pattern: Server-Side Key Storage',
    severity: 'critical',
    pattern: /(?:private_key|secret|wallet)[\s\S]{0,100}(?:server|backend|api|store)/i,
    description: 'Server-side key storage detected. DEXX lost $30M to centralized key leak.',
    recommendation: 'Use client-side custody or MPC. Never store keys on servers.'
  },
  {
    id: 'SOL6817',
    name: 'Pump.fun Pattern: Insider Key Access',
    severity: 'high',
    pattern: /(?:employee|admin|internal)[\s\S]{0,100}(?:key|access|authority)(?![\s\S]{0,100}(?:mpc|multisig|threshold))/i,
    description: 'Single employee key access pattern. Pump.fun lost $1.9M to insider exploit.',
    recommendation: 'Use MPC or multisig for all privileged access.'
  },
  {
    id: 'SOL6818',
    name: 'Thunder Terminal Pattern: MongoDB Session Injection',
    severity: 'high',
    pattern: /(?:session|token|auth)[\s\S]{0,100}(?:mongo|database|store)(?![\s\S]{0,100}(?:encrypt|hash|secure))/i,
    description: 'Session storage without encryption. Thunder Terminal lost $240K via MongoDB extraction.',
    recommendation: 'Encrypt all session tokens and use secure session management.'
  },
  {
    id: 'SOL6819',
    name: 'OptiFi Pattern: Accidental Program Close',
    severity: 'critical',
    pattern: /(?:close|shutdown|terminate)[\s\S]{0,100}(?:program|vault|pool)(?![\s\S]{0,100}(?:require!|assert!|verify))/i,
    description: 'Program close without safety checks. OptiFi locked $661K by accidental closure.',
    recommendation: 'Add multiple confirmations and checks before program closure.'
  },
  {
    id: 'SOL6820',
    name: 'Banana Gun Pattern: Bot Key Compromise',
    severity: 'high',
    pattern: /(?:bot|automated|agent)[\s\S]{0,100}(?:key|wallet|signer)(?![\s\S]{0,100}(?:rotate|expire|limit))/i,
    description: 'Automated trading keys without rotation. Banana Gun lost $1.4M to key compromise.',
    recommendation: 'Implement key rotation and spending limits for bots.'
  },
  {
    id: 'SOL6821',
    name: 'Loopscale Pattern: RateX Collateral Valuation',
    severity: 'critical',
    pattern: /(?:rate|value|price)[\s\S]{0,100}(?:collateral|pt_token|yield)(?![\s\S]{0,150}(?:oracle|external|verify))/i,
    description: 'Collateral valuation without external oracle. Loopscale lost $5.8M (recovered) to PT token bug.',
    recommendation: 'Use verified external oracles for all collateral valuations.'
  },
  {
    id: 'SOL6822',
    name: 'NoOnes Pattern: P2P Bridge Validation Gap',
    severity: 'critical',
    pattern: /(?:p2p|bridge|transfer)[\s\S]{0,100}(?:validate|verify|check)(?![\s\S]{0,100}(?:require!|assert!))/i,
    description: 'P2P bridge without strict validation. NoOnes lost $8.5M (ZachXBT reported).',
    recommendation: 'Implement strict validation for all bridge operations.'
  },

  // ============================================
  // 2026 EMERGING THREAT PATTERNS (SOL6831-SOL6850)
  // ============================================
  {
    id: 'SOL6831',
    name: 'AI Agent Wallet: Unbounded Spending',
    severity: 'critical',
    pattern: /(?:agent|ai|autonomous)[\s\S]{0,100}(?:wallet|spend|transfer)(?![\s\S]{0,100}(?:limit|cap|max_))/i,
    description: 'AI agent with unbounded spending authority. Implement strict limits.',
    recommendation: 'Set per-transaction and per-day spending limits for AI agents.'
  },
  {
    id: 'SOL6832',
    name: 'AI Agent: Prompt Injection via Transaction',
    severity: 'high',
    pattern: /(?:agent|ai|llm)[\s\S]{0,100}(?:parse|interpret|read)[\s\S]{0,100}(?:memo|data|instruction)/i,
    description: 'AI agent parsing transaction data that could contain prompt injection.',
    recommendation: 'Sanitize all transaction data before AI processing.'
  },
  {
    id: 'SOL6833',
    name: 'Quantum-Vulnerable Signature Scheme',
    severity: 'info',
    pattern: /(?:ed25519|secp256k1|ecdsa)(?![\s\S]{0,200}(?:post_quantum|lattice|hash_based))/i,
    description: 'Using pre-quantum signature schemes. Plan for migration.',
    recommendation: 'Begin planning for post-quantum signature migration.'
  },
  {
    id: 'SOL6834',
    name: 'Infrastructure Concentration Risk',
    severity: 'medium',
    pattern: /(?:validator|rpc|node)[\s\S]{0,100}(?:provider|host|endpoint)(?![\s\S]{0,100}(?:backup|fallback|redundant))/i,
    description: 'Single infrastructure provider dependency. 43% of Solana stake on 2 providers.',
    recommendation: 'Use multiple infrastructure providers for redundancy.'
  },
  {
    id: 'SOL6835',
    name: 'Jito Client Dominance Dependency',
    severity: 'medium',
    pattern: /(?:jito|mev|bundle)[\s\S]{0,100}(?:client|validator)(?![\s\S]{0,100}(?:alternative|fallback))/i,
    description: 'Heavy Jito client dependency. 88% validator dominance creates systemic risk.',
    recommendation: 'Support multiple client implementations.'
  },
  {
    id: 'SOL6836',
    name: 'Intent System Solver Manipulation',
    severity: 'high',
    pattern: /(?:intent|solver|filler)[\s\S]{0,100}(?:execute|fill|settle)(?![\s\S]{0,100}(?:verify|validate|auction))/i,
    description: 'Intent system without solver verification.',
    recommendation: 'Implement solver reputation and slashing mechanisms.'
  },
  {
    id: 'SOL6837',
    name: 'Restaking Slash Cascade Risk',
    severity: 'high',
    pattern: /(?:restake|liquid_staking|lst)[\s\S]{0,100}(?:slash|penalty)(?![\s\S]{0,100}(?:cap|limit|isolate))/i,
    description: 'Restaking without slashing isolation. Can cascade to multiple protocols.',
    recommendation: 'Implement slashing caps and cross-protocol isolation.'
  },
  {
    id: 'SOL6838',
    name: 'Chrome Extension Fee Injection',
    severity: 'critical',
    pattern: /(?:extension|browser|addon)[\s\S]{0,100}(?:fee|transfer|inject)/i,
    description: 'Browser extension fee injection pattern (Crypto Copilot attack).',
    recommendation: 'Audit all browser extension transaction handling.'
  },
  {
    id: 'SOL6839',
    name: 'LRT Depeg Attack Vector',
    severity: 'high',
    pattern: /(?:lrt|liquid_restaking|receipt_token)[\s\S]{0,100}(?:redeem|withdraw)(?![\s\S]{0,100}(?:delay|queue))/i,
    description: 'Liquid restaking token without redemption delay. Vulnerable to depeg attacks.',
    recommendation: 'Implement redemption queues with appropriate delays.'
  },
  {
    id: 'SOL6840',
    name: 'ZK Proof Verification Bypass',
    severity: 'critical',
    pattern: /(?:zk|zero_knowledge|proof)[\s\S]{0,100}(?:verify|validate)(?![\s\S]{0,100}(?:require!|assert!))/i,
    description: 'ZK proof verification without assertion.',
    recommendation: 'Always assert ZK proof verification results.'
  },

  // ============================================
  // ACADEMIC RESEARCH PATTERNS (SOL6851-SOL6870)
  // From arXiv:2504.07419 systematic study
  // ============================================
  {
    id: 'SOL6851',
    name: 'arXiv: Missing Discriminator Length Check',
    severity: 'high',
    pattern: /(?:discriminator|type_id)[\s\S]{0,50}(?:\[[\s\S]{0,10}\])(?![\s\S]{0,50}(?:len|length|size))/i,
    description: 'Discriminator without length validation. Risk of collision.',
    recommendation: 'Use 8-byte discriminators and validate length.'
  },
  {
    id: 'SOL6852',
    name: 'arXiv: Unvalidated Remaining Accounts',
    severity: 'high',
    pattern: /remaining_accounts(?![\s\S]{0,100}(?:iter|verify|check))/i,
    description: 'Remaining accounts accessed without validation.',
    recommendation: 'Validate all remaining accounts before use.'
  },
  {
    id: 'SOL6853',
    name: 'arXiv: Stack Overflow via Recursion',
    severity: 'high',
    pattern: /(?:fn\s+\w+)[\s\S]{0,50}(?:self\.\w+|recursive)[\s\S]{0,100}(?:depth|level)(?![\s\S]{0,50}(?:limit|max))/i,
    description: 'Recursive function without depth limit. 4KB stack limit.',
    recommendation: 'Limit recursion depth or use iterative approach.'
  },
  {
    id: 'SOL6854',
    name: 'arXiv: Heap Exhaustion Attack',
    severity: 'high',
    pattern: /(?:Vec|vec!|alloc)[\s\S]{0,50}(?:push|extend|reserve)(?![\s\S]{0,100}(?:capacity|limit|max_))/i,
    description: 'Unbounded heap allocation. 32KB heap limit.',
    recommendation: 'Limit vector sizes and validate capacity.'
  },
  {
    id: 'SOL6855',
    name: 'arXiv: Sysvar Spoofing Risk',
    severity: 'critical',
    pattern: /(?:clock|rent|epoch)[\s\S]{0,50}(?:AccountInfo|Info)(?![\s\S]{0,100}(?:from_account_info|Sysvar))/i,
    description: 'Sysvar account without proper validation.',
    recommendation: 'Use Sysvar::from_account_info() for validation.'
  },
  {
    id: 'SOL6856',
    name: 'arXiv: Account Race Condition',
    severity: 'high',
    pattern: /(?:borrow_mut|try_borrow_mut)[\s\S]{0,100}(?:drop|borrow)(?![\s\S]{0,50}(?:scope|block))/i,
    description: 'Potential race condition in mutable borrows.',
    recommendation: 'Use proper scoping for mutable borrows.'
  },
  {
    id: 'SOL6857',
    name: 'arXiv: Serialization Entropy Loss',
    severity: 'medium',
    pattern: /(?:borsh|serialize|pack)[\s\S]{0,100}(?:enum|variant)(?![\s\S]{0,100}(?:discriminator|tag))/i,
    description: 'Enum serialization without explicit discriminator.',
    recommendation: 'Use explicit discriminators for enum variants.'
  },

  // ============================================
  // SEC3 2025 FINAL REPORT PATTERNS (SOL6871-SOL6890)
  // From 163 audits, 1,669 vulnerabilities
  // ============================================
  {
    id: 'SOL6871',
    name: 'Sec3: Business Logic Invariant Drift (38.5%)',
    severity: 'critical',
    pattern: /(?:invariant|assert|require)[\s\S]{0,200}(?:balance|total|supply)(?![\s\S]{0,100}(?:before|after|check))/i,
    description: 'Business logic without invariant assertions. 38.5% of all vulnerabilities.',
    recommendation: 'Assert invariants before and after state changes.'
  },
  {
    id: 'SOL6872',
    name: 'Sec3: Input Validation Missing (25%)',
    severity: 'high',
    pattern: /(?:pub\s+fn|fn\s+\w+)[\s\S]{0,50}(?:amount|value|size):\s*u(?:64|128)(?![\s\S]{0,100}(?:require!|assert!|>|<))/i,
    description: 'Numeric input without validation. 25% of vulnerabilities.',
    recommendation: 'Validate all numeric inputs for reasonable bounds.'
  },
  {
    id: 'SOL6873',
    name: 'Sec3: Access Control Gap (19%)',
    severity: 'critical',
    pattern: /(?:admin|owner|authority)[\s\S]{0,50}(?:fn|instruction)(?![\s\S]{0,100}(?:signer|has_one|constraint))/i,
    description: 'Admin function without access control. 19% of vulnerabilities.',
    recommendation: 'Add signer/has_one constraints to all admin functions.'
  },
  {
    id: 'SOL6874',
    name: 'Sec3: Data Integrity Race (8.9%)',
    severity: 'high',
    pattern: /(?:read|load)[\s\S]{0,100}(?:modify|update)[\s\S]{0,100}(?:write|store)(?![\s\S]{0,100}(?:atomic|lock))/i,
    description: 'Read-modify-write without atomicity. 8.9% of vulnerabilities.',
    recommendation: 'Use atomic operations or proper locking.'
  },
  {
    id: 'SOL6875',
    name: 'Sec3: DoS Liveness Risk (8.5%)',
    severity: 'high',
    pattern: /(?:for|while|loop)[\s\S]{0,50}(?:iter|next)(?![\s\S]{0,100}(?:take|limit|max))/i,
    description: 'Unbounded iteration causing DoS. 8.5% of vulnerabilities.',
    recommendation: 'Limit all iterations with explicit bounds.'
  },
  {
    id: 'SOL6876',
    name: 'Sec3: 76% of Audits Had Medium+ Issues',
    severity: 'medium',
    pattern: /(?:audit|review|test)(?![\s\S]{0,200}(?:pass|complete|verified))/i,
    description: '76% of audited projects had Medium+ issues. Continuous auditing needed.',
    recommendation: 'Implement continuous security review process.'
  },

  // ============================================
  // SUPPLY CHAIN PATTERNS (SOL6891-SOL6900)
  // Web3.js, Parcl, NPM attacks
  // ============================================
  {
    id: 'SOL6891',
    name: 'NPM Package Integrity Check Missing',
    severity: 'critical',
    pattern: /(?:@solana\/web3|solana-web3)(?![\s\S]{0,50}(?:1\.95\.8|pinned|locked))/i,
    description: 'Web3.js without version pinning. v1.95.5-7 were compromised.',
    recommendation: 'Pin to v1.95.8+ and verify package integrity.'
  },
  {
    id: 'SOL6892',
    name: 'CDN Frontend Injection Risk',
    severity: 'high',
    pattern: /(?:cdn|cloudflare|jsdelivr)[\s\S]{0,100}(?:script|src|import)/i,
    description: 'CDN script loading without integrity check. Parcl-style attack.',
    recommendation: 'Use subresource integrity (SRI) for all CDN resources.'
  },
  {
    id: 'SOL6893',
    name: 'Postinstall Script Attack Vector',
    severity: 'critical',
    pattern: /(?:postinstall|preinstall|install)[\s\S]{0,50}(?:script|exec|spawn)/i,
    description: 'NPM lifecycle scripts can execute malicious code.',
    recommendation: 'Audit postinstall scripts and use --ignore-scripts when possible.'
  },
  {
    id: 'SOL6894',
    name: 'Dependency Typosquatting Risk',
    severity: 'high',
    pattern: /(?:solana-|@solana)(?!(?:web3\.js|spl-token|wallet-adapter))/i,
    description: 'Non-standard Solana package naming. Typosquatting risk.',
    recommendation: 'Only use official @solana/* packages.'
  },
  {
    id: 'SOL6895',
    name: 'Build Reproducibility Missing',
    severity: 'medium',
    pattern: /(?:build|compile|deploy)(?![\s\S]{0,100}(?:hash|checksum|verify))/i,
    description: 'Build without reproducibility verification.',
    recommendation: 'Use verifiable builds with hash verification.'
  },
  {
    id: 'SOL6896',
    name: 'SDK Version Drift',
    severity: 'medium',
    pattern: /(?:anchor|solana)[\s\S]{0,20}(?:version|ver)[\s\S]{0,20}(?:\*|latest|^)/i,
    description: 'Floating version constraints. Vulnerable to supply chain attacks.',
    recommendation: 'Pin all dependencies to exact versions.'
  },
  {
    id: 'SOL6897',
    name: 'Frontend Wallet Drainer Pattern',
    severity: 'critical',
    pattern: /(?:signTransaction|signAllTransactions)[\s\S]{0,200}(?:fetch|post|send)(?![\s\S]{0,100}(?:verify|validate))/i,
    description: 'Frontend transaction signing with external communication.',
    recommendation: 'Verify all transactions before signing, use simulation.'
  },
  {
    id: 'SOL6898',
    name: 'API Key Exposure in Frontend',
    severity: 'critical',
    pattern: /(?:api_key|apiKey|secret)[\s\S]{0,20}=[\s\S]{0,20}["'][a-zA-Z0-9]{20,}["']/i,
    description: 'API key hardcoded in frontend code.',
    recommendation: 'Use environment variables and backend proxies for API keys.'
  },
  {
    id: 'SOL6899',
    name: 'RPC Provider Single Point of Failure',
    severity: 'medium',
    pattern: /(?:Connection|connection)[\s\S]{0,50}(?:endpoint|url)(?![\s\S]{0,100}(?:fallback|backup))/i,
    description: 'Single RPC endpoint without fallback.',
    recommendation: 'Implement RPC failover with multiple providers.'
  },
  {
    id: 'SOL6900',
    name: 'Transaction Retry Without Idempotency',
    severity: 'high',
    pattern: /(?:retry|resend|resubmit)[\s\S]{0,100}(?:transaction|tx)(?![\s\S]{0,100}(?:nonce|idempotent|check))/i,
    description: 'Transaction retry without idempotency guarantee.',
    recommendation: 'Use durable nonces or check for duplicate transactions.'
  },
];

/**
 * Run Batch 106 patterns
 */
export function checkBatch106Patterns(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  
  if (!content) return findings;
  
  const lines = content.split('\n');
  
  for (const pattern of BATCH_106_PATTERNS) {
    try {
      const flags = pattern.pattern.flags.includes('g') ? pattern.pattern.flags : pattern.pattern.flags + 'g';
      const regex = new RegExp(pattern.pattern.source, flags);
      const matches = [...content.matchAll(regex)];
      
      for (const match of matches) {
        const matchIndex = match.index || 0;
        
        let lineNum = 1;
        let charCount = 0;
        for (let i = 0; i < lines.length; i++) {
          charCount += lines[i].length + 1;
          if (charCount > matchIndex) {
            lineNum = i + 1;
            break;
          }
        }
        
        const startLine = Math.max(0, lineNum - 2);
        const endLine = Math.min(lines.length, lineNum + 2);
        const snippet = lines.slice(startLine, endLine).join('\n');
        
        findings.push({
          id: pattern.id,
          title: pattern.name,
          severity: pattern.severity,
          description: pattern.description,
          location: { file: input.path, line: lineNum },
          recommendation: pattern.recommendation,
          code: snippet.substring(0, 200),
        });
      }
    } catch (error) {
      // Skip pattern if regex fails
    }
  }
  
  return findings;
}

export const BATCH_106_COUNT = BATCH_106_PATTERNS.length;
