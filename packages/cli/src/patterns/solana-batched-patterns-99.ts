/**
 * SolShield Security Patterns - Batch 99
 * 
 * Feb 6, 2026 9:00 AM - Latest Feb 2026 Emerging Threats
 * 
 * Sources:
 * - Sec3 2025 Report: 163 audits, 1,669 vulnerabilities examined
 * - Helius Complete History: 38 verified incidents analysis
 * - CyberDaily: Infrastructure concentration risks
 * - arXiv:2504.07419: Solana vulnerability systematic study
 * 
 * Pattern IDs: SOL6101-SOL6200
 */

import type { PatternInput, Finding } from './index.js';

interface Pattern {
  id: string;
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  pattern: RegExp;
  description: string;
  recommendation: string;
  category: string;
  source?: string;
}

// Feb 2026 Emerging Threat Patterns
const FEB_2026_PATTERNS: Pattern[] = [
  // Whale Liquidation Cascade Patterns (from CyberDaily $258M analysis)
  {
    id: 'SOL6101',
    name: 'Whale Position Liquidation Cascade',
    severity: 'critical',
    pattern: /liquidat(?:e|ion)[\s\S]{0,200}(?!.*cascade_protection|.*circuit_breaker|.*max_single_liquidation)/i,
    description: 'Large position liquidations can trigger cascading liquidations across DeFi protocols.',
    recommendation: 'Implement cascade protection: max single liquidation size, circuit breakers, gradual liquidation.',
    category: 'DeFi Stability',
    source: 'CyberDaily: $258M Whale Liquidation Cascade (Nov 2025)'
  },
  {
    id: 'SOL6102',
    name: 'Cross-Protocol Liquidation Contagion',
    severity: 'high',
    pattern: /(?:cross|multi)[\s\S]{0,50}(?:protocol|pool)[\s\S]{0,200}liquidat[\s\S]{0,200}(?!.*isolation|.*firewall)/i,
    description: 'Liquidations in one protocol can cascade to affect linked protocols sharing collateral.',
    recommendation: 'Implement protocol isolation, position limits, and cross-protocol contagion monitoring.',
    category: 'DeFi Stability',
    source: 'CyberDaily: Cross-Protocol Cascade Analysis'
  },
  {
    id: 'SOL6103',
    name: 'Leveraged Position Fragility',
    severity: 'high',
    pattern: /leverage[\s\S]{0,100}(?:position|trade|borrow)[\s\S]{0,200}(?!.*max_leverage|.*leverage_cap|.*<=.*MAX_LEVERAGE)/i,
    description: 'High leverage positions create systemic risk during market volatility.',
    recommendation: 'Cap maximum leverage, require additional margin for high leverage, implement de-leveraging.',
    category: 'DeFi Security',
    source: 'CyberDaily: Leveraged Trading Fragility'
  },

  // MEV Validator Concentration Patterns
  {
    id: 'SOL6104',
    name: 'Jito Client Dominance Risk',
    severity: 'medium',
    pattern: /(?:jito|bundle|mev)[\s\S]{0,200}(?:validator|client)[\s\S]{0,200}(?!.*client_diversity|.*multi_client)/i,
    description: 'Jito client controls 88% of Solana validators - single point of failure risk.',
    recommendation: 'Encourage client diversity, implement multi-client fallbacks, monitor concentration.',
    category: 'Network Security',
    source: 'CyberDaily: Jito 88% Client Dominance (Nov 2025)'
  },
  {
    id: 'SOL6105',
    name: 'MEV Extraction Priority Fee Manipulation',
    severity: 'high',
    pattern: /priority[\s\S]{0,50}fee[\s\S]{0,200}(?:validator|mev|extract)[\s\S]{0,200}(?!.*fee_cap|.*max_fee|.*slippage_protection)/i,
    description: 'MEV-dependent validators can manipulate priority fees for short-term gains.',
    recommendation: 'Implement fee caps, priority fee smoothing, and user-side MEV protection.',
    category: 'MEV Security',
    source: 'CyberDaily: MEV Validator Analysis'
  },

  // Infrastructure Concentration Patterns
  {
    id: 'SOL6106',
    name: 'Hosting Provider Concentration',
    severity: 'medium',
    pattern: /(?:validator|node)[\s\S]{0,200}(?:host|provider|datacenter)[\s\S]{0,200}(?!.*geo_diversity|.*multi_provider)/i,
    description: 'Teraswitch and Latitude.sh control ~43% of Solana stake through infrastructure.',
    recommendation: 'Require geographic and provider diversity for validators, implement failover mechanisms.',
    category: 'Infrastructure Security',
    source: 'CyberDaily: Infrastructure Concentration (Nov 2025)'
  },
  {
    id: 'SOL6107',
    name: 'Stake Concentration Risk',
    severity: 'high',
    pattern: /stake[\s\S]{0,100}(?:pool|delegate|validator)[\s\S]{0,200}(?!.*max_stake|.*concentration_limit|.*decentralization)/i,
    description: 'High stake concentration per validator (avg 620K SOL) creates centralization risk.',
    recommendation: 'Implement stake concentration limits, encourage stake distribution across validators.',
    category: 'Network Security',
    source: 'CyberDaily: Validator Stake Concentration'
  },

  // Sec3 2025 Report - Top Vulnerability Categories
  {
    id: 'SOL6108',
    name: 'Sec3-2025: Business Logic Flaw (38.5%)',
    severity: 'critical',
    pattern: /(?:transfer|withdraw|deposit|swap|mint|burn)[\s\S]{0,300}(?!.*validate_state|.*require.*state|.*state_check)/i,
    description: 'Business logic errors are 38.5% of Solana vulnerabilities (Sec3 2025: 163 audits).',
    recommendation: 'Comprehensive state machine validation, formal verification of state transitions.',
    category: 'Business Logic',
    source: 'Sec3 2025 Report: 642 business logic vulnerabilities'
  },
  {
    id: 'SOL6109',
    name: 'Sec3-2025: Input Validation Gap (25%)',
    severity: 'high',
    pattern: /instruction[\s\S]{0,100}data[\s\S]{0,200}(?!.*validate_input|.*check_bounds|.*sanitize)/i,
    description: 'Input validation issues are 25% of Solana vulnerabilities (Sec3 2025).',
    recommendation: 'Validate all instruction inputs: bounds, types, sizes, relationships.',
    category: 'Input Validation',
    source: 'Sec3 2025 Report: 417 input validation issues'
  },
  {
    id: 'SOL6110',
    name: 'Sec3-2025: Access Control Weakness (19%)',
    severity: 'critical',
    pattern: /(?:admin|authority|owner|signer)[\s\S]{0,200}(?!.*has_one|.*constraint.*signer|.*require.*==.*authority)/i,
    description: 'Access control issues are 19% of Solana vulnerabilities (Sec3 2025).',
    recommendation: 'Strict authority validation using has_one constraints and signer verification.',
    category: 'Access Control',
    source: 'Sec3 2025 Report: 317 access control issues'
  },
  {
    id: 'SOL6111',
    name: 'Sec3-2025: Data Integrity Issue (8.9%)',
    severity: 'high',
    pattern: /(?:account|data)[\s\S]{0,100}(?:init|update|modify)[\s\S]{0,200}(?!.*discriminator|.*type_check|.*data_layout)/i,
    description: 'Data integrity issues are 8.9% of Solana vulnerabilities (Sec3 2025).',
    recommendation: 'Use account discriminators, validate data layouts, implement type checking.',
    category: 'Data Integrity',
    source: 'Sec3 2025 Report: 149 data integrity issues'
  },
  {
    id: 'SOL6112',
    name: 'Sec3-2025: DoS/Liveness Risk (8.5%)',
    severity: 'high',
    pattern: /(?:loop|iter|while|for)[\s\S]{0,200}(?!.*max_iterations|.*bounded|.*limit)/i,
    description: 'DoS/Liveness issues are 8.5% of Solana vulnerabilities (Sec3 2025).',
    recommendation: 'Bound all loops, implement compute limits, prevent unbounded resource consumption.',
    category: 'DoS Prevention',
    source: 'Sec3 2025 Report: 142 DoS/liveness issues'
  },

  // arXiv Academic Research Patterns
  {
    id: 'SOL6113',
    name: 'arXiv: Account Discriminator Length',
    severity: 'high',
    pattern: /discriminator[\s\S]{0,100}(?:\[8\]|\[4\])[\s\S]{0,100}(?!.*\[16\]|.*DISCRIMINATOR_LEN.*>=.*8)/i,
    description: 'Short discriminators (4-8 bytes) increase collision risk in type cosplay attacks.',
    recommendation: 'Use 16+ byte discriminators, include program ID in discriminator hash.',
    category: 'Account Security',
    source: 'arXiv:2504.07419 Discriminator Analysis'
  },
  {
    id: 'SOL6114',
    name: 'arXiv: Sysvar Clock Manipulation',
    severity: 'medium',
    pattern: /Clock::get\(\)|sysvar::clock|clock\.unix_timestamp[\s\S]{0,200}(?!.*slot_check|.*epoch_verify)/i,
    description: 'Clock sysvar can be manipulated within slots, affecting time-sensitive logic.',
    recommendation: 'Use slot numbers for sequencing, combine clock with slot for time validation.',
    category: 'Time Security',
    source: 'arXiv:2504.07419 Clock Manipulation'
  },
  {
    id: 'SOL6115',
    name: 'arXiv: Unvalidated Remaining Accounts',
    severity: 'critical',
    pattern: /remaining_accounts[\s\S]{0,200}(?!.*validate|.*check|.*verify.*owner)/i,
    description: 'Remaining accounts often bypass Anchor validation, enabling injection attacks.',
    recommendation: 'Explicitly validate all remaining accounts: owner, discriminator, and constraints.',
    category: 'Account Validation',
    source: 'arXiv:2504.07419 Remaining Accounts'
  },

  // Helius Response Evolution Patterns
  {
    id: 'SOL6116',
    name: 'Helius: Rapid Response Capability',
    severity: 'medium',
    pattern: /(?:exploit|attack|hack)[\s\S]{0,300}(?!.*pause|.*emergency_stop|.*circuit_breaker)/i,
    description: 'Response times improved from hours (2022) to minutes (2024-2025) with proper controls.',
    recommendation: 'Implement emergency pause, circuit breakers, and automated threat detection.',
    category: 'Incident Response',
    source: 'Helius: Response Evolution Analysis'
  },
  {
    id: 'SOL6117',
    name: 'Helius: Community Alert Integration',
    severity: 'low',
    pattern: /(?:alert|monitor|detect)[\s\S]{0,200}(?!.*community|.*external|.*certik|.*zachxbt)/i,
    description: 'Community alerts (CertiK, ZachXBT) enhanced rapid detection in recent incidents.',
    recommendation: 'Integrate community security alerts, bug bounty programs, and external monitoring.',
    category: 'Monitoring',
    source: 'Helius: Community Vigilance Analysis'
  },

  // Insider Threat Patterns (from Helius)
  {
    id: 'SOL6118',
    name: 'Insider Threat: Employee Key Access',
    severity: 'critical',
    pattern: /(?:employee|staff|team)[\s\S]{0,100}(?:key|private|secret|credential)[\s\S]{0,200}(?!.*mpc|.*multisig|.*threshold)/i,
    description: 'Insider threats emerged as concern (Pump.fun, Cypher, DEXX employee exploits).',
    recommendation: 'Use MPC/threshold signatures, role-based access, and key management policies.',
    category: 'Insider Security',
    source: 'Helius: Insider Threat Analysis'
  },
  {
    id: 'SOL6119',
    name: 'Insider Threat: Privileged Access Abuse',
    severity: 'critical',
    pattern: /(?:admin|privileged|elevated)[\s\S]{0,100}(?:access|permission|role)[\s\S]{0,200}(?!.*audit_log|.*separation_of_duties)/i,
    description: 'Privileged access without audit trails enables insider exploitation.',
    recommendation: 'Implement audit logging, separation of duties, and privileged access monitoring.',
    category: 'Insider Security',
    source: 'Helius: Cypher $317K Insider Theft'
  },

  // Protocol-Specific Deep Patterns
  {
    id: 'SOL6120',
    name: 'Lending: Reserve Config Bypass',
    severity: 'critical',
    pattern: /reserve[\s\S]{0,50}config[\s\S]{0,200}(?:update|modify)[\s\S]{0,200}(?!.*canonical_market|.*expected_market)/i,
    description: 'Attackers can create fake markets to bypass reserve config validation.',
    recommendation: 'Validate against canonical market address, not user-provided market accounts.',
    category: 'Lending Security',
    source: 'Helius: Solend $2M Risk Analysis'
  },
  {
    id: 'SOL6121',
    name: 'Bridge: Guardian Verification Depth',
    severity: 'critical',
    pattern: /guardian[\s\S]{0,100}(?:verify|signature)[\s\S]{0,200}(?!.*depth_check|.*full_chain|.*all_guardians)/i,
    description: 'Shallow guardian verification enabled Wormhole $326M exploit.',
    recommendation: 'Full verification chain: signature validity + guardian authenticity + quorum.',
    category: 'Bridge Security',
    source: 'Helius: Wormhole Verification Analysis'
  },
  {
    id: 'SOL6122',
    name: 'CLMM: Tick Account Authenticity',
    severity: 'critical',
    pattern: /tick[\s\S]{0,50}account[\s\S]{0,200}(?!.*owner_check|.*pool_verify|.*canonical_tick)/i,
    description: 'Crema $8.8M exploit used fake tick accounts to claim excessive fees.',
    recommendation: 'Verify tick account owner matches pool, validate tick account derivation.',
    category: 'AMM Security',
    source: 'Helius: Crema Tick Account Exploit'
  },

  // Supply Chain Patterns (Recent Focus)
  {
    id: 'SOL6123',
    name: 'NPM Package Integrity',
    severity: 'critical',
    pattern: /(?:require|import)[\s\S]{0,50}(?:@solana|solana-web3|anchor)[\s\S]{0,200}(?!.*verify_checksum|.*lockfile)/i,
    description: 'Web3.js supply chain attack ($160K) compromised npm packages.',
    recommendation: 'Use package lockfiles, verify checksums, pin exact versions, audit dependencies.',
    category: 'Supply Chain',
    source: 'Helius: Web3.js Supply Chain Attack'
  },
  {
    id: 'SOL6124',
    name: 'Frontend CDN Injection',
    severity: 'high',
    pattern: /(?:cdn|script|iframe)[\s\S]{0,100}(?:src|href)[\s\S]{0,200}(?!.*integrity|.*sri|.*csp)/i,
    description: 'Parcl frontend compromise injected malicious code via CDN.',
    recommendation: 'Use Subresource Integrity (SRI), Content Security Policy, self-hosted critical scripts.',
    category: 'Frontend Security',
    source: 'Helius: Parcl Frontend Attack'
  },

  // Token-2022 Advanced Patterns
  {
    id: 'SOL6125',
    name: 'Token-2022: Transfer Hook Reentrancy',
    severity: 'critical',
    pattern: /transfer_hook[\s\S]{0,200}(?!.*reentrancy_guard|.*nonReentrant|.*lock)/i,
    description: 'Transfer hooks can introduce reentrancy if not properly guarded.',
    recommendation: 'Implement reentrancy guards in all transfer hook implementations.',
    category: 'Token Security',
    source: 'arXiv: Token-2022 Security Analysis'
  },
  {
    id: 'SOL6126',
    name: 'Token-2022: Confidential Transfer Validation',
    severity: 'high',
    pattern: /confidential[\s\S]{0,50}transfer[\s\S]{0,200}(?!.*proof_verify|.*zk_check|.*range_proof)/i,
    description: 'Confidential transfers require careful zero-knowledge proof validation.',
    recommendation: 'Verify all ZK proofs, range proofs, and commitment schemes correctly.',
    category: 'Token Security',
    source: 'Token-2022 Confidential Transfers'
  },

  // Governance Deep Patterns
  {
    id: 'SOL6127',
    name: 'DAO: Proposal Injection Attack',
    severity: 'critical',
    pattern: /proposal[\s\S]{0,100}(?:create|submit|execute)[\s\S]{0,200}(?!.*quorum_check|.*timelock|.*voting_period)/i,
    description: 'Synthetify DAO lost funds to unnoticed malicious proposal (Helius).',
    recommendation: 'Require minimum voting period, quorum threshold, and proposal review timelock.',
    category: 'Governance Security',
    source: 'Helius: Synthetify DAO Proposal Attack'
  },
  {
    id: 'SOL6128',
    name: 'DAO: Treasury Drainage Prevention',
    severity: 'critical',
    pattern: /treasury[\s\S]{0,100}(?:withdraw|transfer|drain)[\s\S]{0,200}(?!.*multisig|.*timelock|.*limit)/i,
    description: 'Single-transaction treasury drains should be prevented.',
    recommendation: 'Implement treasury withdrawal limits, timelocks, and multisig requirements.',
    category: 'Governance Security',
    source: 'Helius: DAO Treasury Security'
  },

  // Emergency Response Patterns
  {
    id: 'SOL6129',
    name: 'Emergency: Protocol Pause Mechanism',
    severity: 'high',
    pattern: /(?:deposit|withdraw|swap|transfer)[\s\S]{0,300}(?!.*paused|.*is_paused|.*require.*!paused)/i,
    description: 'Thunder Terminal halted in 9 minutes due to effective pause mechanism.',
    recommendation: 'Implement global pause that halts all value-moving operations.',
    category: 'Emergency Response',
    source: 'Helius: Thunder Terminal 9-min Response'
  },
  {
    id: 'SOL6130',
    name: 'Emergency: Automated Threat Detection',
    severity: 'medium',
    pattern: /(?:anomaly|threat|attack)[\s\S]{0,200}(?:detect|monitor)[\s\S]{0,200}(?!.*automated|.*realtime|.*alert)/i,
    description: 'Banana Gun and others benefited from automated threat detection.',
    recommendation: 'Implement automated anomaly detection, real-time alerts, and auto-pause triggers.',
    category: 'Monitoring',
    source: 'Helius: Automated Detection Benefits'
  },

  // Additional Critical Patterns
  {
    id: 'SOL6131',
    name: 'Oracle: TWAP Window Too Short',
    severity: 'high',
    pattern: /twap[\s\S]{0,100}(?:window|period)[\s\S]{0,50}(?:\d{1,3}|seconds|blocks)[\s\S]{0,100}(?!.*>=.*600|.*min_window)/i,
    description: 'Short TWAP windows (< 10 min) are vulnerable to flash loan manipulation.',
    recommendation: 'Use minimum 10-minute TWAP windows, combine multiple oracle sources.',
    category: 'Oracle Security',
    source: 'Mango Markets TWAP Analysis'
  },
  {
    id: 'SOL6132',
    name: 'Flash Loan: Single-Transaction Attack',
    severity: 'critical',
    pattern: /flash[\s\S]{0,50}loan[\s\S]{0,200}(?!.*cross_tx_check|.*multi_block|.*cooldown)/i,
    description: 'Single-transaction flash loan attacks exploit atomic execution.',
    recommendation: 'Implement cross-transaction validation, multi-block verification, cooldowns.',
    category: 'DeFi Security',
    source: 'Helius: Flash Loan Attack Patterns'
  },

  // Private Key Security Patterns
  {
    id: 'SOL6133',
    name: 'Key Storage: Server-Side Exposure',
    severity: 'critical',
    pattern: /(?:private[\s_]?key|secret[\s_]?key|seed[\s_]?phrase)[\s\S]{0,200}(?:server|backend|database|storage)/i,
    description: 'DEXX $30M exploit due to server-side private key storage.',
    recommendation: 'Never store private keys server-side. Use HSMs, MPC, or client-side only.',
    category: 'Key Security',
    source: 'Helius: DEXX $30M Key Leak'
  },
  {
    id: 'SOL6134',
    name: 'Wallet: Browser Extension Vulnerability',
    severity: 'high',
    pattern: /(?:extension|plugin|addon)[\s\S]{0,100}(?:wallet|key|credential)[\s\S]{0,200}(?!.*isolated|.*sandbox)/i,
    description: 'Trust Wallet $7M Chrome extension breach via compromised dependency.',
    recommendation: 'Isolate wallet extensions, audit dependencies, use hardware wallets for large amounts.',
    category: 'Wallet Security',
    source: 'Trust Wallet Chrome Breach (Dec 2025)'
  },

  // Phishing-Specific Patterns
  {
    id: 'SOL6135',
    name: 'Owner Permission Phishing',
    severity: 'critical',
    pattern: /(?:setAuthority|set_authority|transfer_authority)[\s\S]{0,200}(?:owner|mint|freeze)[\s\S]{0,200}(?!.*confirm_user|.*delay|.*warning)/i,
    description: 'Jan 2026 phishing wave exploited owner permission transfers.',
    recommendation: 'Show clear warnings for authority transfers, implement confirmation delays.',
    category: 'Phishing Prevention',
    source: 'BTCC: Owner Permission Phishing (Jan 2026)'
  },
  {
    id: 'SOL6136',
    name: 'Signature Request Deception',
    severity: 'high',
    pattern: /sign[\s\S]{0,50}(?:message|transaction)[\s\S]{0,200}(?!.*display_full|.*parse_intent|.*human_readable)/i,
    description: 'Phishing attacks disguise malicious transactions as benign signature requests.',
    recommendation: 'Display full transaction intent in human-readable format before signing.',
    category: 'Phishing Prevention',
    source: 'Solana Phishing Analysis (Dec 2025)'
  }
];

/**
 * Check for Feb 2026 Emerging Threat patterns
 */
export function checkBatch99Patterns(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const code = input.content;

  for (const pattern of FEB_2026_PATTERNS) {
    if (pattern.pattern.test(code)) {
      findings.push({
        ruleId: pattern.id,
        severity: pattern.severity,
        message: pattern.description,
        location: {
          file: input.filePath,
          line: 1,
        },
        fix: pattern.recommendation,
        context: {
          code: code.substring(0, 200),
          name: pattern.name,
          category: pattern.category,
          source: pattern.source,
        },
      });
    }
  }

  return findings;
}

/**
 * Get all Feb 2026 patterns
 */
export function getFeb2026Patterns(): Pattern[] {
  return FEB_2026_PATTERNS;
}

export const BATCH_99_PATTERN_COUNT = FEB_2026_PATTERNS.length;
