import { VulnerabilityPattern } from '../types';

/**
 * Batch 51: Solana-Specific Advanced Patterns
 * SOL7326-SOL7375 (50 patterns)
 * Focus: Solana runtime, account model, transaction processing
 */
export const solanaSpecificPatterns: VulnerabilityPattern[] = [
  // Account Model Attacks
  {
    id: 'SOL7326',
    name: 'Account Resurrection',
    description: 'Closed account can be resurrected with stale data',
    severity: 'critical',
    category: 'account',
    pattern: /close.*account(?!.*zero.*discriminator)|account.*close(?!.*wipe)/gi,
    recommendation: 'Zero out discriminator and all data before closing accounts'
  },
  {
    id: 'SOL7327',
    name: 'Rent Reclaim Attack',
    description: 'Account rent can be reclaimed leaving invalid state',
    severity: 'high',
    category: 'account',
    pattern: /rent.*reclaim|lamport.*withdraw|close.*rent/gi,
    recommendation: 'Ensure account closure is atomic with state cleanup'
  },
  {
    id: 'SOL7328',
    name: 'Account Size Mismatch',
    description: 'Account size doesnt match expected data layout',
    severity: 'high',
    category: 'account',
    pattern: /data_len.*!=|size.*mismatch|space.*incorrect/gi,
    recommendation: 'Validate account size matches expected struct size'
  },
  {
    id: 'SOL7329',
    name: 'Shared Account State',
    description: 'Multiple instructions share mutable account state unsafely',
    severity: 'high',
    category: 'account',
    pattern: /shared.*state|concurrent.*access|parallel.*modify/gi,
    recommendation: 'Use account locks or ensure atomic operations'
  },
  {
    id: 'SOL7330',
    name: 'Account Data Truncation',
    description: 'Account reallocation can truncate important data',
    severity: 'high',
    category: 'account',
    pattern: /realloc.*smaller|resize.*down|truncate.*data/gi,
    recommendation: 'Validate data integrity after reallocation'
  },

  // Program Derived Address (PDA) Advanced
  {
    id: 'SOL7331',
    name: 'PDA Seed Collision',
    description: 'Different entities can generate same PDA through seed collision',
    severity: 'critical',
    category: 'pda',
    pattern: /seeds.*\[.*user|find_program_address.*variable/gi,
    recommendation: 'Include unique identifiers and type discriminators in seeds'
  },
  {
    id: 'SOL7332',
    name: 'Missing Seed Validation',
    description: 'PDA seeds not validated against stored values',
    severity: 'high',
    category: 'pda',
    pattern: /seeds.*=.*ctx\.accounts|pda(?!.*validate.*seed)/gi,
    recommendation: 'Validate derived PDA matches stored seed values'
  },
  {
    id: 'SOL7333',
    name: 'Dynamic Seed Manipulation',
    description: 'User-controlled data in PDA seeds allows address manipulation',
    severity: 'high',
    category: 'pda',
    pattern: /seeds.*input|user.*seed|dynamic.*pda/gi,
    recommendation: 'Hash or constrain user input used in PDA seeds'
  },
  {
    id: 'SOL7334',
    name: 'PDA Authority Confusion',
    description: 'PDA authority scope unclear or overly broad',
    severity: 'high',
    category: 'pda',
    pattern: /pda.*authority|signer.*seeds|program.*sign/gi,
    recommendation: 'Clearly scope PDA authority and document signing powers'
  },
  {
    id: 'SOL7335',
    name: 'Cross-Program PDA Derivation',
    description: 'PDA derived with wrong program ID for cross-program use',
    severity: 'critical',
    category: 'pda',
    pattern: /find_program_address.*other.*program|cross.*pda/gi,
    recommendation: 'Use correct program ID when deriving cross-program PDAs'
  },

  // CPI Advanced Patterns
  {
    id: 'SOL7336',
    name: 'CPI Privilege Escalation',
    description: 'CPI call escalates privileges beyond intended scope',
    severity: 'critical',
    category: 'cpi',
    pattern: /invoke.*signer|cpi.*authority|program.*invoke/gi,
    recommendation: 'Carefully scope signer seeds and validate CPI targets'
  },
  {
    id: 'SOL7337',
    name: 'CPI Return Value Ignored',
    description: 'CPI return value not checked for success',
    severity: 'high',
    category: 'cpi',
    pattern: /invoke\s*\((?!.*\?)|invoke_signed\s*\((?!.*\?)/gi,
    recommendation: 'Always check CPI return values with ? operator'
  },
  {
    id: 'SOL7338',
    name: 'CPI Account Injection',
    description: 'Attacker can inject malicious accounts into CPI',
    severity: 'critical',
    category: 'cpi',
    pattern: /remaining_accounts.*cpi|extra.*accounts.*invoke/gi,
    recommendation: 'Validate all accounts passed to CPI including remaining_accounts'
  },
  {
    id: 'SOL7339',
    name: 'Nested CPI Depth',
    description: 'Deep CPI nesting can hit stack limits',
    severity: 'medium',
    category: 'cpi',
    pattern: /invoke.*invoke|cpi.*cpi|nested.*call/gi,
    recommendation: 'Limit CPI depth and consider compute costs'
  },
  {
    id: 'SOL7340',
    name: 'CPI Data Deserialization',
    description: 'CPI return data deserialized without validation',
    severity: 'high',
    category: 'cpi',
    pattern: /get_return_data|deserialize.*cpi.*result/gi,
    recommendation: 'Validate and sanitize CPI return data before use'
  },

  // Transaction/Instruction Patterns
  {
    id: 'SOL7341',
    name: 'Instruction Ordering Dependency',
    description: 'Security depends on instruction ordering which can be manipulated',
    severity: 'high',
    category: 'transaction',
    pattern: /previous.*instruction|instruction.*order|first.*call/gi,
    recommendation: 'Avoid relying on instruction ordering for security'
  },
  {
    id: 'SOL7342',
    name: 'Transaction Simulation Bypass',
    description: 'Security check can be bypassed through simulation differences',
    severity: 'medium',
    category: 'transaction',
    pattern: /simulate|preflight|dry.*run/gi,
    recommendation: 'Ensure security checks work identically in simulation and execution'
  },
  {
    id: 'SOL7343',
    name: 'Compute Unit Exhaustion',
    description: 'Transaction can exhaust compute units before completing',
    severity: 'medium',
    category: 'transaction',
    pattern: /compute.*budget|cu.*limit|instruction.*limit/gi,
    recommendation: 'Optimize compute usage and set appropriate limits'
  },
  {
    id: 'SOL7344',
    name: 'Partial Transaction Failure',
    description: 'Transaction partially succeeds leaving inconsistent state',
    severity: 'high',
    category: 'transaction',
    pattern: /batch.*instruction|multi.*ix|transaction.*array/gi,
    recommendation: 'Ensure transaction atomicity and rollback on any failure'
  },
  {
    id: 'SOL7345',
    name: 'Transaction Fee Manipulation',
    description: 'Priority fee mechanics exploitable for front-running',
    severity: 'medium',
    category: 'transaction',
    pattern: /priority.*fee|compute.*unit.*price|fee.*bump/gi,
    recommendation: 'Design for fee competition and implement MEV protection'
  },

  // Serialization/Deserialization
  {
    id: 'SOL7346',
    name: 'Borsh Deserialization Attack',
    description: 'Malformed Borsh data causes unexpected behavior',
    severity: 'high',
    category: 'serialization',
    pattern: /try_from_slice|deserialize.*unchecked|borsh.*parse/gi,
    recommendation: 'Use try_ variants and validate all deserialized data'
  },
  {
    id: 'SOL7347',
    name: 'Account Data Corruption',
    description: 'Serialization can corrupt account data on size change',
    severity: 'high',
    category: 'serialization',
    pattern: /serialize.*into|write.*account|data.*borrow_mut/gi,
    recommendation: 'Validate data size before and after serialization'
  },
  {
    id: 'SOL7348',
    name: 'Discriminator Collision',
    description: 'Account types share discriminator values',
    severity: 'critical',
    category: 'serialization',
    pattern: /discriminator.*=|account.*type.*check/gi,
    recommendation: 'Use unique discriminators for each account type'
  },
  {
    id: 'SOL7349',
    name: 'Version Migration Vulnerability',
    description: 'Account version upgrade leaves exploitable state',
    severity: 'high',
    category: 'serialization',
    pattern: /version.*migrate|upgrade.*account|schema.*change/gi,
    recommendation: 'Implement atomic version migrations with validation'
  },
  {
    id: 'SOL7350',
    name: 'Zero Copy Alignment',
    description: 'Zero copy deserialization with incorrect alignment',
    severity: 'high',
    category: 'serialization',
    pattern: /zero.*copy|from_bytes|cast.*ptr/gi,
    recommendation: 'Ensure proper alignment for zero-copy operations'
  },

  // Clock and Timing
  {
    id: 'SOL7351',
    name: 'Slot-Based Time Manipulation',
    description: 'Using slot number as time allows validator manipulation',
    severity: 'high',
    category: 'timing',
    pattern: /slot.*time|current.*slot.*as.*time/gi,
    recommendation: 'Use Clock sysvar unix_timestamp instead of slots'
  },
  {
    id: 'SOL7352',
    name: 'Epoch Boundary Attack',
    description: 'Logic vulnerable during epoch transitions',
    severity: 'medium',
    category: 'timing',
    pattern: /epoch.*transition|new.*epoch|epoch.*boundary/gi,
    recommendation: 'Handle epoch boundaries gracefully in protocol logic'
  },
  {
    id: 'SOL7353',
    name: 'Timestamp Drift Exploitation',
    description: 'Clock timestamp drift allows timing attacks',
    severity: 'medium',
    category: 'timing',
    pattern: /unix_timestamp.*exact|time.*precise/gi,
    recommendation: 'Account for timestamp variance in time-sensitive operations'
  },
  {
    id: 'SOL7354',
    name: 'Block Time Assumption',
    description: 'Assumes consistent block times which can vary',
    severity: 'medium',
    category: 'timing',
    pattern: /400.*ms|slot.*duration|block.*time.*constant/gi,
    recommendation: 'Use timestamps instead of slot counts for timing'
  },
  {
    id: 'SOL7355',
    name: 'Deadline Racing',
    description: 'Deadline check raceable by transaction ordering',
    severity: 'high',
    category: 'timing',
    pattern: /deadline.*check|expire.*time|timeout.*verify/gi,
    recommendation: 'Include safety margin in deadline checks'
  },

  // Anchor-Specific Advanced
  {
    id: 'SOL7356',
    name: 'Anchor Init Race',
    description: 'Account initialization raceable in Anchor',
    severity: 'high',
    category: 'anchor',
    pattern: /init.*if.*empty|init.*check.*exists/gi,
    recommendation: 'Use Anchors init constraint which is atomic'
  },
  {
    id: 'SOL7357',
    name: 'Constraint Skip Attack',
    description: 'Anchor constraints skippable through malformed accounts',
    severity: 'high',
    category: 'anchor',
    pattern: /constraint.*=.*skip|unchecked.*account/gi,
    recommendation: 'Avoid skipping constraints; add explicit validation'
  },
  {
    id: 'SOL7358',
    name: 'Seeds Constraint Mismatch',
    description: 'Anchor seeds constraint doesnt match derivation',
    severity: 'critical',
    category: 'anchor',
    pattern: /seeds.*=.*\[(?!.*bump)|seeds.*mismatch/gi,
    recommendation: 'Always include bump in seeds and verify derivation'
  },
  {
    id: 'SOL7359',
    name: 'Has One Relation Bypass',
    description: 'Anchor has_one constraint bypassable through account swap',
    severity: 'high',
    category: 'anchor',
    pattern: /has_one.*=|relation.*check/gi,
    recommendation: 'Verify has_one targets are properly constrained'
  },
  {
    id: 'SOL7360',
    name: 'Close Constraint Vulnerability',
    description: 'Anchor close constraint doesnt properly clean up',
    severity: 'high',
    category: 'anchor',
    pattern: /close.*=.*destination|account.*close/gi,
    recommendation: 'Verify discriminator and data zeroed on close'
  },

  // Token Program Specific
  {
    id: 'SOL7361',
    name: 'Token Account Owner Override',
    description: 'Token account owner changeable through set_authority',
    severity: 'high',
    category: 'token',
    pattern: /set_authority.*account.*owner|change.*token.*owner/gi,
    recommendation: 'Validate authority changes and lock when appropriate'
  },
  {
    id: 'SOL7362',
    name: 'Associated Token Confusion',
    description: 'ATA derivation confusion allows wrong account usage',
    severity: 'high',
    category: 'token',
    pattern: /associated.*token|ata.*derive|get_associated/gi,
    recommendation: 'Verify ATA derivation matches expected wallet and mint'
  },
  {
    id: 'SOL7363',
    name: 'Token Delegate Abuse',
    description: 'Token delegate authority abusable for unauthorized transfers',
    severity: 'high',
    category: 'token',
    pattern: /delegate.*authority|approve.*delegate|delegated.*amount/gi,
    recommendation: 'Revoke delegates after use and limit delegate amounts'
  },
  {
    id: 'SOL7364',
    name: 'Mint Authority Retention',
    description: 'Mint authority not properly revoked leaving inflation risk',
    severity: 'critical',
    category: 'token',
    pattern: /mint_authority.*Some|set_authority.*mint(?!.*None)/gi,
    recommendation: 'Revoke mint authority when token supply should be fixed'
  },
  {
    id: 'SOL7365',
    name: 'Token-2022 Extension Handling',
    description: 'Token-2022 extensions not properly handled',
    severity: 'high',
    category: 'token',
    pattern: /token.*2022|extension.*type|transfer.*hook/gi,
    recommendation: 'Check and handle all Token-2022 extensions appropriately'
  },

  // Compute and Resources
  {
    id: 'SOL7366',
    name: 'Heap Memory Exhaustion',
    description: 'Program can exhaust 32KB heap allocation',
    severity: 'medium',
    category: 'resource',
    pattern: /vec.*push.*loop|dynamic.*alloc|heap.*grow/gi,
    recommendation: 'Bound dynamic allocations and use fixed-size when possible'
  },
  {
    id: 'SOL7367',
    name: 'Stack Overflow Risk',
    description: 'Deep recursion or large stack frames risk overflow',
    severity: 'medium',
    category: 'resource',
    pattern: /recursive.*call|deep.*nesting|stack.*frame/gi,
    recommendation: 'Limit recursion depth and stack frame sizes'
  },
  {
    id: 'SOL7368',
    name: 'Log Size Limits',
    description: 'Logging exceeds size limits causing truncation',
    severity: 'low',
    category: 'resource',
    pattern: /msg!.*long|log.*truncate|emit.*large/gi,
    recommendation: 'Keep log messages within size limits'
  },
  {
    id: 'SOL7369',
    name: 'Account Data Limit',
    description: 'Account data approaching 10MB limit',
    severity: 'medium',
    category: 'resource',
    pattern: /realloc.*max|data.*size.*large|10.*mb/gi,
    recommendation: 'Design for account size limits and use multiple accounts'
  },
  {
    id: 'SOL7370',
    name: 'Instruction Data Limit',
    description: 'Instruction data exceeding maximum size',
    severity: 'medium',
    category: 'resource',
    pattern: /instruction.*data.*large|param.*size|input.*limit/gi,
    recommendation: 'Keep instruction data within limits or split operations'
  },

  // Validator/Consensus
  {
    id: 'SOL7371',
    name: 'Leader Schedule Exploitation',
    description: 'Logic depends on predictable leader schedule',
    severity: 'medium',
    category: 'consensus',
    pattern: /leader.*schedule|current.*leader|slot.*leader/gi,
    recommendation: 'Do not rely on leader schedule for security decisions'
  },
  {
    id: 'SOL7372',
    name: 'Fork Choice Manipulation',
    description: 'Protocol state inconsistent across forks',
    severity: 'high',
    category: 'consensus',
    pattern: /fork.*check|chain.*tip|finality.*confirm/gi,
    recommendation: 'Wait for finality before considering state permanent'
  },
  {
    id: 'SOL7373',
    name: 'Vote Account Manipulation',
    description: 'Vote account state exploitable for staking attacks',
    severity: 'high',
    category: 'consensus',
    pattern: /vote.*account|validator.*vote|stake.*vote/gi,
    recommendation: 'Validate vote account state and authority'
  },
  {
    id: 'SOL7374',
    name: 'Stake Activation Timing',
    description: 'Stake activation/deactivation timing exploitable',
    severity: 'medium',
    category: 'consensus',
    pattern: /stake.*activation|deactivate.*stake|warmup.*cooldown/gi,
    recommendation: 'Account for activation delays in staking logic'
  },
  {
    id: 'SOL7375',
    name: 'Rent Epoch Exploitation',
    description: 'Rent collection timing exploitable for attacks',
    severity: 'low',
    category: 'consensus',
    pattern: /rent.*epoch|rent.*exempt|rent.*collect/gi,
    recommendation: 'Maintain rent-exempt status and handle rent changes'
  }
];

export default solanaSpecificPatterns;
