/**
 * SolGuard Security Patterns - Batch 96
 * 
 * Feb 6, 2026 8:00 AM - Latest 2026 Exploits + Sec3 2025 Final + Helius Complete History
 * 
 * Sources:
 * - Helius "Solana Hacks, Bugs, and Exploits: A Complete History" (38 verified incidents)
 * - Sec3 2025 Solana Security Ecosystem Review (163 audits, 1,669 vulnerabilities)
 * - Solsec Research Repository
 * - arXiv Academic Papers on Solana Security
 * 
 * Pattern IDs: SOL5801-SOL5900
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

// Helius Complete Exploit History Patterns
const HELIUS_COMPLETE_PATTERNS: Pattern[] = [
  // From NoOnes Platform Exploit (2024)
  {
    id: 'SOL5801',
    name: 'P2P Bridge Validation Gap',
    severity: 'critical',
    pattern: /bridge.*(?:p2p|peer|escrow)[\s\S]{0,300}(?!validate.*(?:signature|signer|authority))/i,
    description: 'P2P bridge or escrow lacks proper validation for cross-platform transfers, similar to NoOnes platform exploit.',
    recommendation: 'Implement multi-signature validation for P2P bridges and verify all cross-platform transfers against trusted oracles.',
    category: 'Bridge Security',
    source: 'Helius: NoOnes Platform Exploit 2024'
  },
  {
    id: 'SOL5802',
    name: 'Hot Wallet Authorization Bypass',
    severity: 'critical',
    pattern: /hot_?wallet[\s\S]{0,200}(?:transfer|withdraw|send)[\s\S]{0,200}(?!require.*(?:multisig|2fa|timelock))/i,
    description: 'Hot wallet operations without multi-factor authorization detected.',
    recommendation: 'Require multi-signature or 2FA for all hot wallet operations exceeding threshold amounts.',
    category: 'Wallet Security',
    source: 'Helius: Multiple Exchange/Platform Exploits'
  },
  {
    id: 'SOL5803',
    name: 'Loopscale Admin Key Exploit Pattern',
    severity: 'critical',
    pattern: /admin.*(?:key|authority|role)[\s\S]{0,200}(?:compromise|expose|leak|log)/i,
    description: 'Admin key exposure risk similar to Loopscale $5.8M exploit.',
    recommendation: 'Use hardware security modules (HSM) for admin keys. Implement key rotation and monitoring.',
    category: 'Key Management',
    source: 'Helius: Loopscale Exploit 2025'
  },
  {
    id: 'SOL5804',
    name: 'DEXX Private Key Logging',
    severity: 'critical',
    pattern: /(?:private_?key|seed_?phrase|mnemonic)[\s\S]{0,100}(?:log|print|console|debug|store|save)/i,
    description: 'Private key or seed phrase may be logged or stored insecurely, similar to DEXX $30M exploit.',
    recommendation: 'Never log private keys. Use secure enclaves and ensure keys are zeroed after use.',
    category: 'Key Management',
    source: 'Helius: DEXX Private Key Leak $30M'
  },
  {
    id: 'SOL5805',
    name: 'Banana Gun Bot Compromise Pattern',
    severity: 'high',
    pattern: /(?:trading_?bot|sniper|arbitrage)[\s\S]{0,300}(?:withdraw|transfer)[\s\S]{0,200}(?!.*limit|.*cap|.*whitelist)/i,
    description: 'Trading bot withdrawal without limits detected, vulnerable to compromise like Banana Gun.',
    recommendation: 'Implement withdrawal limits, cooling periods, and whitelisted addresses for bot operations.',
    category: 'Trading Security',
    source: 'Helius: Banana Gun Bot Compromise'
  },
  
  // From Pump.fun Employee Exploit
  {
    id: 'SOL5806',
    name: 'Insider Threat - Employee Access Pattern',
    severity: 'high',
    pattern: /(?:employee|internal|staff|admin)[\s\S]{0,200}(?:access|key|credential)[\s\S]{0,200}(?!.*audit|.*log|.*monitor)/i,
    description: 'Employee access without proper auditing, vulnerable to insider threats like Pump.fun exploit.',
    recommendation: 'Implement comprehensive audit logging, access monitoring, and separation of duties.',
    category: 'Insider Threat',
    source: 'Helius: Pump.fun Employee Exploit $1.9M'
  },
  {
    id: 'SOL5807',
    name: 'Flash Loan Bonding Curve Manipulation',
    severity: 'critical',
    pattern: /bonding_?curve[\s\S]{0,300}(?!.*flash_?loan_?guard|.*reentrancy_?guard|.*same_?block_?check)/i,
    description: 'Bonding curve without flash loan protection, vulnerable to price manipulation.',
    recommendation: 'Add flash loan guards, same-block checks, and TWAP pricing for bonding curves.',
    category: 'Flash Loan',
    source: 'Helius: Nirvana Finance $3.5M Exploit'
  },
  
  // Supply Chain Attack Patterns
  {
    id: 'SOL5808',
    name: 'Frontend Supply Chain Attack Vector',
    severity: 'high',
    pattern: /(?:cdn|cloudflare|vercel|netlify)[\s\S]{0,200}(?:inject|script|src)[\s\S]{0,200}(?!.*integrity|.*sri|.*hash)/i,
    description: 'Frontend asset loading without integrity checks, vulnerable to supply chain attacks like Parcl.',
    recommendation: 'Use Subresource Integrity (SRI) hashes for all external scripts and CDN resources.',
    category: 'Supply Chain',
    source: 'Helius: Parcl Front-End Attack'
  },
  {
    id: 'SOL5809',
    name: 'NPM Package Compromise Detection',
    severity: 'critical',
    pattern: /solana\/web3\.js[\s\S]{0,100}(?:1\.95\.5|1\.95\.6|1\.95\.7)/i,
    description: 'Potentially compromised web3.js version detected (supply chain attack).',
    recommendation: 'Verify package integrity. Use lockfiles and audit dependencies regularly.',
    category: 'Supply Chain',
    source: 'Helius: Web3.js Supply Chain Attack'
  },
  
  // Network-Level Attack Patterns
  {
    id: 'SOL5810',
    name: 'Jito Bundle DDoS Vector',
    severity: 'medium',
    pattern: /jito[\s\S]{0,200}(?:bundle|searcher)[\s\S]{0,200}(?!.*rate_?limit|.*throttle)/i,
    description: 'Jito bundle submission without rate limiting, potential DDoS vector.',
    recommendation: 'Implement rate limiting and circuit breakers for MEV bundle submissions.',
    category: 'Network Security',
    source: 'Helius: Jito DDoS Incident'
  },
  {
    id: 'SOL5811',
    name: 'NFT Minting DoS Pattern',
    severity: 'medium',
    pattern: /mint[\s\S]{0,200}(?:nft|candy_?machine)[\s\S]{0,200}(?!.*queue|.*batch|.*throttle)/i,
    description: 'NFT minting without queue or throttling, vulnerable to DoS attacks.',
    recommendation: 'Implement queue-based minting with proper throttling during high-demand periods.',
    category: 'DoS Prevention',
    source: 'Helius: Candy Machine NFT Minting Outage'
  },
  
  // Core Protocol Vulnerability Patterns
  {
    id: 'SOL5812',
    name: 'Turbine Block Propagation Vulnerability',
    severity: 'high',
    pattern: /turbine[\s\S]{0,200}(?:shred|block|propagat)[\s\S]{0,200}(?!.*validate|.*verify)/i,
    description: 'Turbine block propagation without proper validation, potential consensus issue.',
    recommendation: 'Ensure all Turbine shreds are validated before processing.',
    category: 'Core Protocol',
    source: 'Helius: Solana Turbine Bug/Failure'
  },
  {
    id: 'SOL5813',
    name: 'JIT Cache Invalidation Bug',
    severity: 'high',
    pattern: /(?:jit|cache)[\s\S]{0,200}(?:invalidat|flush|clear)[\s\S]{0,200}(?!.*sync|.*lock)/i,
    description: 'JIT cache operations without proper synchronization, potential consistency issues.',
    recommendation: 'Use proper locking and synchronization for all cache operations.',
    category: 'Core Protocol',
    source: 'Helius: Solana JIT Cache Bug'
  },
  {
    id: 'SOL5814',
    name: 'ELF Address Alignment Vulnerability',
    severity: 'high',
    pattern: /(?:elf|binary|loader)[\s\S]{0,200}(?:align|address|offset)[\s\S]{0,200}(?!.*check|.*validate)/i,
    description: 'ELF binary loading without proper address alignment checks.',
    recommendation: 'Validate all address alignments when loading ELF binaries.',
    category: 'Core Protocol',
    source: 'Helius: ELF Address Alignment Vulnerability'
  },
  {
    id: 'SOL5815',
    name: 'Durable Nonce Race Condition',
    severity: 'medium',
    pattern: /durable_?nonce[\s\S]{0,200}(?:advance|use)[\s\S]{0,200}(?!.*atomic|.*lock)/i,
    description: 'Durable nonce operations without proper atomicity, potential race condition.',
    recommendation: 'Ensure durable nonce operations are atomic and properly sequenced.',
    category: 'Core Protocol',
    source: 'Helius: Solana Durable Nonce Bug'
  }
];

// Sec3 2025 Report - Business Logic Patterns (38.5% of findings)
const SEC3_BUSINESS_LOGIC_PATTERNS: Pattern[] = [
  {
    id: 'SOL5816',
    name: 'State Machine Transition Bypass',
    severity: 'critical',
    pattern: /(?:state|status|phase)[\s\S]{0,200}(?:=|:=)[\s\S]{0,100}(?!.*match|.*require|.*assert)/i,
    description: 'State transition without validation can be bypassed, accounting for 38.5% of audit findings.',
    recommendation: 'Use explicit state machine with validated transitions. Never allow direct state assignment.',
    category: 'Business Logic',
    source: 'Sec3 2025: Business Logic 38.5%'
  },
  {
    id: 'SOL5817',
    name: 'Protocol Invariant Violation',
    severity: 'critical',
    pattern: /(?:invariant|constraint|rule)[\s\S]{0,200}(?:break|violat|bypass)/i,
    description: 'Protocol invariant may be violated, leading to inconsistent state.',
    recommendation: 'Enforce invariants with require! statements at all state-modifying boundaries.',
    category: 'Business Logic',
    source: 'Sec3 2025: Business Logic'
  },
  {
    id: 'SOL5818',
    name: 'Order of Operations Vulnerability',
    severity: 'high',
    pattern: /(?:transfer|send|mint)[\s\S]{0,200}(?:update|set|modify)[\s\S]{0,100}(?:state|balance|amount)/i,
    description: 'External calls before state updates may enable reentrancy or state inconsistency.',
    recommendation: 'Follow checks-effects-interactions pattern. Update state before external calls.',
    category: 'Business Logic',
    source: 'Sec3 2025: Business Logic'
  },
  {
    id: 'SOL5819',
    name: 'Liquidation Logic Flaw',
    severity: 'critical',
    pattern: /liquidat[\s\S]{0,300}(?!.*threshold|.*ratio|.*health_?factor)/i,
    description: 'Liquidation logic without proper threshold checks, may allow improper liquidations.',
    recommendation: 'Verify health factor and collateral ratios before any liquidation action.',
    category: 'Business Logic',
    source: 'Sec3 2025: DeFi Logic Flaws'
  },
  {
    id: 'SOL5820',
    name: 'Reward Distribution Miscalculation',
    severity: 'high',
    pattern: /reward[\s\S]{0,200}(?:distribut|calculat|claim)[\s\S]{0,200}(?!.*precision|.*decimal|.*scale)/i,
    description: 'Reward distribution without precision handling may lead to rounding errors.',
    recommendation: 'Use scaled arithmetic with sufficient precision for reward calculations.',
    category: 'Business Logic',
    source: 'Sec3 2025: Business Logic'
  }
];

// Sec3 2025 Report - Input Validation Patterns (25% of findings)
const SEC3_INPUT_VALIDATION_PATTERNS: Pattern[] = [
  {
    id: 'SOL5821',
    name: 'Unconstrained Input Length',
    severity: 'high',
    pattern: /(?:input|data|payload)[\s\S]{0,100}\.len\(\)[\s\S]{0,100}(?!.*<|.*<=|.*max|.*limit)/i,
    description: 'Input length not validated, may cause buffer overflow or DoS.',
    recommendation: 'Always validate input length against maximum allowed values.',
    category: 'Input Validation',
    source: 'Sec3 2025: Input Validation 25%'
  },
  {
    id: 'SOL5822',
    name: 'Missing Instruction Data Validation',
    severity: 'high',
    pattern: /instruction_data[\s\S]{0,200}(?:deserialize|unpack)[\s\S]{0,200}(?!.*validate|.*check|.*verify)/i,
    description: 'Instruction data deserialized without validation, may accept malformed inputs.',
    recommendation: 'Validate all instruction data fields after deserialization.',
    category: 'Input Validation',
    source: 'Sec3 2025: Input Validation'
  },
  {
    id: 'SOL5823',
    name: 'Zero Address Acceptance',
    severity: 'medium',
    pattern: /(?:address|pubkey|account)[\s\S]{0,100}(?!.*!=.*default|.*!=.*zero|.*is_initialized)/i,
    description: 'May accept zero/default addresses which could lead to locked funds.',
    recommendation: 'Explicitly reject zero or default addresses in account validation.',
    category: 'Input Validation',
    source: 'Sec3 2025: Input Validation'
  },
  {
    id: 'SOL5824',
    name: 'Negative Value Acceptance',
    severity: 'high',
    pattern: /(?:amount|value|quantity):\s*i(?:64|128|size)[\s\S]{0,100}(?!.*>=\s*0|.*positive|.*unsigned)/i,
    description: 'Signed integer may accept negative values, leading to unexpected behavior.',
    recommendation: 'Use unsigned integers or explicitly validate non-negative values.',
    category: 'Input Validation',
    source: 'Sec3 2025: Input Validation'
  },
  {
    id: 'SOL5825',
    name: 'Uncapped Iteration Count',
    severity: 'medium',
    pattern: /for[\s\S]{0,50}in[\s\S]{0,100}(?!.*\.take\(|.*MAX_|.*limit)/i,
    description: 'Loop iteration without cap may cause compute budget exhaustion.',
    recommendation: 'Use bounded iteration with .take(MAX_ITERATIONS) or similar limits.',
    category: 'Input Validation',
    source: 'Sec3 2025: Input Validation'
  }
];

// Sec3 2025 Report - Access Control Patterns (19% of findings)
const SEC3_ACCESS_CONTROL_PATTERNS: Pattern[] = [
  {
    id: 'SOL5826',
    name: 'Missing Role-Based Access Control',
    severity: 'critical',
    pattern: /(?:admin|owner|authority)[\s\S]{0,200}fn[\s\S]{0,300}(?!.*#\[access_control|.*has_one|.*constraint)/i,
    description: 'Privileged function without role-based access control, 19% of audit findings.',
    recommendation: 'Implement RBAC with Anchor constraints or custom access control checks.',
    category: 'Access Control',
    source: 'Sec3 2025: Access Control 19%'
  },
  {
    id: 'SOL5827',
    name: 'Privilege Escalation via Unvalidated Account',
    severity: 'critical',
    pattern: /UncheckedAccount[\s\S]{0,300}(?:authority|admin|owner)/i,
    description: 'UncheckedAccount used for authority, enabling privilege escalation.',
    recommendation: 'Use typed Account<> with proper constraints for all authority accounts.',
    category: 'Access Control',
    source: 'Sec3 2025: Access Control'
  },
  {
    id: 'SOL5828',
    name: 'Governance Proposal Injection',
    severity: 'critical',
    pattern: /proposal[\s\S]{0,200}(?:execute|process)[\s\S]{0,200}(?!.*validate_proposer|.*quorum|.*timelock)/i,
    description: 'Governance proposal execution without proper validation, similar to Audius exploit.',
    recommendation: 'Validate proposer authority, enforce quorum, and implement timelocks.',
    category: 'Access Control',
    source: 'Helius: Audius Governance Exploit'
  },
  {
    id: 'SOL5829',
    name: 'Emergency Function Without Multisig',
    severity: 'high',
    pattern: /(?:emergency|pause|freeze|shutdown)[\s\S]{0,200}(?!.*multisig|.*threshold|.*timelock)/i,
    description: 'Emergency function without multisig protection.',
    recommendation: 'Require multisig or timelock for all emergency/admin functions.',
    category: 'Access Control',
    source: 'Sec3 2025: Access Control'
  },
  {
    id: 'SOL5830',
    name: 'Authority Transfer Without Two-Step',
    severity: 'medium',
    pattern: /(?:set_authority|transfer_authority|update_admin)[\s\S]{0,200}(?!.*pending|.*accept|.*two_step)/i,
    description: 'Authority transfer without two-step process may lead to permanent lockout.',
    recommendation: 'Implement two-step authority transfer with pending/accept pattern.',
    category: 'Access Control',
    source: 'Sec3 2025: Access Control'
  }
];

// Sec3 2025 Report - Data Integrity Patterns (8.9% of findings)
const SEC3_DATA_INTEGRITY_PATTERNS: Pattern[] = [
  {
    id: 'SOL5831',
    name: 'Precision Loss in Division',
    severity: 'high',
    pattern: /\/[\s\S]{0,50}(?:u64|u128|i64|i128)[\s\S]{0,100}(?!.*checked_|.*precision|.*scale)/i,
    description: 'Integer division may lose precision, 8.9% of audit findings relate to data integrity.',
    recommendation: 'Use scaled arithmetic or decimal libraries for financial calculations.',
    category: 'Data Integrity',
    source: 'Sec3 2025: Data Integrity 8.9%'
  },
  {
    id: 'SOL5832',
    name: 'Multiplication Before Division Missing',
    severity: 'medium',
    pattern: /(\w+)\s*\/\s*(\w+)\s*\*\s*(\w+)/,
    description: 'Division before multiplication loses precision.',
    recommendation: 'Perform multiplication before division: (a * b) / c instead of (a / c) * b.',
    category: 'Data Integrity',
    source: 'Sec3 2025: Data Integrity'
  },
  {
    id: 'SOL5833',
    name: 'Token Decimal Mismatch',
    severity: 'high',
    pattern: /decimals[\s\S]{0,200}(?:6|8|9|18)[\s\S]{0,100}(?!.*normalize|.*scale|.*convert)/i,
    description: 'Token decimal handling without normalization may cause value mismatches.',
    recommendation: 'Normalize all token amounts to a common precision before calculations.',
    category: 'Data Integrity',
    source: 'Sec3 2025: Data Integrity'
  },
  {
    id: 'SOL5834',
    name: 'Timestamp Manipulation Vulnerability',
    severity: 'medium',
    pattern: /Clock::get\(\)[\s\S]{0,200}unix_timestamp[\s\S]{0,200}(?!.*tolerance|.*drift|.*grace)/i,
    description: 'Direct timestamp use without tolerance may be manipulatable.',
    recommendation: 'Allow for clock drift tolerance and avoid tight timestamp dependencies.',
    category: 'Data Integrity',
    source: 'Sec3 2025: Data Integrity'
  },
  {
    id: 'SOL5835',
    name: 'Slot-Based Timing Attack',
    severity: 'medium',
    pattern: /Clock::get\(\)[\s\S]{0,200}slot[\s\S]{0,200}(?:==|!=|<|>)[\s\S]{0,50}(?!.*approximate)/i,
    description: 'Exact slot comparisons may fail due to slot timing variability.',
    recommendation: 'Use slot ranges rather than exact values for timing logic.',
    category: 'Data Integrity',
    source: 'Sec3 2025: Data Integrity'
  }
];

// Sec3 2025 Report - DoS & Liveness Patterns (8.5% of findings)
const SEC3_DOS_LIVENESS_PATTERNS: Pattern[] = [
  {
    id: 'SOL5836',
    name: 'Unbounded Account Reallocation',
    severity: 'medium',
    pattern: /realloc[\s\S]{0,200}(?!.*MAX_|.*limit|.*cap)/i,
    description: 'Account reallocation without bounds may exhaust rent or cause DoS.',
    recommendation: 'Implement maximum size limits for account reallocations.',
    category: 'DoS Prevention',
    source: 'Sec3 2025: DoS & Liveness 8.5%'
  },
  {
    id: 'SOL5837',
    name: 'Compute Budget Exhaustion Risk',
    severity: 'medium',
    pattern: /for[\s\S]{0,100}\.iter\(\)[\s\S]{0,200}(?!.*take|.*limit|.*MAX)/i,
    description: 'Iteration without bounds may exhaust compute budget.',
    recommendation: 'Use bounded iteration and consider splitting large operations.',
    category: 'DoS Prevention',
    source: 'Sec3 2025: DoS & Liveness'
  },
  {
    id: 'SOL5838',
    name: 'CPI Depth Limit Risk',
    severity: 'medium',
    pattern: /invoke(?:_signed)?[\s\S]{0,200}invoke(?:_signed)?[\s\S]{0,200}invoke(?:_signed)?/i,
    description: 'Multiple nested CPI calls may hit depth limit (4).',
    recommendation: 'Minimize CPI depth and consider alternative designs for deep call chains.',
    category: 'DoS Prevention',
    source: 'Sec3 2025: DoS & Liveness'
  },
  {
    id: 'SOL5839',
    name: 'Missing Rent Exemption Check',
    severity: 'low',
    pattern: /lamports[\s\S]{0,200}(?:transfer|subtract)[\s\S]{0,200}(?!.*rent_exempt|.*minimum_balance)/i,
    description: 'Lamport transfer without rent exemption check may make account unusable.',
    recommendation: 'Always maintain minimum rent-exempt balance after transfers.',
    category: 'DoS Prevention',
    source: 'Sec3 2025: DoS & Liveness'
  },
  {
    id: 'SOL5840',
    name: 'Account Close Dust Attack',
    severity: 'low',
    pattern: /close[\s\S]{0,200}account[\s\S]{0,200}(?!.*check_lamports|.*verify_empty)/i,
    description: 'Account closure without checking for dust may leave orphaned lamports.',
    recommendation: 'Verify account is empty before closing and handle dust appropriately.',
    category: 'DoS Prevention',
    source: 'Sec3 2025: DoS & Liveness'
  }
];

// Advanced 2026 Emerging Threat Patterns
const EMERGING_2026_PATTERNS: Pattern[] = [
  {
    id: 'SOL5841',
    name: 'AI Agent Wallet Autonomy Risk',
    severity: 'high',
    pattern: /(?:ai|agent|autonomous)[\s\S]{0,200}(?:wallet|sign|transact)[\s\S]{0,200}(?!.*limit|.*approve|.*human)/i,
    description: 'AI agent with autonomous wallet access without human-in-the-loop controls.',
    recommendation: 'Implement transaction limits, approval workflows, and monitoring for AI agents.',
    category: '2026 Emerging',
    source: 'Emerging: AI Agent Security'
  },
  {
    id: 'SOL5842',
    name: 'Intent-Based System Manipulation',
    severity: 'high',
    pattern: /intent[\s\S]{0,200}(?:solver|filler|execute)[\s\S]{0,200}(?!.*verify|.*validate|.*auction)/i,
    description: 'Intent-based system without proper solver verification.',
    recommendation: 'Implement solver reputation, competitive auctions, and outcome verification.',
    category: '2026 Emerging',
    source: 'Emerging: Intent-Based Protocols'
  },
  {
    id: 'SOL5843',
    name: 'Restaking Slashing Cascade',
    severity: 'critical',
    pattern: /restake[\s\S]{0,200}slash[\s\S]{0,200}(?!.*cap|.*limit|.*circuit_breaker)/i,
    description: 'Restaking protocol without slashing caps may cause cascade effects.',
    recommendation: 'Implement slashing caps and circuit breakers for restaking protocols.',
    category: '2026 Emerging',
    source: 'Emerging: Restaking Security'
  },
  {
    id: 'SOL5844',
    name: 'Validator Concentration Attack',
    severity: 'medium',
    pattern: /(?:validator|stake)[\s\S]{0,200}(?:delegate|assign)[\s\S]{0,200}(?!.*distribute|.*diversify)/i,
    description: 'Stake delegation without distribution may enable centralization attacks.',
    recommendation: 'Implement stake distribution across multiple validators.',
    category: '2026 Emerging',
    source: 'Emerging: Validator Security'
  },
  {
    id: 'SOL5845',
    name: 'Token-2022 Extension Abuse',
    severity: 'high',
    pattern: /Token(?:2022|Extension)[\s\S]{0,200}(?:transfer_?hook|interest_?bearing|confidential)[\s\S]{0,200}(?!.*validate|.*verify)/i,
    description: 'Token-2022 extension usage without proper validation.',
    recommendation: 'Carefully validate all Token-2022 extension behaviors and edge cases.',
    category: '2026 Emerging',
    source: 'Emerging: Token-2022 Security'
  },
  {
    id: 'SOL5846',
    name: 'Compressed NFT Merkle Manipulation',
    severity: 'high',
    pattern: /merkle[\s\S]{0,200}(?:cnft|compressed)[\s\S]{0,200}(?!.*verify_?proof|.*validate_?root)/i,
    description: 'Compressed NFT operations without Merkle proof verification.',
    recommendation: 'Always verify Merkle proofs and root consistency for cNFT operations.',
    category: '2026 Emerging',
    source: 'Emerging: cNFT Security'
  },
  {
    id: 'SOL5847',
    name: 'MEV Backrunning Vulnerability',
    severity: 'medium',
    pattern: /(?:swap|trade|exchange)[\s\S]{0,200}(?!.*slippage|.*deadline|.*private)/i,
    description: 'Trade without slippage protection vulnerable to MEV backrunning.',
    recommendation: 'Implement strict slippage limits, deadlines, and consider private mempools.',
    category: '2026 Emerging',
    source: 'Emerging: MEV Protection'
  },
  {
    id: 'SOL5848',
    name: 'Lookup Table Manipulation',
    severity: 'medium',
    pattern: /address_?lookup_?table[\s\S]{0,200}(?:extend|create)[\s\S]{0,200}(?!.*authority|.*owner)/i,
    description: 'Address lookup table modification without proper authority checks.',
    recommendation: 'Verify authority before any lookup table modifications.',
    category: '2026 Emerging',
    source: 'Emerging: ALT Security'
  },
  {
    id: 'SOL5849',
    name: 'Simulation-Based Attack Detection',
    severity: 'medium',
    pattern: /(?:simulate|preflight|dry_?run)[\s\S]{0,200}(?:result|outcome)[\s\S]{0,200}(?!.*verify_?on_?chain)/i,
    description: 'Reliance on simulation results without on-chain verification.',
    recommendation: 'Never trust simulation results for security-critical decisions.',
    category: '2026 Emerging',
    source: 'Emerging: Simulation Attacks'
  },
  {
    id: 'SOL5850',
    name: 'Cross-Program Return Data Poisoning',
    severity: 'high',
    pattern: /get_return_data[\s\S]{0,200}(?!.*program_?id|.*verify_?source)/i,
    description: 'CPI return data used without verifying source program.',
    recommendation: 'Always verify the program_id when reading CPI return data.',
    category: '2026 Emerging',
    source: 'Emerging: CPI Security'
  }
];

// Combine all patterns
const ALL_BATCH_96_PATTERNS = [
  ...HELIUS_COMPLETE_PATTERNS,
  ...SEC3_BUSINESS_LOGIC_PATTERNS,
  ...SEC3_INPUT_VALIDATION_PATTERNS,
  ...SEC3_ACCESS_CONTROL_PATTERNS,
  ...SEC3_DATA_INTEGRITY_PATTERNS,
  ...SEC3_DOS_LIVENESS_PATTERNS,
  ...EMERGING_2026_PATTERNS
];

export function checkBatch96Patterns(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  for (const pattern of ALL_BATCH_96_PATTERNS) {
    if (pattern.pattern.test(content)) {
      const match = content.match(pattern.pattern);
      let lineNumber: number | undefined;
      
      if (match?.index !== undefined) {
        lineNumber = content.slice(0, match.index).split('\n').length;
      }
      
      findings.push({
        id: pattern.id,
        title: pattern.name,
        severity: pattern.severity,
        description: `${pattern.description}${pattern.source ? ` [Source: ${pattern.source}]` : ''}`,
        location: { file: input.path, line: lineNumber },
        recommendation: pattern.recommendation,
        code: match ? match[0].slice(0, 200) : undefined
      });
    }
  }
  
  return findings;
}

// Export pattern count for registry
export const BATCH_96_PATTERN_COUNT = ALL_BATCH_96_PATTERNS.length;
