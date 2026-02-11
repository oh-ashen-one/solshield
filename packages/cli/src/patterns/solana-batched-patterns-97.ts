/**
 * SolShield Security Patterns - Batch 97
 * 
 * Feb 6, 2026 8:00 AM - Protocol-Specific Deep Dives + Solsec PoC Research
 * 
 * Sources:
 * - Solsec GitHub: PoC Exploits for Discovered Vulnerabilities
 * - OtterSec, Neodyme, Kudelski Audit Reports
 * - Armani Sealevel Attacks Repository
 * - DeFi Protocol Post-Mortems
 * 
 * Pattern IDs: SOL5901-SOL6000
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

// Solsec PoC Research Patterns
const SOLSEC_POC_PATTERNS: Pattern[] = [
  // Cashio Exploit PoC Patterns
  {
    id: 'SOL5901',
    name: 'Collateral Mint Validation Gap',
    severity: 'critical',
    pattern: /collateral[\s\S]{0,200}mint[\s\S]{0,200}(?!.*==.*expected|.*constraint.*mint|.*validate_mint)/i,
    description: 'Collateral mint not validated against expected value, enables infinite mint like Cashio.',
    recommendation: 'Explicitly validate collateral mint matches expected program-owned mint.',
    category: 'Collateral Security',
    source: 'Solsec PoC: Cashio $52.8M Exploit'
  },
  {
    id: 'SOL5902',
    name: 'Arrow Account Forgery',
    severity: 'critical',
    pattern: /(?:arrow|wrapper|proxy)[\s\S]{0,200}account[\s\S]{0,200}(?!.*validate_owner|.*owner.*==)/i,
    description: 'Wrapper/arrow account without owner validation allows account forgery.',
    recommendation: 'Validate all wrapper account owners against trusted program IDs.',
    category: 'Account Security',
    source: 'Solsec PoC: Cashio Arrow Forgery'
  },
  {
    id: 'SOL5903',
    name: 'Saber LP Token Spoofing',
    severity: 'critical',
    pattern: /(?:saber|swap|lp)[\s\S]{0,200}token[\s\S]{0,200}(?!.*validate_pool|.*pool_mint.*==)/i,
    description: 'LP token not validated against legitimate pool, allows spoofed LP deposits.',
    recommendation: 'Verify LP token mint corresponds to legitimate, audited liquidity pool.',
    category: 'DeFi Security',
    source: 'Solsec PoC: Cashio LP Spoofing'
  },
  
  // Port Finance PoC Patterns
  {
    id: 'SOL5904',
    name: 'Max Withdraw Calculation Bug',
    severity: 'high',
    pattern: /max_?withdraw[\s\S]{0,200}(?:calculate|compute)[\s\S]{0,200}(?!.*collateral_?ratio|.*utilization)/i,
    description: 'Max withdraw calculation without proper collateral ratio check.',
    recommendation: 'Include collateral ratio and utilization in max withdraw calculations.',
    category: 'Lending Security',
    source: 'Solsec PoC: Port Finance Max Withdraw'
  },
  {
    id: 'SOL5905',
    name: 'Reserve Config Bypass',
    severity: 'critical',
    pattern: /reserve_?config[\s\S]{0,200}(?:update|set|modify)[\s\S]{0,200}(?!.*lending_?market_?authority)/i,
    description: 'Reserve config modification without proper authority validation.',
    recommendation: 'Require lending market authority signature for all reserve config updates.',
    category: 'Lending Security',
    source: 'Solsec PoC: Solend Reserve Bypass'
  },
  
  // Jet Protocol PoC Patterns
  {
    id: 'SOL5906',
    name: 'Break Statement Logic Bug',
    severity: 'high',
    pattern: /for[\s\S]{0,100}\{[\s\S]{0,300}break[\s\S]{0,100}\}[\s\S]{0,100}(?!.*continue|.*all_processed)/i,
    description: 'Break in loop may exit prematurely, skipping important processing.',
    recommendation: 'Verify break conditions are correct and all items are processed.',
    category: 'Logic Bug',
    source: 'Solsec PoC: Jet Protocol Break Bug'
  },
  {
    id: 'SOL5907',
    name: 'Governance Vote Weight Manipulation',
    severity: 'critical',
    pattern: /vote_?weight[\s\S]{0,200}(?:calculat|comput)[\s\S]{0,200}(?!.*snapshot|.*checkpoint)/i,
    description: 'Vote weight calculated without snapshot, allows flash loan voting.',
    recommendation: 'Use checkpointed voting power from before proposal creation.',
    category: 'Governance',
    source: 'Solsec PoC: Jet Governance'
  },
  
  // Cope Roulette PoC Patterns
  {
    id: 'SOL5908',
    name: 'Transaction Revert Exploitation',
    severity: 'high',
    pattern: /(?:random|rng|seed)[\s\S]{0,200}(?:generate|create)[\s\S]{0,200}(?!.*commit_?reveal|.*vrf|.*chainlink)/i,
    description: 'Random generation without commit-reveal, vulnerable to revert exploitation.',
    recommendation: 'Use commit-reveal scheme or VRF for fair randomness.',
    category: 'Randomness',
    source: 'Solsec PoC: Cope Roulette Revert'
  },
  {
    id: 'SOL5909',
    name: 'Deterministic Randomness Source',
    severity: 'high',
    pattern: /(?:slot|block_?hash|timestamp)[\s\S]{0,100}(?:as.*seed|.*random)/i,
    description: 'Using predictable on-chain data for randomness.',
    recommendation: 'Use VRF, commit-reveal, or off-chain randomness with verification.',
    category: 'Randomness',
    source: 'Solsec PoC: Cope Roulette'
  },
  
  // Neodyme $2.6B Lending Disclosure Patterns
  {
    id: 'SOL5910',
    name: 'Rounding Error Accumulation',
    severity: 'critical',
    pattern: /(?:interest|rate|yield)[\s\S]{0,200}(?:accrue|compound|calculate)[\s\S]{0,200}(?!.*scale_?factor|.*precision_?guard)/i,
    description: 'Interest accrual without precision guards, enables rounding error accumulation.',
    recommendation: 'Use high-precision arithmetic with proper scaling for interest calculations.',
    category: 'Lending Security',
    source: 'Neodyme: $2.6B Lending Disclosure'
  },
  {
    id: 'SOL5911',
    name: 'Floor vs Round Vulnerability',
    severity: 'high',
    pattern: /\.round\(\)[\s\S]{0,100}(?:deposit|withdraw|borrow|repay)/i,
    description: 'Using round() instead of floor() for financial operations.',
    recommendation: 'Use floor() for amounts going out, ceil() for amounts going in.',
    category: 'Lending Security',
    source: 'Neodyme: SPL Lending Rounding'
  }
];

// Armani Sealevel Attacks Patterns
const SEALEVEL_ATTACKS_PATTERNS: Pattern[] = [
  {
    id: 'SOL5912',
    name: 'Sealevel Missing Owner Check',
    severity: 'critical',
    pattern: /Account<[\s\S]{0,50}>[\s\S]{0,200}(?!.*constraint.*owner|.*owner.*=)/i,
    description: 'Account without owner constraint, allows malicious account substitution.',
    recommendation: 'Add owner constraint: #[account(owner = expected_program)]',
    category: 'Sealevel Attacks',
    source: 'Armani: Sealevel Attacks'
  },
  {
    id: 'SOL5913',
    name: 'Sealevel Missing Signer Check',
    severity: 'critical',
    pattern: /authority[\s\S]{0,50}:[\s\S]{0,50}Account[\s\S]{0,200}(?!.*Signer|.*signer)/i,
    description: 'Authority account not marked as signer.',
    recommendation: 'Use Signer<> type or add signer constraint for authority accounts.',
    category: 'Sealevel Attacks',
    source: 'Armani: Sealevel Attacks'
  },
  {
    id: 'SOL5914',
    name: 'Sealevel Arithmetic Overflow',
    severity: 'high',
    pattern: /(?:\+|-|\*|<<|>>)[\s\S]{0,30}(?:u64|u128|i64|i128)[\s\S]{0,100}(?!.*checked_|.*saturating_|.*wrapping_)/i,
    description: 'Arithmetic operation without overflow protection.',
    recommendation: 'Use checked_*, saturating_*, or wrapping_* operations.',
    category: 'Sealevel Attacks',
    source: 'Armani: Sealevel Attacks'
  },
  {
    id: 'SOL5915',
    name: 'Sealevel Account Data Matching',
    severity: 'high',
    pattern: /Account[\s\S]{0,100}has_one[\s\S]{0,100}(?!.*@|.*constraint)/i,
    description: 'has_one constraint without error handling.',
    recommendation: 'Add custom error: has_one = field @ CustomError::InvalidField',
    category: 'Sealevel Attacks',
    source: 'Armani: Sealevel Attacks'
  },
  {
    id: 'SOL5916',
    name: 'Sealevel Type Cosplay Prevention',
    severity: 'critical',
    pattern: /try_from_slice[\s\S]{0,200}(?!.*discriminator|.*account_type|.*magic)/i,
    description: 'Deserializing account without type discriminator check.',
    recommendation: 'Use Anchor discriminators or manual type checks to prevent type cosplay.',
    category: 'Sealevel Attacks',
    source: 'Armani: Sealevel Attacks'
  },
  {
    id: 'SOL5917',
    name: 'Sealevel Duplicate Mutable Accounts',
    severity: 'critical',
    pattern: /#\[account\(mut\)\][\s\S]{0,500}#\[account\(mut\)\][\s\S]{0,200}(?!.*constraint.*!=)/i,
    description: 'Multiple mutable accounts without uniqueness constraint.',
    recommendation: 'Add constraint: constraint = account_a.key() != account_b.key()',
    category: 'Sealevel Attacks',
    source: 'Armani: Sealevel Attacks'
  },
  {
    id: 'SOL5918',
    name: 'Sealevel PDA Bump Seed Canonicalization',
    severity: 'high',
    pattern: /find_program_address[\s\S]{0,200}(?!.*canonical|.*store.*bump|.*bump.*=)/i,
    description: 'PDA creation without storing/validating canonical bump.',
    recommendation: 'Always store and validate the canonical bump seed.',
    category: 'Sealevel Attacks',
    source: 'Armani: Sealevel Attacks'
  },
  {
    id: 'SOL5919',
    name: 'Sealevel Closing Account Exploit',
    severity: 'high',
    pattern: /close[\s\S]{0,100}=[\s\S]{0,100}(?!.*force_?defund|.*rent_exempt)/i,
    description: 'Account closing without proper cleanup.',
    recommendation: 'Use force_defund flag and ensure account data is zeroed.',
    category: 'Sealevel Attacks',
    source: 'Armani: Sealevel Attacks'
  },
  {
    id: 'SOL5920',
    name: 'Sealevel Reinitialization Attack',
    severity: 'critical',
    pattern: /init[\s\S]{0,200}(?!.*init_if_needed|.*is_initialized.*false)/i,
    description: 'Account initialization without checking if already initialized.',
    recommendation: 'Anchor init handles this, but verify is_initialized for native programs.',
    category: 'Sealevel Attacks',
    source: 'Armani: Sealevel Attacks'
  }
];

// OtterSec Audit Patterns
const OTTERSEC_AUDIT_PATTERNS: Pattern[] = [
  {
    id: 'SOL5921',
    name: 'Tick Account Spoofing (Crema)',
    severity: 'critical',
    pattern: /tick[\s\S]{0,200}(?:account|data)[\s\S]{0,200}(?!.*validate_owner|.*verify_tick)/i,
    description: 'Tick account not validated, allows spoofed tick data like Crema exploit.',
    recommendation: 'Validate tick account ownership and data integrity.',
    category: 'CLMM Security',
    source: 'OtterSec: Crema Finance Audit'
  },
  {
    id: 'SOL5922',
    name: 'LP Token Oracle Manipulation',
    severity: 'critical',
    pattern: /lp[\s\S]{0,100}(?:price|value|oracle)[\s\S]{0,200}(?!.*fair_?pricing|.*twap|.*reserve_?ratio)/i,
    description: 'LP token pricing vulnerable to manipulation.',
    recommendation: 'Use fair pricing formula based on reserve ratios, not spot price.',
    category: 'Oracle Security',
    source: 'OtterSec: LP Token Oracle Manipulation $200M'
  },
  {
    id: 'SOL5923',
    name: 'Flash Loan Fee Claim Manipulation',
    severity: 'high',
    pattern: /(?:fee|reward)[\s\S]{0,200}claim[\s\S]{0,200}(?!.*accrue_?first|.*update_?state)/i,
    description: 'Fee claim without prior state update, vulnerable to flash loan manipulation.',
    recommendation: 'Always accrue fees and update state before allowing claims.',
    category: 'Flash Loan',
    source: 'OtterSec: Fee Manipulation'
  },
  {
    id: 'SOL5924',
    name: 'Position NFT Authority Bypass',
    severity: 'high',
    pattern: /position[\s\S]{0,200}nft[\s\S]{0,200}(?!.*owner.*signer|.*authority.*check)/i,
    description: 'Position NFT operations without owner verification.',
    recommendation: 'Verify NFT owner is signer for all position modifications.',
    category: 'NFT Security',
    source: 'OtterSec: Position NFT Audits'
  },
  {
    id: 'SOL5925',
    name: 'Concentrated Liquidity Bounds Check',
    severity: 'high',
    pattern: /(?:tick_?lower|tick_?upper|sqrt_?price)[\s\S]{0,200}(?!.*MIN_|.*MAX_|.*bounds)/i,
    description: 'Concentrated liquidity parameters without bounds validation.',
    recommendation: 'Validate tick ranges and sqrt prices against protocol bounds.',
    category: 'CLMM Security',
    source: 'OtterSec: CLMM Audits'
  }
];

// Kudelski Audit Patterns
const KUDELSKI_AUDIT_PATTERNS: Pattern[] = [
  {
    id: 'SOL5926',
    name: 'Ownership Verification Gap',
    severity: 'critical',
    pattern: /AccountInfo[\s\S]{0,300}(?![\s\S]{0,200}\.owner[\s\S]{0,50}==)/,
    description: 'AccountInfo used without owner verification (Kudelski common finding).',
    recommendation: 'Always verify account.owner equals expected program ID.',
    category: 'Account Security',
    source: 'Kudelski: Solana Program Security'
  },
  {
    id: 'SOL5927',
    name: 'Data Validation Gap',
    severity: 'high',
    pattern: /\.data\.borrow[\s\S]{0,200}(?!.*validate|.*check|.*verify)/i,
    description: 'Account data borrowed without validation.',
    recommendation: 'Validate deserialized account data before use.',
    category: 'Data Validation',
    source: 'Kudelski: Solana Program Security'
  },
  {
    id: 'SOL5928',
    name: 'CPI Signer Verification',
    severity: 'critical',
    pattern: /invoke_signed[\s\S]{0,300}(?!.*signer_seeds.*validate|.*verify_signer)/i,
    description: 'CPI with invoke_signed without signer seed verification.',
    recommendation: 'Verify signer seeds are correctly derived before CPI.',
    category: 'CPI Security',
    source: 'Kudelski: CPI Best Practices'
  },
  {
    id: 'SOL5929',
    name: 'Delegation Chain Verification',
    severity: 'critical',
    pattern: /(?:delegat|verif)[\s\S]{0,200}chain[\s\S]{0,200}(?!.*root.*trust|.*verify_chain)/i,
    description: 'Delegation chain without root of trust verification (Wormhole pattern).',
    recommendation: 'Verify entire delegation chain leads to trusted root.',
    category: 'Trust Chain',
    source: 'Kudelski: Wormhole Analysis'
  },
  {
    id: 'SOL5930',
    name: 'Reference Account Modification',
    severity: 'high',
    pattern: /AccountInfo[\s\S]{0,100}(?:borrow_mut|try_borrow_mut)[\s\S]{0,200}(?!.*is_writable)/i,
    description: 'Attempting to modify potentially read-only account.',
    recommendation: 'Verify is_writable flag before mutating account data.',
    category: 'Account Security',
    source: 'Kudelski: Account Handling'
  }
];

// Protocol-Specific Deep Dive Patterns
const PROTOCOL_DEEP_DIVE_PATTERNS: Pattern[] = [
  // Mango Markets Specific
  {
    id: 'SOL5931',
    name: 'Oracle Price Band Bypass',
    severity: 'critical',
    pattern: /oracle[\s\S]{0,200}price[\s\S]{0,200}(?!.*band|.*deviation|.*confidence)/i,
    description: 'Oracle price used without confidence/deviation bands (Mango pattern).',
    recommendation: 'Implement price bands and reject oracle updates outside confidence interval.',
    category: 'Oracle Security',
    source: 'Mango Markets $116M Exploit'
  },
  {
    id: 'SOL5932',
    name: 'Perp Funding Rate Manipulation',
    severity: 'high',
    pattern: /funding[\s\S]{0,100}rate[\s\S]{0,200}(?!.*clamp|.*max|.*limit)/i,
    description: 'Perpetual funding rate without limits.',
    recommendation: 'Clamp funding rate to reasonable bounds to prevent manipulation.',
    category: 'Perpetuals',
    source: 'Mango Markets Perp Exploit'
  },
  
  // Marinade Specific
  {
    id: 'SOL5933',
    name: 'Stake Pool Share Calculation',
    severity: 'high',
    pattern: /stake[\s\S]{0,100}pool[\s\S]{0,200}(?:share|token)[\s\S]{0,200}(?!.*total_?lamports|.*pool_?tokens)/i,
    description: 'Stake pool share calculation without proper total tracking.',
    recommendation: 'Calculate shares based on total_lamports / pool_tokens ratio.',
    category: 'Staking',
    source: 'Marinade Audits'
  },
  
  // Orca Whirlpools Specific
  {
    id: 'SOL5934',
    name: 'Whirlpool Tick Array Bounds',
    severity: 'medium',
    pattern: /tick_?array[\s\S]{0,200}(?:index|offset)[\s\S]{0,200}(?!.*TICK_ARRAY_SIZE|.*bounds)/i,
    description: 'Tick array access without proper bounds checking.',
    recommendation: 'Validate tick array index against TICK_ARRAY_SIZE.',
    category: 'CLMM Security',
    source: 'Orca Whirlpool Audits'
  },
  
  // Drift Protocol Specific
  {
    id: 'SOL5935',
    name: 'Oracle Guardrails Missing',
    severity: 'high',
    pattern: /oracle[\s\S]{0,200}(?!.*guardrail|.*circuit_?breaker|.*staleness)/i,
    description: 'Oracle usage without Drift-style guardrails.',
    recommendation: 'Implement oracle guardrails: staleness, deviation, confidence checks.',
    category: 'Oracle Security',
    source: 'Drift Protocol Guardrails'
  },
  
  // Phoenix DEX Specific
  {
    id: 'SOL5936',
    name: 'Order Matching Engine Fairness',
    severity: 'medium',
    pattern: /(?:match|fill)[\s\S]{0,200}order[\s\S]{0,200}(?!.*fifo|.*price_?time|.*fair)/i,
    description: 'Order matching without fairness guarantees.',
    recommendation: 'Implement FIFO or price-time priority for fair order matching.',
    category: 'DEX Security',
    source: 'Phoenix DEX Audits'
  }
];

// Advanced Detection Patterns
const ADVANCED_DETECTION_PATTERNS: Pattern[] = [
  {
    id: 'SOL5937',
    name: 'Multi-Instruction Atomic Vulnerability',
    severity: 'high',
    pattern: /instruction[\s\S]{0,200}(?:previous|next|sysvar)[\s\S]{0,200}(?!.*validate_?instruction|.*atomic)/i,
    description: 'Multi-instruction operation without atomicity guarantees.',
    recommendation: 'Use sysvar instructions to validate instruction ordering and atomicity.',
    category: 'Transaction Security',
    source: 'Advanced: Multi-Instruction'
  },
  {
    id: 'SOL5938',
    name: 'Versioned Transaction Compatibility',
    severity: 'low',
    pattern: /transaction[\s\S]{0,200}(?!.*legacy|.*versioned|.*v0)/i,
    description: 'Transaction handling without versioning consideration.',
    recommendation: 'Handle both legacy and versioned (v0) transactions appropriately.',
    category: 'Transaction Security',
    source: 'Advanced: Versioned Transactions'
  },
  {
    id: 'SOL5939',
    name: 'Compute Unit Estimation Attack',
    severity: 'medium',
    pattern: /compute[\s\S]{0,100}(?:unit|budget)[\s\S]{0,200}(?!.*estimate|.*simulate)/i,
    description: 'Fixed compute budget may fail under different conditions.',
    recommendation: 'Dynamically estimate compute units or add safety margin.',
    category: 'Compute Budget',
    source: 'Advanced: CU Attacks'
  },
  {
    id: 'SOL5940',
    name: 'Priority Fee Manipulation',
    severity: 'low',
    pattern: /priority[\s\S]{0,100}fee[\s\S]{0,200}(?!.*estimate|.*recent_?fees)/i,
    description: 'Hardcoded priority fees may be gamed.',
    recommendation: 'Use dynamic priority fee estimation based on recent blocks.',
    category: 'Transaction Security',
    source: 'Advanced: Fee Manipulation'
  },
  
  // Zero-Copy Safety
  {
    id: 'SOL5941',
    name: 'Zero-Copy Alignment Issue',
    severity: 'high',
    pattern: /#\[account\(zero_copy\)\][\s\S]{0,300}(?!.*repr.*packed|.*repr.*C)/i,
    description: 'Zero-copy account without proper repr attribute.',
    recommendation: 'Use #[repr(packed)] or #[repr(C)] for zero-copy accounts.',
    category: 'Memory Safety',
    source: 'Advanced: Zero-Copy'
  },
  {
    id: 'SOL5942',
    name: 'AccountLoader Unsafe Access',
    severity: 'high',
    pattern: /AccountLoader[\s\S]{0,200}load_mut[\s\S]{0,200}(?!.*drop|.*scope)/i,
    description: 'Zero-copy AccountLoader loaded mutably without proper scoping.',
    recommendation: 'Ensure AccountLoader borrows are properly scoped and dropped.',
    category: 'Memory Safety',
    source: 'Advanced: Zero-Copy Safety'
  },
  
  // Anchor Specific
  {
    id: 'SOL5943',
    name: 'Anchor Init Space Calculation',
    severity: 'medium',
    pattern: /init[\s\S]{0,100}space[\s\S]{0,100}=[\s\S]{0,50}(?!.*INIT_SPACE|.*size_of)/i,
    description: 'Manual space calculation for init may be incorrect.',
    recommendation: 'Use #[derive(InitSpace)] or INIT_SPACE constant for accuracy.',
    category: 'Anchor',
    source: 'Anchor: Space Calculation'
  },
  {
    id: 'SOL5944',
    name: 'Anchor Seeds Constraint Missing',
    severity: 'high',
    pattern: /seeds[\s\S]{0,100}=[\s\S]{0,200}(?!.*bump|.*canonical)/i,
    description: 'PDA seeds without bump constraint.',
    recommendation: 'Always include bump constraint: seeds = [...], bump = account.bump',
    category: 'Anchor',
    source: 'Anchor: PDA Best Practices'
  },
  {
    id: 'SOL5945',
    name: 'Anchor Remaining Accounts Validation',
    severity: 'medium',
    pattern: /remaining_accounts[\s\S]{0,200}(?!.*validate|.*check|.*verify)/i,
    description: 'Remaining accounts used without validation.',
    recommendation: 'Validate all remaining accounts before use.',
    category: 'Anchor',
    source: 'Anchor: Account Validation'
  }
];

// 2026 Latest Threat Patterns
const LATEST_2026_PATTERNS: Pattern[] = [
  {
    id: 'SOL5946',
    name: 'ZK Proof Verification Bypass',
    severity: 'critical',
    pattern: /zk[\s\S]{0,100}(?:proof|verify)[\s\S]{0,200}(?!.*groth16|.*plonk|.*verify_proof)/i,
    description: 'ZK proof handling without proper verification.',
    recommendation: 'Use established ZK verification libraries and validate all proofs.',
    category: '2026 Emerging',
    source: 'Emerging: ZK Security'
  },
  {
    id: 'SOL5947',
    name: 'Blink Actions Permission Escalation',
    severity: 'high',
    pattern: /blink[\s\S]{0,200}action[\s\S]{0,200}(?!.*validate_?origin|.*permission)/i,
    description: 'Solana Blink actions without proper permission validation.',
    recommendation: 'Validate action origins and implement proper permission checks.',
    category: '2026 Emerging',
    source: 'Emerging: Blink Security'
  },
  {
    id: 'SOL5948',
    name: 'Session Token Expiry Bypass',
    severity: 'high',
    pattern: /session[\s\S]{0,200}token[\s\S]{0,200}(?!.*expiry|.*valid_?until|.*ttl)/i,
    description: 'Session token without expiry mechanism.',
    recommendation: 'Implement session token expiry and automatic invalidation.',
    category: '2026 Emerging',
    source: 'Emerging: Session Security'
  },
  {
    id: 'SOL5949',
    name: 'Gasless Transaction Relay Abuse',
    severity: 'medium',
    pattern: /(?:gasless|relayer|meta_?tx)[\s\S]{0,200}(?!.*rate_?limit|.*nonce|.*signature)/i,
    description: 'Gasless transaction relay without abuse prevention.',
    recommendation: 'Implement rate limiting, nonces, and signature verification for relays.',
    category: '2026 Emerging',
    source: 'Emerging: Gasless Security'
  },
  {
    id: 'SOL5950',
    name: 'Cross-Program State Inconsistency',
    severity: 'high',
    pattern: /CpiContext[\s\S]{0,300}(?!.*reload|.*refresh|.*sync_state)/i,
    description: 'State may be stale after CPI, leading to inconsistency.',
    recommendation: 'Reload account state after CPI calls to ensure consistency.',
    category: '2026 Emerging',
    source: 'Emerging: CPI State'
  }
];

// Combine all patterns
const ALL_BATCH_97_PATTERNS = [
  ...SOLSEC_POC_PATTERNS,
  ...SEALEVEL_ATTACKS_PATTERNS,
  ...OTTERSEC_AUDIT_PATTERNS,
  ...KUDELSKI_AUDIT_PATTERNS,
  ...PROTOCOL_DEEP_DIVE_PATTERNS,
  ...ADVANCED_DETECTION_PATTERNS,
  ...LATEST_2026_PATTERNS
];

export function checkBatch97Patterns(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  for (const pattern of ALL_BATCH_97_PATTERNS) {
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
export const BATCH_97_PATTERN_COUNT = ALL_BATCH_97_PATTERNS.length;
