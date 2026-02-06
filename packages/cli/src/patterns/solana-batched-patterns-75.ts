/**
 * SolGuard Batch 75 Security Patterns
 * Based on: Sec3 2025 Final Deep Dive + helius.dev Complete Exploit History + arXiv Research
 * 
 * Pattern IDs: SOL3576 - SOL3675 (100 patterns)
 * Created: Feb 5, 2026 11:30 PM CST
 * 
 * Sources:
 * - Sec3 2025 Security Report (163 audits, 1,669 vulnerabilities)
 * - helius.dev/blog/solana-hacks (Complete exploit history)
 * - arXiv:2504.07419 (Solana Smart Contract Vulnerabilities)
 * - Medium: Comprehensive Security History Analysis
 */

import type { Finding, PatternInput } from './index.js';

// ============================================================================
// SEC3 2025 FINAL: BUSINESS LOGIC DEEP PATTERNS (38.5% of all issues)
// ============================================================================

const SEC3_BUSINESS_LOGIC_FINAL: {
  id: string;
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  pattern: RegExp;
  description: string;
  recommendation: string;
}[] = [
  {
    id: 'SOL3576',
    name: 'State Machine Violation - Missing Transition Guard',
    severity: 'critical',
    pattern: /enum\s+\w+State[\s\S]{0,300}(?!transition_guard|valid_transition|can_transition)/,
    description: 'State machine lacks transition guards, allowing invalid state changes.',
    recommendation: 'Implement explicit transition guards with allowed_transitions mapping.'
  },
  {
    id: 'SOL3577',
    name: 'Invariant Violation - Balance Sum Drift',
    severity: 'critical',
    pattern: /(?:deposit|withdraw|transfer)[\s\S]{0,200}(?!assert_total_balance|verify_invariant|sum_check)/,
    description: 'Balance-modifying operation without invariant verification.',
    recommendation: 'Add post-operation invariant check: assert!(sum(balances) == expected_total).'
  },
  {
    id: 'SOL3578',
    name: 'Protocol Fee Bypass - Missing Fee Enforcement',
    severity: 'high',
    pattern: /(?:swap|trade|exchange)[\s\S]{0,300}(?!fee_amount|protocol_fee|take_fee)/,
    description: 'Trading operation without fee enforcement allows fee bypass.',
    recommendation: 'Enforce fee collection before completing transaction.'
  },
  {
    id: 'SOL3579',
    name: 'Reward Distribution - Proportional Calculation Error',
    severity: 'high',
    pattern: /reward[\s\S]{0,100}(?:\/|div)[\s\S]{0,50}(?!checked_div|safe_div|precision)/,
    description: 'Reward calculation may lose precision or be manipulated.',
    recommendation: 'Use high-precision math (128-bit) and verify proportional distribution.'
  },
  {
    id: 'SOL3580',
    name: 'Epoch Boundary - Stale Data After Transition',
    severity: 'medium',
    pattern: /epoch[\s\S]{0,100}(?!refresh_epoch|current_epoch|epoch_check)/,
    description: 'Epoch-dependent operation without freshness check.',
    recommendation: 'Verify epoch is current before using epoch-dependent data.'
  },
  {
    id: 'SOL3581',
    name: 'Position Accounting - Share vs Amount Mismatch',
    severity: 'critical',
    pattern: /(?:shares|amount)[\s\S]{0,100}(?:convert|calculate)[\s\S]{0,100}(?!rate_check|exchange_rate)/,
    description: 'Share-to-amount conversion without rate verification.',
    recommendation: 'Use locked exchange rate and verify before/after conversion.'
  },
  {
    id: 'SOL3582',
    name: 'Withdrawal Queue - Priority Manipulation',
    severity: 'high',
    pattern: /queue[\s\S]{0,100}(?:push|insert|add)[\s\S]{0,100}(?!timestamp|priority_lock)/,
    description: 'Queue insertion without proper ordering can be manipulated.',
    recommendation: 'Use timestamp-based priority with manipulation resistance.'
  },
  {
    id: 'SOL3583',
    name: 'Atomic Operation - Partial Execution',
    severity: 'critical',
    pattern: /(?:multi_transfer|batch)[\s\S]{0,200}(?!atomic|all_or_nothing|revert_on_fail)/,
    description: 'Multi-step operation can fail partially, leaving inconsistent state.',
    recommendation: 'Implement atomic execution with full rollback on any failure.'
  },
  {
    id: 'SOL3584',
    name: 'Vesting Schedule - Cliff Bypass',
    severity: 'high',
    pattern: /vest(?:ing)?[\s\S]{0,150}(?!cliff_check|cliff_passed|unlock_time)/,
    description: 'Vesting logic may allow early withdrawal before cliff.',
    recommendation: 'Enforce cliff period check before any token release.'
  },
  {
    id: 'SOL3585',
    name: 'Auction Mechanism - Bid Manipulation',
    severity: 'high',
    pattern: /(?:auction|bid)[\s\S]{0,200}(?!minimum_increment|anti_snipe|time_extension)/,
    description: 'Auction lacks anti-manipulation mechanisms.',
    recommendation: 'Add minimum bid increment and anti-sniping time extensions.'
  },
];

// ============================================================================
// SEC3 2025 FINAL: INPUT VALIDATION DEEP PATTERNS (25% of all issues)
// ============================================================================

const SEC3_INPUT_VALIDATION_FINAL: typeof SEC3_BUSINESS_LOGIC_FINAL = [
  {
    id: 'SOL3586',
    name: 'Seed Collision - Predictable PDA Generation',
    severity: 'critical',
    pattern: /find_program_address[\s\S]{0,100}(?:user_input|external_data)[\s\S]{0,50}(?!hash|sanitize)/,
    description: 'PDA seeds from user input can cause collisions.',
    recommendation: 'Hash user input before using as PDA seed.'
  },
  {
    id: 'SOL3587',
    name: 'String Length - Unbounded Input',
    severity: 'medium',
    pattern: /String[\s\S]{0,50}(?!max_len|bounded|truncate|limit)/,
    description: 'Unbounded string input can exhaust compute or storage.',
    recommendation: 'Enforce maximum string length at input validation.'
  },
  {
    id: 'SOL3588',
    name: 'Array Index - Unchecked Access',
    severity: 'high',
    pattern: /\[[\s\S]{0,20}as\s+usize[\s\S]{0,10}\](?!.*get\(|.*get_mut\()/,
    description: 'Direct array access without bounds checking.',
    recommendation: 'Use .get() or .get_mut() for safe array access.'
  },
  {
    id: 'SOL3589',
    name: 'Timestamp Future - Excessive Future Date',
    severity: 'medium',
    pattern: /timestamp[\s\S]{0,100}(?:\+|add)[\s\S]{0,50}(?!max_future|reasonable_limit)/,
    description: 'Timestamp can be set far into future, locking funds.',
    recommendation: 'Limit maximum future timestamp to reasonable bounds.'
  },
  {
    id: 'SOL3590',
    name: 'Percentage Overflow - Greater Than 100%',
    severity: 'high',
    pattern: /(?:percent|bps|basis_points)[\s\S]{0,50}(?!<=\s*10000|<=\s*100|max_percent)/,
    description: 'Percentage/BPS input can exceed 100%, causing overflow.',
    recommendation: 'Validate percentage <= 10000 BPS (100%).'
  },
  {
    id: 'SOL3591',
    name: 'Merkle Proof - Invalid Proof Length',
    severity: 'high',
    pattern: /merkle[\s\S]{0,100}proof[\s\S]{0,100}(?!len\s*==|proof_size|max_depth)/,
    description: 'Merkle proof without length validation can cause DoS.',
    recommendation: 'Validate proof length matches expected tree depth.'
  },
  {
    id: 'SOL3592',
    name: 'Decimal Precision - Inconsistent Decimals',
    severity: 'high',
    pattern: /decimals[\s\S]{0,100}(?!normalize|scale|convert_decimals)/,
    description: 'Token decimal handling without normalization.',
    recommendation: 'Normalize all token amounts to consistent decimal places.'
  },
  {
    id: 'SOL3593',
    name: 'Vector Capacity - Unbounded Growth',
    severity: 'medium',
    pattern: /Vec::(?:new|with_capacity)[\s\S]{0,100}(?:push|extend)[\s\S]{0,100}(?!max_len|capacity_check)/,
    description: 'Vector can grow unbounded, exhausting compute.',
    recommendation: 'Enforce maximum vector capacity limits.'
  },
  {
    id: 'SOL3594',
    name: 'Negative Amount - Unsigned Underflow',
    severity: 'critical',
    pattern: /amount[\s\S]{0,50}(?:checked_sub|saturating_sub)[\s\S]{0,30}(?!>=|zero_check)/,
    description: 'Subtraction may underflow even with checked math if not validated.',
    recommendation: 'Validate amount >= subtrahend before subtraction.'
  },
  {
    id: 'SOL3595',
    name: 'Slot Number - Past Slot Manipulation',
    severity: 'medium',
    pattern: /slot[\s\S]{0,50}(?!>=\s*current|future_slot|slot_check)/,
    description: 'Slot number validation allows past slots.',
    recommendation: 'Require slot >= current_slot for future-dated operations.'
  },
];

// ============================================================================
// SEC3 2025 FINAL: ACCESS CONTROL DEEP PATTERNS (19% of all issues)
// ============================================================================

const SEC3_ACCESS_CONTROL_FINAL: typeof SEC3_BUSINESS_LOGIC_FINAL = [
  {
    id: 'SOL3596',
    name: 'Role Hierarchy - Missing Inheritance Check',
    severity: 'high',
    pattern: /role[\s\S]{0,100}(?:admin|operator|manager)[\s\S]{0,100}(?!inherits|hierarchy|parent_role)/,
    description: 'Role-based access without hierarchy verification.',
    recommendation: 'Implement role hierarchy with proper inheritance checks.'
  },
  {
    id: 'SOL3597',
    name: 'Capability Escalation - Self-Promotion',
    severity: 'critical',
    pattern: /set_role|grant_permission[\s\S]{0,100}(?!admin_only|require_admin|authorized_grantor)/,
    description: 'Role granting without proper authorization allows self-promotion.',
    recommendation: 'Only authorized administrators can grant elevated roles.'
  },
  {
    id: 'SOL3598',
    name: 'Emergency Mode - Insufficient Protection',
    severity: 'critical',
    pattern: /emergency[\s\S]{0,100}(?:pause|freeze|shutdown)[\s\S]{0,100}(?!multisig|timelock|guardian)/,
    description: 'Emergency controls without adequate protection.',
    recommendation: 'Use multisig or guardian council for emergency actions.'
  },
  {
    id: 'SOL3599',
    name: 'Delegate Authority - Revocation Missing',
    severity: 'high',
    pattern: /delegate[\s\S]{0,100}(?:authority|permission)[\s\S]{0,100}(?!revoke|expiration|time_limit)/,
    description: 'Delegated authority without revocation mechanism.',
    recommendation: 'Implement expiration or explicit revocation for delegations.'
  },
  {
    id: 'SOL3600',
    name: 'Ownership Transfer - Two-Step Missing',
    severity: 'high',
    pattern: /transfer_ownership|set_owner[\s\S]{0,150}(?!pending_owner|accept_ownership|two_step)/,
    description: 'Single-step ownership transfer risks permanent loss.',
    recommendation: 'Use two-step ownership transfer with acceptance.'
  },
  {
    id: 'SOL3601',
    name: 'Whitelist Bypass - Empty Check',
    severity: 'high',
    pattern: /whitelist[\s\S]{0,100}(?:contains|check)[\s\S]{0,100}(?!is_empty|len\s*>|non_empty)/,
    description: 'Empty whitelist may allow all or deny all unexpectedly.',
    recommendation: 'Handle empty whitelist case explicitly.'
  },
  {
    id: 'SOL3602',
    name: 'Time-Based Access - Clock Manipulation',
    severity: 'medium',
    pattern: /Clock::get[\s\S]{0,100}(?:start_time|end_time)[\s\S]{0,100}(?!slot_based|block_height)/,
    description: 'Time-based access using only clock can be manipulated.',
    recommendation: 'Use slot-based timing for manipulation resistance.'
  },
  {
    id: 'SOL3603',
    name: 'Cross-Program Authority - CPI Privilege',
    severity: 'critical',
    pattern: /invoke_signed[\s\S]{0,150}(?!caller_check|program_origin|authorized_caller)/,
    description: 'CPI with PDA signing without caller verification.',
    recommendation: 'Verify calling program is authorized before CPI signing.'
  },
  {
    id: 'SOL3604',
    name: 'Nonce Authority - Unauthorized Usage',
    severity: 'high',
    pattern: /nonce[\s\S]{0,100}(?:advance|authorize)[\s\S]{0,100}(?!authority_check|signer_check)/,
    description: 'Nonce account operations without authority verification.',
    recommendation: 'Verify nonce authority before operations.'
  },
  {
    id: 'SOL3605',
    name: 'Program Authority - Upgrade Without Timelock',
    severity: 'high',
    pattern: /upgrade_authority|SetAuthority[\s\S]{0,100}(?!timelock|delay|governance)/,
    description: 'Program upgrade authority without delay mechanism.',
    recommendation: 'Implement timelock for program upgrades.'
  },
];

// ============================================================================
// HELIUS 2024-2025 COMPLETE EXPLOIT HISTORY PATTERNS
// ============================================================================

const HELIUS_COMPLETE_HISTORY: typeof SEC3_BUSINESS_LOGIC_FINAL = [
  {
    id: 'SOL3606',
    name: 'Cypher Protocol ($1M) - Unsafe Deserialization',
    severity: 'critical',
    pattern: /try_from_slice|deserialize[\s\S]{0,100}(?!verify_discriminator|type_check|version_check)/,
    description: 'Account deserialization without type verification (Cypher exploit).',
    recommendation: 'Verify account discriminator and version before deserializing.'
  },
  {
    id: 'SOL3607',
    name: 'Marinade Finance ($0) - Stake Account Validation',
    severity: 'high',
    pattern: /stake_account|StakeState[\s\S]{0,100}(?!verify_delegation|validator_check)/,
    description: 'Stake account operations without proper validation.',
    recommendation: 'Verify stake account delegation and validator identity.'
  },
  {
    id: 'SOL3608',
    name: 'Tulip Protocol ($0) - Strategy Vault Confusion',
    severity: 'high',
    pattern: /strategy|vault[\s\S]{0,100}(?!strategy_check|vault_type|authorized_strategy)/,
    description: 'Vault strategy operations without type verification.',
    recommendation: 'Verify strategy type matches expected vault strategy.'
  },
  {
    id: 'SOL3609',
    name: 'Synthetify ($0) - Synthetic Asset Minting',
    severity: 'critical',
    pattern: /synthetic|mint_synthetic[\s\S]{0,100}(?!collateral_ratio|backing_check)/,
    description: 'Synthetic asset minting without collateral verification.',
    recommendation: 'Verify collateral ratio meets minimum requirements.'
  },
  {
    id: 'SOL3610',
    name: 'Jet Protocol ($0) - Interest Rate Model',
    severity: 'high',
    pattern: /interest_rate|utilization[\s\S]{0,100}(?!rate_bounds|max_rate|curve_check)/,
    description: 'Interest rate calculation without bounds checking.',
    recommendation: 'Enforce rate bounds and validate utilization curve.'
  },
  {
    id: 'SOL3611',
    name: 'Saber Protocol - LP Token Accounting',
    severity: 'high',
    pattern: /lp_token|pool_token[\s\S]{0,100}(?!supply_check|mint_verify)/,
    description: 'LP token operations without supply verification.',
    recommendation: 'Verify LP token supply matches pool reserves.'
  },
  {
    id: 'SOL3612',
    name: 'Mercurial Finance - Stable Swap Imbalance',
    severity: 'high',
    pattern: /stable_swap|curve[\s\S]{0,100}(?!imbalance_check|a_factor|amplification)/,
    description: 'Stable swap without imbalance protection.',
    recommendation: 'Check pool imbalance and amplification factor bounds.'
  },
  {
    id: 'SOL3613',
    name: 'Orca Whirlpool - Position Range Validation',
    severity: 'high',
    pattern: /tick_lower|tick_upper[\s\S]{0,100}(?!range_check|tick_spacing|valid_range)/,
    description: 'Concentrated liquidity position without range validation.',
    recommendation: 'Validate tick range adheres to pool tick spacing.'
  },
  {
    id: 'SOL3614',
    name: 'Lifinity - Proactive Market Making',
    severity: 'medium',
    pattern: /oracle[\s\S]{0,100}rebalance[\s\S]{0,100}(?!frequency_limit|cooldown)/,
    description: 'Oracle-based rebalancing without frequency limits.',
    recommendation: 'Limit rebalancing frequency to prevent manipulation.'
  },
  {
    id: 'SOL3615',
    name: 'Phoenix DEX - Order Matching Priority',
    severity: 'medium',
    pattern: /order[\s\S]{0,100}match[\s\S]{0,100}(?!price_time_priority|fifo)/,
    description: 'Order matching without proper priority enforcement.',
    recommendation: 'Enforce price-time priority for fair order matching.'
  },
];

// ============================================================================
// ARXIV RESEARCH PATTERNS (Academic Security Research)
// ============================================================================

const ARXIV_RESEARCH_PATTERNS: typeof SEC3_BUSINESS_LOGIC_FINAL = [
  {
    id: 'SOL3616',
    name: 'BPF Verifier Bypass - Unchecked Division',
    severity: 'critical',
    pattern: /\/[\s\S]{0,30}(?!checked_div|safe_div|zero_check)/,
    description: 'Division without zero check may bypass BPF verifier.',
    recommendation: 'Use checked_div or verify divisor != 0.'
  },
  {
    id: 'SOL3617',
    name: 'Stack Overflow - Deep Recursion',
    severity: 'high',
    pattern: /fn\s+\w+[\s\S]{0,100}self\.\w+\(|recursive/,
    description: 'Recursive function may cause stack overflow.',
    recommendation: 'Convert recursion to iteration or limit depth.'
  },
  {
    id: 'SOL3618',
    name: 'Compute Budget - Unbounded Loop',
    severity: 'high',
    pattern: /for[\s\S]{0,30}\.iter\(\)[\s\S]{0,50}(?!take\(|limit|max_iterations)/,
    description: 'Unbounded iteration may exceed compute budget.',
    recommendation: 'Limit iteration count or use pagination.'
  },
  {
    id: 'SOL3619',
    name: 'Account Reallocation - Data Loss',
    severity: 'high',
    pattern: /realloc[\s\S]{0,100}(?!copy|preserve|migrate)/,
    description: 'Account reallocation may lose existing data.',
    recommendation: 'Preserve existing data when reallocating accounts.'
  },
  {
    id: 'SOL3620',
    name: 'Sysvar Spoofing - Invalid Sysvar',
    severity: 'critical',
    pattern: /sysvar[\s\S]{0,50}(?!from_account_info|check_id|verify_sysvar)/,
    description: 'Sysvar account without proper validation can be spoofed.',
    recommendation: 'Use from_account_info to validate sysvar accounts.'
  },
  {
    id: 'SOL3621',
    name: 'Program Data - Version Mismatch',
    severity: 'medium',
    pattern: /program_data|ProgramData[\s\S]{0,100}(?!version_check|upgrade_authority)/,
    description: 'Program data access without version verification.',
    recommendation: 'Verify program data version and upgrade authority.'
  },
  {
    id: 'SOL3622',
    name: 'Loader Confusion - Wrong Loader',
    severity: 'high',
    pattern: /bpf_loader|loader[\s\S]{0,100}(?!loader_check|correct_loader)/,
    description: 'Program loader not verified may allow exploitation.',
    recommendation: 'Verify program uses expected loader (BPF Loader 2).'
  },
  {
    id: 'SOL3623',
    name: 'Account Rent - Exempt Status Change',
    severity: 'medium',
    pattern: /lamports[\s\S]{0,100}(?:sub|transfer)[\s\S]{0,100}(?!rent_exempt|minimum_balance)/,
    description: 'Lamport withdrawal may break rent-exempt status.',
    recommendation: 'Verify account remains rent-exempt after withdrawal.'
  },
  {
    id: 'SOL3624',
    name: 'Clock Sysvar - Slot Drift',
    severity: 'low',
    pattern: /Clock::get[\s\S]{0,50}unix_timestamp[\s\S]{0,50}(?!slot_for_time|drift_check)/,
    description: 'Clock sysvar timestamp may drift from actual time.',
    recommendation: 'Use slot-based timing for precision-critical operations.'
  },
  {
    id: 'SOL3625',
    name: 'Epoch Info - Stale Epoch Data',
    severity: 'low',
    pattern: /EpochInfo[\s\S]{0,100}(?!current_epoch|epoch_refresh)/,
    description: 'Epoch info may be stale across epoch boundaries.',
    recommendation: 'Refresh epoch info for epoch-sensitive operations.'
  },
];

// ============================================================================
// 2025-2026 EMERGING ATTACK VECTORS
// ============================================================================

const EMERGING_2026_PATTERNS: typeof SEC3_BUSINESS_LOGIC_FINAL = [
  {
    id: 'SOL3626',
    name: 'Token-2022 Transfer Hook - Reentrancy via Hook',
    severity: 'critical',
    pattern: /transfer_hook|TransferHook[\s\S]{0,100}(?!reenter_guard|hook_lock)/,
    description: 'Token-2022 transfer hooks enable reentrancy attacks.',
    recommendation: 'Implement reentrancy guard in transfer hook handlers.'
  },
  {
    id: 'SOL3627',
    name: 'Confidential Transfers - Amount Verification',
    severity: 'high',
    pattern: /confidential[\s\S]{0,100}transfer[\s\S]{0,100}(?!range_proof|verify_amount)/,
    description: 'Confidential transfer without amount range proof.',
    recommendation: 'Verify range proofs for confidential transfer amounts.'
  },
  {
    id: 'SOL3628',
    name: 'Lookup Tables - Stale Entry Reference',
    severity: 'medium',
    pattern: /AddressLookupTable[\s\S]{0,100}(?!deactivation_slot|is_active)/,
    description: 'Lookup table reference without freshness check.',
    recommendation: 'Verify lookup table is active and not deactivating.'
  },
  {
    id: 'SOL3629',
    name: 'Blink Actions - URL Parameter Injection',
    severity: 'high',
    pattern: /actions\.json|blink[\s\S]{0,100}(?!sanitize|validate_url|escape)/,
    description: 'Blink action URLs without sanitization.',
    recommendation: 'Sanitize and validate all Blink action parameters.'
  },
  {
    id: 'SOL3630',
    name: 'Compressed NFT - Invalid Leaf Update',
    severity: 'high',
    pattern: /cnft|compressed[\s\S]{0,100}update[\s\S]{0,100}(?!merkle_verify|proof_check)/,
    description: 'cNFT leaf update without proof verification.',
    recommendation: 'Verify merkle proof before updating compressed NFT.'
  },
  {
    id: 'SOL3631',
    name: 'Jito Bundle - MEV Sandwich Protection',
    severity: 'high',
    pattern: /swap|trade[\s\S]{0,200}(?!bundle|jito|private|mev_protect)/i,
    description: 'Trade without MEV protection is vulnerable to sandwich.',
    recommendation: 'Use Jito bundles or private transactions for trades.'
  },
  {
    id: 'SOL3632',
    name: 'Priority Fee - Griefing Attack',
    severity: 'medium',
    pattern: /compute_budget|priority_fee[\s\S]{0,100}(?!max_fee|fee_limit)/,
    description: 'Unbounded priority fees enable griefing attacks.',
    recommendation: 'Implement maximum priority fee limits.'
  },
  {
    id: 'SOL3633',
    name: 'Versioned Transactions - Legacy Fallback',
    severity: 'low',
    pattern: /Transaction[\s\S]{0,50}(?!versioned|message_version|v0)/,
    description: 'Legacy transaction format limits functionality.',
    recommendation: 'Use versioned transactions (v0) for new features.'
  },
  {
    id: 'SOL3634',
    name: 'Durable Nonce - Expiration Handling',
    severity: 'medium',
    pattern: /durable_nonce|nonce_account[\s\S]{0,100}(?!expiration|advance_nonce)/,
    description: 'Durable nonce without expiration handling.',
    recommendation: 'Handle nonce expiration and advancement properly.'
  },
  {
    id: 'SOL3635',
    name: 'Stake Pool - Validator Selection Manipulation',
    severity: 'high',
    pattern: /stake_pool[\s\S]{0,100}validator[\s\S]{0,100}(?!commission_check|performance)/,
    description: 'Stake pool validator selection without performance check.',
    recommendation: 'Verify validator commission and historical performance.'
  },
];

// ============================================================================
// ADDITIONAL DEEP PATTERNS (SOL3636-SOL3675)
// ============================================================================

const ADDITIONAL_DEEP_PATTERNS: typeof SEC3_BUSINESS_LOGIC_FINAL = [
  // Protocol-Specific Deep Patterns
  {
    id: 'SOL3636',
    name: 'Perpetuals - Funding Rate Manipulation',
    severity: 'critical',
    pattern: /funding_rate|mark_price[\s\S]{0,100}(?!twap|time_window|rate_cap)/,
    description: 'Perpetual funding rate without manipulation protection.',
    recommendation: 'Use TWAP for mark price and cap funding rate changes.'
  },
  {
    id: 'SOL3637',
    name: 'Options - Greeks Calculation',
    severity: 'high',
    pattern: /delta|gamma|theta[\s\S]{0,100}(?!iv_check|time_decay|precision)/,
    description: 'Options Greeks calculation without precision handling.',
    recommendation: 'Use high-precision math for Greeks calculations.'
  },
  {
    id: 'SOL3638',
    name: 'Lending - Utilization Spike',
    severity: 'high',
    pattern: /utilization[\s\S]{0,100}(?!rate_smoothing|gradual_change)/,
    description: 'Interest rate spikes on utilization changes.',
    recommendation: 'Implement rate smoothing to prevent sudden spikes.'
  },
  {
    id: 'SOL3639',
    name: 'AMM - Virtual Reserves Manipulation',
    severity: 'critical',
    pattern: /virtual_reserve|virtual_balance[\s\S]{0,100}(?!real_balance_check|bounds)/,
    description: 'Virtual reserves without real balance verification.',
    recommendation: 'Verify virtual reserves match real token balances.'
  },
  {
    id: 'SOL3640',
    name: 'Yield Aggregator - Strategy Exit Delay',
    severity: 'medium',
    pattern: /withdraw[\s\S]{0,100}strategy[\s\S]{0,100}(?!delay|timelock|queue)/,
    description: 'Strategy withdrawal without delay allows front-running.',
    recommendation: 'Implement withdrawal delay or queuing mechanism.'
  },
  {
    id: 'SOL3641',
    name: 'Governance - Flash Loan Voting',
    severity: 'critical',
    pattern: /vote|proposal[\s\S]{0,100}(?!snapshot|voting_escrow|time_lock)/,
    description: 'Governance voting vulnerable to flash loan attacks.',
    recommendation: 'Use voting escrow or snapshot-based voting power.'
  },
  {
    id: 'SOL3642',
    name: 'Insurance Fund - Underfunding',
    severity: 'high',
    pattern: /insurance[\s\S]{0,100}fund[\s\S]{0,100}(?!minimum_balance|coverage_ratio)/,
    description: 'Insurance fund without minimum coverage requirements.',
    recommendation: 'Maintain minimum insurance fund coverage ratio.'
  },
  {
    id: 'SOL3643',
    name: 'Liquidation - Cascade Prevention',
    severity: 'critical',
    pattern: /liquidat[\s\S]{0,100}(?!batch_limit|cascade_check|max_liquidation)/,
    description: 'Liquidation without cascade prevention.',
    recommendation: 'Limit liquidation batch size to prevent cascades.'
  },
  {
    id: 'SOL3644',
    name: 'Cross-Margin - Position Isolation',
    severity: 'high',
    pattern: /cross_margin|portfolio[\s\S]{0,100}(?!isolation|max_exposure)/,
    description: 'Cross-margin without position isolation limits.',
    recommendation: 'Implement per-asset exposure limits in cross-margin.'
  },
  {
    id: 'SOL3645',
    name: 'Fee Tier - Inconsistent Application',
    severity: 'medium',
    pattern: /fee_tier|fee_rate[\s\S]{0,100}(?!consistent|standardized)/,
    description: 'Fee tier application inconsistent across operations.',
    recommendation: 'Standardize fee tier calculation and application.'
  },
  // Wallet & Infrastructure Patterns
  {
    id: 'SOL3646',
    name: 'Wallet Adapter - Unsafe Connection',
    severity: 'high',
    pattern: /wallet[\s\S]{0,50}connect[\s\S]{0,100}(?!verify|standard_wallet)/i,
    description: 'Wallet connection without adapter verification.',
    recommendation: 'Use standard wallet adapter with verification.'
  },
  {
    id: 'SOL3647',
    name: 'RPC Endpoint - Untrusted Source',
    severity: 'medium',
    pattern: /rpc[\s\S]{0,50}(?:url|endpoint)[\s\S]{0,50}(?!trusted|allowlist)/i,
    description: 'RPC endpoint from untrusted source.',
    recommendation: 'Use trusted RPC endpoints from allowlist.'
  },
  {
    id: 'SOL3648',
    name: 'Transaction Simulation - Skip Preflight',
    severity: 'medium',
    pattern: /skip[_-]?preflight|preflightCommitment[\s\S]{0,30}null/i,
    description: 'Skipping preflight simulation hides errors.',
    recommendation: 'Always run preflight simulation for error detection.'
  },
  {
    id: 'SOL3649',
    name: 'Blockhash Caching - Stale Hash',
    severity: 'medium',
    pattern: /blockhash[\s\S]{0,100}cache[\s\S]{0,100}(?!refresh|ttl|expire)/,
    description: 'Cached blockhash may become stale.',
    recommendation: 'Implement blockhash caching with short TTL.'
  },
  {
    id: 'SOL3650',
    name: 'Commitment Level - Inconsistent',
    severity: 'low',
    pattern: /commitment[\s\S]{0,30}(?:processed|confirmed|finalized)[\s\S]{0,100}(?!consistent)/,
    description: 'Inconsistent commitment levels across operations.',
    recommendation: 'Use consistent commitment level (finalized for critical ops).'
  },
  // Additional Security Patterns
  {
    id: 'SOL3651',
    name: 'Seed Phrase - Exposure Risk',
    severity: 'critical',
    pattern: /mnemonic|seed_phrase|recovery[\s\S]{0,50}(?!encrypt|secure_store)/i,
    description: 'Seed phrase handling without encryption.',
    recommendation: 'Never store or transmit seed phrases unencrypted.'
  },
  {
    id: 'SOL3652',
    name: 'Private Key - Memory Exposure',
    severity: 'critical',
    pattern: /private_key|secret_key[\s\S]{0,100}(?!zeroize|secure_memory)/,
    description: 'Private key in memory without secure handling.',
    recommendation: 'Use zeroize and secure memory for private keys.'
  },
  {
    id: 'SOL3653',
    name: 'Transaction Logging - Sensitive Data',
    severity: 'high',
    pattern: /log|print|debug[\s\S]{0,50}(?:key|secret|private|password)/i,
    description: 'Logging may expose sensitive data.',
    recommendation: 'Never log sensitive data like keys or secrets.'
  },
  {
    id: 'SOL3654',
    name: 'Error Message - Information Leak',
    severity: 'low',
    pattern: /Error[\s\S]{0,100}(?:address|amount|balance|internal)/,
    description: 'Error messages may leak sensitive information.',
    recommendation: 'Use generic error messages for security-sensitive failures.'
  },
  {
    id: 'SOL3655',
    name: 'Randomness Source - Predictable',
    severity: 'critical',
    pattern: /random|rand[\s\S]{0,100}(?!vrf|chainlink|switchboard)/i,
    description: 'On-chain randomness is predictable.',
    recommendation: 'Use VRF (Switchboard, Chainlink) for secure randomness.'
  },
  // Final Protocol Patterns
  {
    id: 'SOL3656',
    name: 'Token Freeze - Authority Check',
    severity: 'high',
    pattern: /freeze[\s\S]{0,100}(?!authority_check|freeze_authority)/,
    description: 'Freeze operations without authority verification.',
    recommendation: 'Verify freeze authority before freeze operations.'
  },
  {
    id: 'SOL3657',
    name: 'Mint Authority - Centralization',
    severity: 'medium',
    pattern: /mint_authority[\s\S]{0,100}(?!multisig|dao|decentralized)/,
    description: 'Centralized mint authority is a security risk.',
    recommendation: 'Use multisig or DAO for mint authority.'
  },
  {
    id: 'SOL3658',
    name: 'Close Authority - Denial of Service',
    severity: 'high',
    pattern: /close_authority[\s\S]{0,100}(?!user_check|owner_only)/,
    description: 'Close authority may enable account DoS.',
    recommendation: 'Restrict close authority to account owner.'
  },
  {
    id: 'SOL3659',
    name: 'Permanent Delegate - Token Theft',
    severity: 'critical',
    pattern: /permanent_delegate|PermanentDelegate[\s\S]{0,100}(?!warn|user_consent)/,
    description: 'Permanent delegate enables token theft.',
    recommendation: 'Warn users about permanent delegate implications.'
  },
  {
    id: 'SOL3660',
    name: 'Non-Transferable - Bypass',
    severity: 'high',
    pattern: /non_transferable|NonTransferable[\s\S]{0,100}(?!burn_check|wrap_prevent)/,
    description: 'Non-transferable token may be bypassed via wrap.',
    recommendation: 'Prevent wrapping of non-transferable tokens.'
  },
  // Final Security Patterns
  {
    id: 'SOL3661',
    name: 'Account Data Injection - Untrusted Parsing',
    severity: 'critical',
    pattern: /try_from_slice[\s\S]{0,50}account\.data[\s\S]{0,50}(?!sanitize|validate)/,
    description: 'Account data parsed without sanitization.',
    recommendation: 'Validate and sanitize all account data before parsing.'
  },
  {
    id: 'SOL3662',
    name: 'Program Invocation - Unbounded Depth',
    severity: 'high',
    pattern: /invoke[\s\S]{0,100}invoke[\s\S]{0,100}(?!depth_check|max_depth)/,
    description: 'Nested CPI without depth limit.',
    recommendation: 'Track and limit CPI depth to prevent DoS.'
  },
  {
    id: 'SOL3663',
    name: 'Account Seed - Collision Attack',
    severity: 'high',
    pattern: /seeds[\s\S]{0,50}(?:&\[|vec!)[\s\S]{0,100}(?!unique|hash|nonce)/,
    description: 'PDA seeds may collide without unique component.',
    recommendation: 'Include unique identifier in PDA seeds.'
  },
  {
    id: 'SOL3664',
    name: 'Instruction Data - Size Limit',
    severity: 'medium',
    pattern: /instruction[\s\S]{0,50}data[\s\S]{0,100}(?!max_size|len_check)/,
    description: 'Instruction data without size validation.',
    recommendation: 'Validate instruction data size before processing.'
  },
  {
    id: 'SOL3665',
    name: 'Account List - Duplicate Entry',
    severity: 'high',
    pattern: /accounts[\s\S]{0,100}iter[\s\S]{0,100}(?!unique|dedup|no_duplicate)/,
    description: 'Account list may contain duplicates.',
    recommendation: 'Validate accounts list has no duplicates.'
  },
  // Final Patterns
  {
    id: 'SOL3666',
    name: 'Token Account - ATA Mismatch',
    severity: 'high',
    pattern: /get_associated_token_address[\s\S]{0,100}(?!verify|check_ata)/,
    description: 'ATA address not verified against expected.',
    recommendation: 'Verify ATA matches expected derivation.'
  },
  {
    id: 'SOL3667',
    name: 'Metadata Account - Tampering',
    severity: 'medium',
    pattern: /metadata[\s\S]{0,100}(?!verify_creator|verify_collection)/,
    description: 'NFT metadata without creator/collection verification.',
    recommendation: 'Verify metadata creator and collection.'
  },
  {
    id: 'SOL3668',
    name: 'Edition Account - Supply Overflow',
    severity: 'high',
    pattern: /edition[\s\S]{0,100}supply[\s\S]{0,100}(?!max_supply|supply_check)/,
    description: 'Edition supply modification without limit check.',
    recommendation: 'Enforce maximum supply for editions.'
  },
  {
    id: 'SOL3669',
    name: 'Master Edition - Unauthorized Print',
    severity: 'critical',
    pattern: /master_edition[\s\S]{0,100}print[\s\S]{0,100}(?!authority_check)/,
    description: 'Edition printing without authority verification.',
    recommendation: 'Verify print authority before creating editions.'
  },
  {
    id: 'SOL3670',
    name: 'Collection Verification - Bypass',
    severity: 'high',
    pattern: /collection[\s\S]{0,100}verified[\s\S]{0,100}(?!authority_check)/,
    description: 'Collection verification without authority check.',
    recommendation: 'Only collection authority can verify NFTs.'
  },
  {
    id: 'SOL3671',
    name: 'Creator Royalties - Enforcement',
    severity: 'medium',
    pattern: /creator[\s\S]{0,100}royalt[\s\S]{0,100}(?!pnft|enforce|programmable)/,
    description: 'Royalties not enforced (non-programmable NFT).',
    recommendation: 'Use programmable NFTs for enforced royalties.'
  },
  {
    id: 'SOL3672',
    name: 'Token Record - State Mismatch',
    severity: 'high',
    pattern: /TokenRecord[\s\S]{0,100}(?!state_check|valid_state)/,
    description: 'Token record state not validated.',
    recommendation: 'Verify token record state matches expected.'
  },
  {
    id: 'SOL3673',
    name: 'Rule Set - Authorization',
    severity: 'high',
    pattern: /rule_set|RuleSet[\s\S]{0,100}(?!authority|authorized_update)/,
    description: 'Rule set modification without authorization.',
    recommendation: 'Verify rule set authority before updates.'
  },
  {
    id: 'SOL3674',
    name: 'Delegate Role - Scope Creep',
    severity: 'medium',
    pattern: /delegate[\s\S]{0,100}role[\s\S]{0,100}(?!scope|limited|specific)/,
    description: 'Delegate role without scope limitation.',
    recommendation: 'Limit delegate role to specific operations.'
  },
  {
    id: 'SOL3675',
    name: 'Authorization Record - Expiration',
    severity: 'medium',
    pattern: /authorization[\s\S]{0,100}(?!expiration|time_limit|revoke)/,
    description: 'Authorization without expiration.',
    recommendation: 'Set expiration for all authorizations.'
  },
];

// Combine all patterns
const ALL_BATCH_75_PATTERNS = [
  ...SEC3_BUSINESS_LOGIC_FINAL,
  ...SEC3_INPUT_VALIDATION_FINAL,
  ...SEC3_ACCESS_CONTROL_FINAL,
  ...HELIUS_COMPLETE_HISTORY,
  ...ARXIV_RESEARCH_PATTERNS,
  ...EMERGING_2026_PATTERNS,
  ...ADDITIONAL_DEEP_PATTERNS,
];

/**
 * Run Batch 75 patterns against input
 */
export function checkBatch75Patterns(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  const fileName = input.path || input.rust?.filePath || 'unknown';
  
  if (!content) return findings;
  
  const lines = content.split('\n');
  
  for (const pattern of ALL_BATCH_75_PATTERNS) {
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
          location: { file: fileName, line: lineNum },
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

// Export pattern count
export const BATCH_75_PATTERN_COUNT = ALL_BATCH_75_PATTERNS.length;
