/**
 * SolShield Batch 85 Patterns
 * Added: Feb 6, 2026 3:30 AM
 * Source: Sec3 2025 Report Analysis + Solsec PoC Deep Dives + 2026 Emerging Threats
 * Patterns: SOL4501-SOL4600
 */

import type { ParsedRust } from '../parsers/rust.js';

interface Pattern {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  category: string;
  description: string;
  detector: RegExp;
  recommendation: string;
}

const batch85Patterns: Pattern[] = [
  // ===== SEC3 2025 BUSINESS LOGIC PATTERNS (38.5% of all vulns) =====
  {
    id: 'SOL4501',
    title: 'Protocol State Machine Violation',
    severity: 'critical',
    category: 'business-logic',
    description: 'State machine transitions not properly validated. Sec3 2025: Business logic is 38.5% of all vulnerabilities.',
    detector: /state\s*[=:]\s*(State|Status|Phase|Mode)\s*[^;]*(?!match|if|require)/i,
    recommendation: 'Use explicit state machine pattern with exhaustive match statements for all transitions.'
  },
  {
    id: 'SOL4502',
    title: 'Missing Pre-Condition Validation',
    severity: 'high',
    category: 'business-logic',
    description: 'Function lacks pre-condition checks before state mutation. Sec3 2025: Input validation is 25% of issues.',
    detector: /pub\s+fn\s+\w+\([^)]*\)\s*->\s*Result[^{]*\{\s*(?!require|assert|if|let\s+\w+\s*=\s*ctx\.accounts)/,
    recommendation: 'Add pre-condition validation at function entry before any state modifications.'
  },
  {
    id: 'SOL4503',
    title: 'Semantic Inconsistency Between Functions',
    severity: 'high',
    category: 'business-logic',
    description: 'Same calculation performed differently across functions (Solana Stake Pool vuln). May lead to arbitrage.',
    detector: /(stake|share|token|rate|price).*calc|calc.*(stake|share|token|rate|price)/i,
    recommendation: 'Extract common calculations to shared functions. Ensure semantic consistency across all entry points.'
  },
  {
    id: 'SOL4504',
    title: 'Protocol Invariant Not Enforced',
    severity: 'critical',
    category: 'business-logic',
    description: 'Core protocol invariants (total supply, TVL, ratios) not validated after mutations.',
    detector: /(total_supply|total_value|total_staked|tvl|invariant)\s*[+-=]/i,
    recommendation: 'Add invariant checks after every state mutation. Consider using invariant!() macro.'
  },
  {
    id: 'SOL4505',
    title: 'Unidirectional Flow Bypass',
    severity: 'high',
    category: 'business-logic',
    description: 'Protocol allows bidirectional operations where only one direction should be permitted.',
    detector: /(deposit|stake|lock)\s*\([^)]*\)|\.transfer\s*\(/i,
    recommendation: 'Enforce unidirectional flows with time locks or admin-only reversal mechanisms.'
  },
  
  // ===== COPE ROULETTE REVERTING TRANSACTION PATTERNS =====
  {
    id: 'SOL4506',
    title: 'Reverting Transaction Exploitation (Cope Roulette)',
    severity: 'critical',
    category: 'transaction-security',
    description: 'Vulnerable to reverting transaction attacks where attacker can observe outcome and revert unfavorable txns.',
    detector: /rand|random|rng|lottery|raffle|roulette|dice|flip|bet/i,
    recommendation: 'Use commit-reveal scheme or VRF (Verifiable Random Function). Never use on-chain randomness that can be front-run.'
  },
  {
    id: 'SOL4507',
    title: 'Outcome-Dependent Branching Exploitable',
    severity: 'high',
    category: 'transaction-security',
    description: 'Transaction outcome determines different paths that attacker can exploit by reverting.',
    detector: /if\s*\([^)]*\)\s*\{[^}]*revert|return\s+Err|panic!/,
    recommendation: 'Design atomic operations where partial completion is not beneficial to attacker.'
  },
  {
    id: 'SOL4508',
    title: 'Slot-Based Randomness Manipulation',
    severity: 'critical',
    category: 'randomness',
    description: 'Using slot hash or slot number for randomness. Validators can manipulate or attackers can predict.',
    detector: /slot_hashes|SlotHashes|Clock::get\(\)\.unwrap\(\)\.slot|current_slot/i,
    recommendation: 'Use Switchboard VRF or commit-reveal with user-provided entropy combined with block hash.'
  },
  
  // ===== PORT FINANCE MAX WITHDRAW BUG PATTERNS =====
  {
    id: 'SOL4509',
    title: 'Maximum Withdrawal Calculation Error',
    severity: 'critical',
    category: 'lending',
    description: 'Port Finance bug: max withdrawal calculations may allow draining more than entitled.',
    detector: /max_withdraw|calculate_max|available_to_withdraw|withdrawable/i,
    recommendation: 'Use conservative floor() for user withdrawals. Re-validate max after every partial withdrawal.'
  },
  {
    id: 'SOL4510',
    title: 'Collateral Factor Edge Case',
    severity: 'high',
    category: 'lending',
    description: 'Collateral factor calculations at boundaries (0%, 100%) may have unexpected behavior.',
    detector: /collateral_factor|loan_to_value|ltv|health_factor/i,
    recommendation: 'Test edge cases at 0%, 100%, and near-boundary values. Add explicit bounds checking.'
  },
  {
    id: 'SOL4511',
    title: 'Iterative Balance Reduction Exploit',
    severity: 'critical',
    category: 'lending',
    description: 'Neodyme lending bug: Repeated small withdrawals accumulate rounding errors draining protocol.',
    detector: /while.*withdraw|loop.*transfer|for.*amount/i,
    recommendation: 'Track cumulative withdrawal against original balance. Use checked math with floor for all reductions.'
  },
  
  // ===== JET PROTOCOL BREAK LOGIC BUG =====
  {
    id: 'SOL4512',
    title: 'Unintended Break Statement in Loop (Jet Bug)',
    severity: 'high',
    category: 'control-flow',
    description: 'Jet Protocol bug: break statement exits loop prematurely, skipping critical validations.',
    detector: /for\s+[^{]*\{[^}]*break[^}]*\}/,
    recommendation: 'Review all break/continue statements. Ensure loop invariants are maintained.'
  },
  {
    id: 'SOL4513',
    title: 'Early Return Skipping Cleanup',
    severity: 'medium',
    category: 'control-flow',
    description: 'Early return statements may skip necessary cleanup or state updates.',
    detector: /return\s+Ok\([^)]*\);[^}]*\}/,
    recommendation: 'Use RAII pattern or ensure cleanup runs regardless of return path.'
  },
  
  // ===== SEC3 ACCESS CONTROL PATTERNS (19% of vulns) =====
  {
    id: 'SOL4514',
    title: 'Authority Derivation Without Seeds',
    severity: 'critical',
    category: 'access-control',
    description: 'Authority derived from PDA without proper seeds, allowing impersonation.',
    detector: /authority|admin|owner|governance/i,
    recommendation: 'Derive authority PDAs with program_id + unique identifier seeds. Verify derivation on every call.'
  },
  {
    id: 'SOL4515',
    title: 'Privilege Escalation via Delegation Chain',
    severity: 'critical',
    category: 'access-control',
    description: 'Delegation chains can be exploited to escalate privileges. Wormhole signature chain vuln pattern.',
    detector: /delegate|proxy|forward|relay/i,
    recommendation: 'Validate entire delegation chain. Prevent circular delegations. Limit delegation depth.'
  },
  {
    id: 'SOL4516',
    title: 'Missing Role-Based Access Control',
    severity: 'high',
    category: 'access-control',
    description: 'Function accessible to all users when it should be role-restricted.',
    detector: /pub\s+fn\s+(admin|governance|emergency|upgrade|migrate|pause)/i,
    recommendation: 'Implement RBAC with explicit role checks. Use #[access_control] attribute in Anchor.'
  },
  {
    id: 'SOL4517',
    title: 'Authority Transfer Without Timelock',
    severity: 'high',
    category: 'access-control',
    description: 'Critical authority can be transferred instantly without delay for community review.',
    detector: /set_authority|transfer_authority|update_admin|change_owner/i,
    recommendation: 'Implement 2-step transfer with timelock. Emit events for community monitoring.'
  },
  
  // ===== SOLEND MALICIOUS LENDING MARKET PATTERN =====
  {
    id: 'SOL4518',
    title: 'Fake Lending Market Account (Solend Auth Bypass)',
    severity: 'critical',
    category: 'account-validation',
    description: 'Solend 2021: Attacker creates fake lending market passing it as legitimate to bypass auth checks.',
    detector: /lending_market|market_authority|reserve_authority/i,
    recommendation: 'Validate market account is derived from known program. Check all authority chains back to root.'
  },
  {
    id: 'SOL4519',
    title: 'Configurable Parameter Manipulation',
    severity: 'high',
    category: 'configuration',
    description: 'Protocol parameters (thresholds, rates, fees) can be manipulated without proper validation.',
    detector: /update_config|set_fee|set_rate|set_threshold|configure/i,
    recommendation: 'Add bounds checking for all configurable parameters. Use timelocks for critical changes.'
  },
  
  // ===== LP TOKEN ORACLE MANIPULATION (OtterSec $200M) =====
  {
    id: 'SOL4520',
    title: 'LP Token Oracle Manipulation ($200M Risk)',
    severity: 'critical',
    category: 'oracle',
    description: 'OtterSec finding: LP token prices can be manipulated by moving AMM reserves.',
    detector: /lp_token|pool_token|share_token|liquidity_token/i,
    recommendation: 'Use fair pricing formula: 2 * sqrt(reserve0 * reserve1) / totalSupply. Never use spot reserves.'
  },
  {
    id: 'SOL4521',
    title: 'Single-Block Price Manipulation',
    severity: 'critical',
    category: 'oracle',
    description: 'Using single-block price for collateral valuation. Can be manipulated within same block.',
    detector: /price\s*=|current_price|get_price/i,
    recommendation: 'Use TWAP with minimum window of 10+ minutes. Add price deviation bounds.'
  },
  {
    id: 'SOL4522',
    title: 'Missing Drift Oracle Guardrails',
    severity: 'high',
    category: 'oracle',
    description: 'Drift protocol uses oracle guardrails to prevent manipulation. Pattern for similar implementations.',
    detector: /oracle_price|pyth_price|switchboard/i,
    recommendation: 'Implement oracle guardrails: max deviation from TWAP, confidence intervals, staleness checks.'
  },
  
  // ===== SEC3 DATA INTEGRITY PATTERNS (8.9% of vulns) =====
  {
    id: 'SOL4523',
    title: 'Integer Truncation in Token Decimals',
    severity: 'high',
    category: 'arithmetic',
    description: 'Truncation when converting between tokens with different decimals.',
    detector: /decimals|10_u64\.pow|as\s+u64|as\s+u32/i,
    recommendation: 'Always handle decimal conversion explicitly. Use checked multiplication before division.'
  },
  {
    id: 'SOL4524',
    title: 'Rounding Direction Attack',
    severity: 'high',
    category: 'arithmetic',
    description: 'Neodyme $2.6B risk: Rounding in favor of users allows draining via repeated operations.',
    detector: /round|\.div|\/\s*\d+/i,
    recommendation: 'Always round against the user (floor for withdrawals, ceil for deposits).'
  },
  {
    id: 'SOL4525',
    title: 'Precision Loss in Rate Calculations',
    severity: 'medium',
    category: 'arithmetic',
    description: 'Interest rate or exchange rate calculations lose precision over time.',
    detector: /rate|interest|apy|apr|yield/i,
    recommendation: 'Use high-precision fixed-point math (e.g., U192). Accumulate rates multiplicatively.'
  },
  
  // ===== CASHIO ROOT OF TRUST PATTERNS =====
  {
    id: 'SOL4526',
    title: 'Missing Root of Trust (Cashio $52M)',
    severity: 'critical',
    category: 'account-validation',
    description: 'Cashio bug: Failed to validate account chain back to known root, allowing fake collateral.',
    detector: /collateral|backing|reserve|mint/i,
    recommendation: 'Establish clear root of trust. Validate entire account derivation chain. Use samczsun pattern.'
  },
  {
    id: 'SOL4527',
    title: 'Saber LP Token Validation Missing',
    severity: 'critical',
    category: 'account-validation',
    description: 'Cashio-specific: Missing validation of saber_swap.arrow mint field.',
    detector: /saber|arrow|lp_mint|pool_mint/i,
    recommendation: 'Validate all fields of nested account structures, not just top-level accounts.'
  },
  
  // ===== SEC3 DOS/LIVENESS PATTERNS (8.5% of vulns) =====
  {
    id: 'SOL4528',
    title: 'Unbounded Iteration DoS',
    severity: 'high',
    category: 'dos',
    description: 'Unbounded iteration over user-controlled data can exhaust compute budget.',
    detector: /for\s+\w+\s+in\s+\w+\.iter\(\)|\.iter\(\)\.enumerate\(\)/,
    recommendation: 'Add explicit bounds. Process in batches with continuation token.'
  },
  {
    id: 'SOL4529',
    title: 'Account Dust Attack',
    severity: 'medium',
    category: 'dos',
    description: 'Attacker creates many small accounts to bloat iteration or state.',
    detector: /accounts\.|remaining_accounts|\.len\(\)/i,
    recommendation: 'Require minimum account size. Charge creation fees. Limit total account count.'
  },
  {
    id: 'SOL4530',
    title: 'Compute Unit Exhaustion via Complex Calculation',
    severity: 'medium',
    category: 'dos',
    description: 'Complex calculations (sqrt, pow, log) can exhaust compute budget.',
    detector: /sqrt|pow|log|exp|isqrt/i,
    recommendation: 'Pre-compute expensive values. Use lookup tables. Profile compute usage.'
  },
  
  // ===== 2026 EMERGING THREAT PATTERNS =====
  {
    id: 'SOL4531',
    title: 'Simulation-Only Code Path',
    severity: 'high',
    category: 'simulation-bypass',
    description: 'Code that behaves differently in simulation vs execution. Used to hide malicious behavior.',
    detector: /is_simulation|simulate|preflight|skip_preflight/i,
    recommendation: 'Never branch on simulation detection. All code paths should be identical.'
  },
  {
    id: 'SOL4532',
    title: 'MEV-Extractable State Transition',
    severity: 'high',
    category: 'mev',
    description: 'State transition that can be profitably front-run by MEV searchers.',
    detector: /liquidate|swap|trade|exchange|settle/i,
    recommendation: 'Use Jito bundles for atomicity. Consider commit-reveal for sensitive operations.'
  },
  {
    id: 'SOL4533',
    title: 'Cross-Program State Dependency',
    severity: 'medium',
    category: 'composability',
    description: 'Relying on external program state that may change between transactions.',
    detector: /invoke|invoke_signed|cpi_context/i,
    recommendation: 'Validate external state is fresh. Use atomic operations where possible.'
  },
  
  // ===== WORMHOLE GUARDIAN SIGNATURE PATTERNS =====
  {
    id: 'SOL4534',
    title: 'Signature Verification Delegation Chain',
    severity: 'critical',
    category: 'signature',
    description: 'Wormhole bug: Delegated signature verification can be bypassed if chain is broken.',
    detector: /verify_signatures|guardian|quorum|multisig/i,
    recommendation: 'Validate signature verification chain end-to-end. Never trust intermediate verification.'
  },
  {
    id: 'SOL4535',
    title: 'Fake SignatureSet Account',
    severity: 'critical',
    category: 'account-validation',
    description: 'Wormhole pattern: Attacker creates fake SignatureSet account to bypass verification.',
    detector: /signature_set|sig_verify|secp256k1/i,
    recommendation: 'Derive SignatureSet PDA from message hash. Validate derivation on use.'
  },
  
  // ===== SYNTHETIFY DAO GOVERNANCE ATTACK =====
  {
    id: 'SOL4536',
    title: 'Inactive DAO Governance Takeover',
    severity: 'high',
    category: 'governance',
    description: 'Synthetify DAO: Low engagement allows attacker to pass malicious proposals unnoticed.',
    detector: /proposal|vote|quorum|governance/i,
    recommendation: 'Require minimum participation. Add notification systems. Implement veto council.'
  },
  {
    id: 'SOL4537',
    title: 'Multi-Proposal Smokescreen Attack',
    severity: 'high',
    category: 'governance',
    description: 'Attacker submits many benign proposals to hide malicious one.',
    detector: /create_proposal|submit_proposal|new_proposal/i,
    recommendation: 'Limit proposals per address. Require stake lock. Add mandatory review period.'
  },
  
  // ===== THUNDER TERMINAL MONGODB INJECTION =====
  {
    id: 'SOL4538',
    title: 'Third-Party Database Injection',
    severity: 'critical',
    category: 'infrastructure',
    description: 'Thunder Terminal: MongoDB connection URL leak allowed unauthorized access.',
    detector: /mongodb|database|connection_url|db_uri/i,
    recommendation: 'Never expose database credentials. Use managed secrets. Implement IP allowlisting.'
  },
  {
    id: 'SOL4539',
    title: 'External Service Credential Exposure',
    severity: 'critical',
    category: 'infrastructure',
    description: 'API keys or credentials for external services exposed in code or logs.',
    detector: /api_key|secret_key|access_token|bearer/i,
    recommendation: 'Use environment variables. Rotate credentials regularly. Audit access logs.'
  },
  
  // ===== INCINERATOR NFT ATTACK CHAIN =====
  {
    id: 'SOL4540',
    title: 'NFT Burn Validation Missing',
    severity: 'high',
    category: 'nft',
    description: 'Solens Incinerator: NFT burn operations can be exploited with crafted SPL token program.',
    detector: /burn|incinerate|destroy|close_account/i,
    recommendation: 'Validate token program is official SPL Token. Check mint authority.'
  },
  {
    id: 'SOL4541',
    title: 'Exploit Chain Combination',
    severity: 'critical',
    category: 'exploit-chain',
    description: 'Solens Royal Flush: Multiple small vulnerabilities chained for significant exploit.',
    detector: /remaining_accounts|ctx\.accounts|AccountInfo/i,
    recommendation: 'Consider exploit chaining during audits. Fix all issues regardless of individual severity.'
  },
  
  // ===== ADVANCED AUDIT PATTERNS =====
  {
    id: 'SOL4542',
    title: 'Unchecked Account Constraints Missing Documentation',
    severity: 'medium',
    category: 'anchor',
    description: 'Anchor requires UncheckedAccount to have /// CHECK documentation explaining safety.',
    detector: /UncheckedAccount[^/]*(?!\/\/\/\s*CHECK)/,
    recommendation: 'Add /// CHECK comment explaining why account is safe. Or use proper account type.'
  },
  {
    id: 'SOL4543',
    title: 'Zero Account Confusion',
    severity: 'high',
    category: 'anchor',
    description: 'Candy Machine bug: Using #[account(zero)] incorrectly vs #[account(init, zero)].',
    detector: /#\[account\(zero\)\]/,
    recommendation: 'Use #[account(init, zero)] for new accounts. Understand Anchor account lifecycle.'
  },
  {
    id: 'SOL4544',
    title: 'SPL Token Approval Lingering',
    severity: 'medium',
    category: 'token',
    description: 'Token approval not revoked after use, allowing future unauthorized transfers.',
    detector: /approve|set_authority.*delegate/i,
    recommendation: 'Revoke approvals immediately after use. Check approval balances in frontend.'
  },
  {
    id: 'SOL4545',
    title: 'Transaction Simulation Detection',
    severity: 'high',
    category: 'simulation-bypass',
    description: 'Opcodes research: Programs can detect simulation and behave differently.',
    detector: /recent_blockhash|Bank|simulate|preflight/i,
    recommendation: 'Audit for simulation detection. Test with randomized blockhashes.'
  },
  
  // ===== KUDELSKI OWNERSHIP CHECK PATTERNS =====
  {
    id: 'SOL4546',
    title: 'Missing Owner Check on Token Account',
    severity: 'critical',
    category: 'account-validation',
    description: 'Kudelski pattern: Token account owner not verified, allowing spoofed accounts.',
    detector: /token_account|TokenAccount|Account<.*Token>/i,
    recommendation: 'Verify token account owner matches expected program (Token Program or Token-2022).'
  },
  {
    id: 'SOL4547',
    title: 'Missing Data Length Validation',
    severity: 'high',
    category: 'account-validation',
    description: 'Account data length not checked before deserialization.',
    detector: /\.data\.borrow|try_from_slice|deserialize/i,
    recommendation: 'Check account data length matches expected struct size before deserialization.'
  },
  
  // ===== NEODYME COMMON PITFALLS =====
  {
    id: 'SOL4548',
    title: 'Account Confusion Type Mismatch',
    severity: 'critical',
    category: 'type-safety',
    description: 'Neodyme pitfall: Same account type used for different purposes enabling confusion.',
    detector: /AccountInfo|UncheckedAccount/,
    recommendation: 'Use Anchor typed accounts. Add 8-byte discriminator. Validate account type on use.'
  },
  {
    id: 'SOL4549',
    title: 'Invoke Signed Seeds Not Verified',
    severity: 'critical',
    category: 'cpi',
    description: 'Neodyme pitfall: invoke_signed seeds not properly constructed or verified.',
    detector: /invoke_signed|seeds\s*=|signer_seeds/i,
    recommendation: 'Derive seeds from known inputs. Verify PDA matches expected address.'
  },
  {
    id: 'SOL4550',
    title: 'Missing Signer Verification',
    severity: 'critical',
    category: 'access-control',
    description: 'Neodyme pitfall: Critical operation lacks signer check.',
    detector: /pub\s+fn\s+\w+[^}]*(?!\.is_signer|Signer<)/,
    recommendation: 'Add explicit signer checks. Use Anchor Signer<> type for required signers.'
  },
  
  // ===== DRIFT ORACLE GUARDRAILS =====
  {
    id: 'SOL4551',
    title: 'Missing Oracle Confidence Check',
    severity: 'high',
    category: 'oracle',
    description: 'Drift pattern: Oracle confidence interval not checked, may accept stale/wide prices.',
    detector: /oracle|pyth|switchboard|price_feed/i,
    recommendation: 'Check oracle confidence is within acceptable bounds. Reject wide spreads.'
  },
  {
    id: 'SOL4552',
    title: 'Oracle Staleness Not Checked',
    severity: 'high',
    category: 'oracle',
    description: 'Using oracle price without verifying freshness.',
    detector: /publish_time|update_time|last_update|timestamp/i,
    recommendation: 'Verify oracle update timestamp is within acceptable staleness window.'
  },
  {
    id: 'SOL4553',
    title: 'Missing TWAP Oracle Fallback',
    severity: 'medium',
    category: 'oracle',
    description: 'No fallback when primary oracle fails or provides invalid data.',
    detector: /get_price|fetch_price|oracle_price/i,
    recommendation: 'Implement fallback oracle. Use circuit breaker on oracle failure.'
  },
  
  // ===== 2026 TOKEN-2022 PATTERNS =====
  {
    id: 'SOL4554',
    title: 'Token-2022 Transfer Hook Not Validated',
    severity: 'high',
    category: 'token-2022',
    description: 'Token-2022 transfer hooks can execute arbitrary code during transfers.',
    detector: /transfer_hook|TransferHook|hook_program/i,
    recommendation: 'Validate transfer hook program is trusted. Account for hook compute usage.'
  },
  {
    id: 'SOL4555',
    title: 'Token-2022 Confidential Transfer Misuse',
    severity: 'medium',
    category: 'token-2022',
    description: 'Confidential transfers require special handling for compliance.',
    detector: /confidential_transfer|ConfidentialTransfer|encrypted_balance/i,
    recommendation: 'Understand confidential transfer requirements. Implement proper decryption.'
  },
  {
    id: 'SOL4556',
    title: 'Token-2022 Interest Bearing Token Calculation',
    severity: 'medium',
    category: 'token-2022',
    description: 'Interest-bearing tokens require time-adjusted balance calculations.',
    detector: /interest_bearing|InterestBearing|accrued_interest/i,
    recommendation: 'Use amount_to_ui_amount for display. Account for interest in all calculations.'
  },
  
  // ===== ZELLIC ANCHOR VULNERABILITY PATTERNS =====
  {
    id: 'SOL4557',
    title: 'Anchor Init If Needed Race Condition',
    severity: 'high',
    category: 'anchor',
    description: 'Zellic: init_if_needed can cause race conditions in concurrent initialization.',
    detector: /init_if_needed/,
    recommendation: 'Prefer separate init instruction. Add explicit initialization state tracking.'
  },
  {
    id: 'SOL4558',
    title: 'Anchor Close Account Destination',
    severity: 'high',
    category: 'anchor',
    description: 'Zellic: Closing account to wrong destination can lose funds.',
    detector: /#\[account\([^)]*close\s*=/,
    recommendation: 'Verify close destination is protocol treasury or original depositor.'
  },
  {
    id: 'SOL4559',
    title: 'Anchor Constraint Order Dependency',
    severity: 'medium',
    category: 'anchor',
    description: 'Zellic: Anchor constraint evaluation order may cause unexpected behavior.',
    detector: /#\[account\([^)]*constraint\s*=/,
    recommendation: 'Order constraints from least to most expensive. Test constraint combinations.'
  },
  {
    id: 'SOL4560',
    title: 'Anchor Bump Not Canonical',
    severity: 'medium',
    category: 'anchor',
    description: 'Using non-canonical bump allows multiple valid PDAs for same seeds.',
    detector: /bump\s*=\s*[a-zA-Z]/,
    recommendation: 'Store and use canonical bump. Use find_program_address once at creation.'
  },
  
  // ===== VIPERS VALIDATION PATTERNS =====
  {
    id: 'SOL4561',
    title: 'Vipers Assert Keys Equal Missing',
    severity: 'high',
    category: 'validation',
    description: 'Saber Vipers pattern: Key comparison should use constant-time comparison.',
    detector: /==\s*ctx\.accounts\.\w+\.key\(\)|\.key\(\)\s*==/,
    recommendation: 'Use vipers::assert_keys_eq! for secure key comparison.'
  },
  {
    id: 'SOL4562',
    title: 'Vipers Unwrap or Err Pattern',
    severity: 'medium',
    category: 'error-handling',
    description: 'Using unwrap() instead of proper error handling.',
    detector: /\.unwrap\(\)(?!\s*;?\s*\/\/\s*safe)/,
    recommendation: 'Use vipers::unwrap_or_err! or proper Result propagation.'
  },
  
  // ===== ADDITIONAL SEC3 AUDIT METHODOLOGY PATTERNS =====
  {
    id: 'SOL4563',
    title: 'Input Account Not In Expected Program',
    severity: 'critical',
    category: 'account-validation',
    description: 'Sec3 methodology: Account owner not verified to be expected program.',
    detector: /AccountInfo|UncheckedAccount/,
    recommendation: 'Verify account.owner == expected_program_id for all input accounts.'
  },
  {
    id: 'SOL4564',
    title: 'Writable Account Not Needed',
    severity: 'low',
    category: 'optimization',
    description: 'Account marked writable but not modified, wasting compute.',
    detector: /#\[account\([^)]*mut[^)]*\)]/,
    recommendation: 'Remove mut from accounts that are only read. Reduces transaction size.'
  },
  {
    id: 'SOL4565',
    title: 'Remaining Accounts Not Validated',
    severity: 'high',
    category: 'account-validation',
    description: 'ctx.remaining_accounts used without proper validation.',
    detector: /remaining_accounts/,
    recommendation: 'Validate each remaining account: owner, type, derivation, and permissions.'
  },
  
  // ===== PENETRATION TESTING PATTERNS =====
  {
    id: 'SOL4566',
    title: 'PoC Framework Entry Point',
    severity: 'info',
    category: 'testing',
    description: 'Neodyme PoC framework pattern for penetration testing.',
    detector: /Environment|LocalEnvironment|create_accounts_rent_exempt/i,
    recommendation: 'Use Neodyme PoC framework for security testing. Document all test cases.'
  },
  {
    id: 'SOL4567',
    title: 'Fuzzing Target Function',
    severity: 'info',
    category: 'testing',
    description: 'Ackee Trident fuzzing target pattern.',
    detector: /fuzz_target|arbitrary|FuzzData/i,
    recommendation: 'Implement Trident fuzzing for critical functions. Cover edge cases.'
  },
  
  // ===== SOLANA 2026 RUNTIME PATTERNS =====
  {
    id: 'SOL4568',
    title: 'Compute Budget Not Requested',
    severity: 'low',
    category: 'compute',
    description: 'Complex transaction may exceed default compute budget.',
    detector: /invoke|cpi|cross_program/i,
    recommendation: 'Request appropriate compute budget. Profile compute usage in tests.'
  },
  {
    id: 'SOL4569',
    title: 'Account Reallocation Without Rent Check',
    severity: 'medium',
    category: 'rent',
    description: 'Reallocating account without ensuring rent exemption.',
    detector: /realloc|account_info\.realloc/i,
    recommendation: 'Verify account remains rent-exempt after reallocation. Transfer SOL if needed.'
  },
  {
    id: 'SOL4570',
    title: 'Durable Nonce Not Validated',
    severity: 'high',
    category: 'nonce',
    description: 'Durable nonce transaction without proper nonce account validation.',
    detector: /durable_nonce|nonce_account|AdvanceNonceAccount/i,
    recommendation: 'Validate nonce authority. Check nonce state before use.'
  },
  
  // ===== FINAL BATCH: COMPREHENSIVE PATTERNS =====
  {
    id: 'SOL4571',
    title: 'Flash Loan Re-entrancy via CPI',
    severity: 'critical',
    category: 'reentrancy',
    description: 'Flash loan callback can re-enter protocol via CPI.',
    detector: /flash_loan|callback|on_flash_loan/i,
    recommendation: 'Use re-entrancy guard. Lock state before flash loan. Validate callback caller.'
  },
  {
    id: 'SOL4572',
    title: 'Cross-Margin Liquidation Cascade',
    severity: 'high',
    category: 'defi',
    description: 'Cross-margin position liquidation can cascade to other positions.',
    detector: /cross_margin|margin_account|liquidation/i,
    recommendation: 'Implement circuit breakers. Limit cascade depth. Use isolated margins for risky assets.'
  },
  {
    id: 'SOL4573',
    title: 'Vault Share Inflation Attack',
    severity: 'critical',
    category: 'vault',
    description: 'First depositor can inflate share price to steal from subsequent depositors.',
    detector: /vault|share|deposit.*mint|withdraw.*burn/i,
    recommendation: 'Seed vault with initial deposit. Use dead shares pattern. Minimum deposit amount.'
  },
  {
    id: 'SOL4574',
    title: 'Staking Reward Manipulation',
    severity: 'high',
    category: 'staking',
    description: 'Reward calculation can be manipulated by timing stake/unstake.',
    detector: /reward|stake|epoch|claim_rewards/i,
    recommendation: 'Lock staking for minimum period. Use weighted average duration.'
  },
  {
    id: 'SOL4575',
    title: 'Bridge Message Replay',
    severity: 'critical',
    category: 'bridge',
    description: 'Cross-chain message can be replayed on same or different chain.',
    detector: /bridge|vaa|message|cross_chain/i,
    recommendation: 'Include chain ID in message. Mark messages as processed. Validate sequence numbers.'
  },
  {
    id: 'SOL4576',
    title: 'AMM Constant Product Invariant Violation',
    severity: 'critical',
    category: 'amm',
    description: 'AMM operation violates x*y=k invariant.',
    detector: /constant_product|x_mul_y|k_invariant|swap/i,
    recommendation: 'Verify invariant after every swap. Add tolerance for rounding only.'
  },
  {
    id: 'SOL4577',
    title: 'Lending Protocol Utilization Cliff',
    severity: 'high',
    category: 'lending',
    description: 'Interest rate spike at high utilization can cause liquidation cascade.',
    detector: /utilization|interest_rate|borrow_rate/i,
    recommendation: 'Use gradual interest rate curves. Add utilization-based borrow limits.'
  },
  {
    id: 'SOL4578',
    title: 'NFT Royalty Bypass',
    severity: 'medium',
    category: 'nft',
    description: 'Metaplex royalty enforcement can be bypassed by direct transfer.',
    detector: /royalty|creator_fee|seller_fee/i,
    recommendation: 'Use Metaplex royalty enforcement. Validate in marketplace contracts.'
  },
  {
    id: 'SOL4579',
    title: 'Governance Proposal Spam DoS',
    severity: 'medium',
    category: 'governance',
    description: 'Unlimited proposals can DoS governance by overwhelming voters.',
    detector: /create_proposal|proposal_count/i,
    recommendation: 'Require proposal deposit. Limit active proposals per user. Add cooldown.'
  },
  {
    id: 'SOL4580',
    title: 'Token Decimal Mismatch in Multi-Token Operation',
    severity: 'high',
    category: 'token',
    description: 'Operations involving multiple tokens with different decimals.',
    detector: /token_a.*token_b|decimals.*decimals|mint_a.*mint_b/i,
    recommendation: 'Normalize all amounts to common base before calculation. Validate decimals.'
  },
  {
    id: 'SOL4581',
    title: 'Program Upgrade Backdoor',
    severity: 'critical',
    category: 'upgrade',
    description: 'Upgradeable program with single-key upgrade authority.',
    detector: /upgrade_authority|BpfLoaderUpgradeable|set_upgrade_authority/i,
    recommendation: 'Use multisig for upgrade authority. Add timelock. Consider immutability.'
  },
  {
    id: 'SOL4582',
    title: 'Event Log Manipulation',
    severity: 'low',
    category: 'events',
    description: 'Event logs can be manipulated or missing, affecting indexers.',
    detector: /emit!|msg!|sol_log/i,
    recommendation: 'Emit events for all state changes. Include relevant data for reconstruction.'
  },
  {
    id: 'SOL4583',
    title: 'Timestamp Dependency for Critical Logic',
    severity: 'medium',
    category: 'time',
    description: 'Using Clock::get() timestamp for critical business logic.',
    detector: /Clock::get|unix_timestamp|current_time/i,
    recommendation: 'Use slots for relative time. Account for timestamp drift. Avoid time-critical thresholds.'
  },
  {
    id: 'SOL4584',
    title: 'PDA Authority Mismatch',
    severity: 'critical',
    category: 'pda',
    description: 'PDA derived with different seeds than expected authority.',
    detector: /seeds|find_program_address|create_program_address/i,
    recommendation: 'Document PDA derivation. Verify seeds match expected pattern. Add seed validation.'
  },
  {
    id: 'SOL4585',
    title: 'Batch Operation Partial Failure',
    severity: 'medium',
    category: 'atomicity',
    description: 'Batch operation can partially fail leaving inconsistent state.',
    detector: /batch|bulk|multiple|for.*in.*iter/i,
    recommendation: 'Make batches atomic. Track progress for retry. Validate pre-conditions for all items.'
  },
  {
    id: 'SOL4586',
    title: 'Priority Fee Griefing',
    severity: 'medium',
    category: 'mev',
    description: 'Attacker can grief by submitting higher priority fee to block others.',
    detector: /priority_fee|compute_unit_price/i,
    recommendation: 'Design for eventual execution. Use time-weighted operations. Add deadline checks.'
  },
  {
    id: 'SOL4587',
    title: 'Account Data Truncation',
    severity: 'high',
    category: 'serialization',
    description: 'Serialized data larger than account allocation causes truncation.',
    detector: /serialize|borsh|pack/i,
    recommendation: 'Calculate exact serialization size. Check capacity before write. Use realloc if needed.'
  },
  {
    id: 'SOL4588',
    title: 'Zero Amount Transfer Allowed',
    severity: 'low',
    category: 'validation',
    description: 'Zero amount transfers waste compute and may have unintended effects.',
    detector: /transfer.*amount|amount.*transfer/i,
    recommendation: 'Reject zero amount transfers. Add require!(amount > 0) check.'
  },
  {
    id: 'SOL4589',
    title: 'Self-Transfer Handling',
    severity: 'medium',
    category: 'validation',
    description: 'Transfer from account to itself may have unexpected behavior.',
    detector: /from.*to|source.*destination/i,
    recommendation: 'Check from != to before transfer. Handle self-transfers explicitly.'
  },
  {
    id: 'SOL4590',
    title: 'Account Close Order Dependency',
    severity: 'high',
    category: 'close',
    description: 'Closing accounts in wrong order can leave orphaned state.',
    detector: /close|close_account|AccountClose/i,
    recommendation: 'Close child accounts before parent. Validate no remaining references.'
  },
  {
    id: 'SOL4591',
    title: 'CPI Return Data Not Checked',
    severity: 'medium',
    category: 'cpi',
    description: 'Return data from CPI not validated.',
    detector: /invoke|cpi.*return|get_return_data/i,
    recommendation: 'Check CPI return data. Validate expected response format.'
  },
  {
    id: 'SOL4592',
    title: 'Lookup Table Manipulation',
    severity: 'high',
    category: 'versioned-tx',
    description: 'Address lookup table can be modified after transaction creation.',
    detector: /lookup_table|AddressLookupTable|LookupTableAccount/i,
    recommendation: 'Validate lookup table state. Use recent lookup table for time-sensitive txns.'
  },
  {
    id: 'SOL4593',
    title: 'Token Freeze Authority Active',
    severity: 'info',
    category: 'token',
    description: 'Token has active freeze authority that could be abused.',
    detector: /freeze_authority|FreezeAccount|can_freeze/i,
    recommendation: 'Document freeze authority policy. Consider transferring to null for immutability.'
  },
  {
    id: 'SOL4594',
    title: 'Instruction Data Length Not Checked',
    severity: 'high',
    category: 'input-validation',
    description: 'Instruction data length not validated before parsing.',
    detector: /instruction_data|data\.len\(\)/i,
    recommendation: 'Check instruction data length matches expected format before deserialization.'
  },
  {
    id: 'SOL4595',
    title: 'Cross-Instruction State Assumption',
    severity: 'medium',
    category: 'atomicity',
    description: 'Assuming state from previous instruction in same transaction.',
    detector: /instructions_sysvar|load_instruction_at|get_instruction_relative/i,
    recommendation: 'Re-validate state at each instruction. Do not assume previous instruction success.'
  },
  {
    id: 'SOL4596',
    title: 'Memo Program Injection',
    severity: 'low',
    category: 'memo',
    description: 'Memo content not validated, could contain malicious data.',
    detector: /memo|MemoProgram|Memo\s/i,
    recommendation: 'Do not process memo content as code. Treat as untrusted string.'
  },
  {
    id: 'SOL4597',
    title: 'Associated Token Account Creation Race',
    severity: 'medium',
    category: 'ata',
    description: 'ATA creation can fail if concurrent creation by another party.',
    detector: /get_associated_token_address|create_associated_token_account/i,
    recommendation: 'Use create_if_needed pattern. Handle AlreadyInUse error gracefully.'
  },
  {
    id: 'SOL4598',
    title: 'System Program Invoke Confusion',
    severity: 'high',
    category: 'cpi',
    description: 'System program invocation with wrong accounts.',
    detector: /system_program::transfer|SystemInstruction|system_instruction/i,
    recommendation: 'Validate system program ID. Check from/to accounts match expected.'
  },
  {
    id: 'SOL4599',
    title: 'Rent Exemption Calculation Stale',
    severity: 'low',
    category: 'rent',
    description: 'Using hardcoded rent values instead of querying sysvar.',
    detector: /LAMPORTS_PER_SOL.*\/\s*\d+|minimum_balance/i,
    recommendation: 'Query Rent sysvar for current exemption. Do not hardcode rent values.'
  },
  {
    id: 'SOL4600',
    title: 'Protocol Fee Extraction Vulnerability',
    severity: 'high',
    category: 'fees',
    description: 'Fee calculation or distribution can be manipulated.',
    detector: /protocol_fee|treasury_fee|fee_rate|collect_fee/i,
    recommendation: 'Validate fee destinations. Cap fee rates. Use immutable fee parameters where possible.'
  }
];

export function checkBatch85Patterns(parsed: ParsedRust): Array<{ id: string; title: string; severity: string; category: string; description: string; recommendation: string; line: number }> {
  const findings: Array<{ id: string; title: string; severity: string; category: string; description: string; recommendation: string; line: number }> = [];
  
  const lines = parsed.content.split('\n');
  
  for (const pattern of batch85Patterns) {
    for (let i = 0; i < lines.length; i++) {
      if (pattern.detector.test(lines[i])) {
        findings.push({
          id: pattern.id,
          title: pattern.title,
          severity: pattern.severity,
          category: pattern.category,
          description: pattern.description,
          recommendation: pattern.recommendation,
          line: i + 1
        });
      }
    }
  }
  
  return findings;
}

export { batch85Patterns };
