/**
 * SolGuard Batch 66 - Advanced Exploit Patterns & Protocol Security
 * SOL2951-SOL3050 (100 patterns)
 * 
 * Sources:
 * - Ackee Blockchain Crema Finance Analysis
 * - CertiK Solana Security Reports
 * - arXiv:2504.07419 Solana Vulnerabilities
 * - Sec3 2025 1,669 Vulnerability Analysis
 * - Real-World PoC Frameworks
 * 
 * Created: Feb 5, 2026 8:00 PM CST
 */

import type { PatternInput, Finding } from './index.js';

// ============================================================================
// Crema Finance CLMM Deep Dive ($8.8M, July 2022)
// ============================================================================

const SOL2951_FAKE_TICK_ACCOUNT_CREATION = {
  id: 'SOL2951',
  title: 'CLMM Fake Tick Account Creation',
  severity: 'critical' as const,
  description: 'Attacker created fake tick account mimicking real tick structure. Crema Finance lost $8.8M by circumventing owner checks.',
  pattern: /tick.*account|tick_lower|tick_upper|tick.*state/i,
  antiPattern: /owner.*==.*program|has_one.*tick|tick.*verified/i,
  recommendation: 'Verify tick accounts are owned by expected program. Use Anchor has_one constraints. Check tick address derivation.'
};

const SOL2952_TICK_OWNER_CHECK_BYPASS = {
  id: 'SOL2952',
  title: 'Tick Account Owner Check Bypass',
  severity: 'critical' as const,
  description: 'Writing initialized tick address into fake account bypassed owner verification. Critical CLMM vulnerability.',
  pattern: /tick.*owner|verify.*tick|check.*tick.*account/i,
  antiPattern: /strict.*owner|pda.*derivation|seed.*verify/i,
  recommendation: 'Derive tick addresses from PDAs with verified seeds. Never trust user-provided tick accounts without full validation.'
};

const SOL2953_FEE_ACCUMULATOR_MANIPULATION = {
  id: 'SOL2953',
  title: 'CLMM Fee Accumulator Manipulation',
  severity: 'critical' as const,
  description: 'Replacing authentic fee data with faked values allows claiming massive fees. Core Crema exploit mechanism.',
  pattern: /fee.*accumulator|fee.*growth|accumulated.*fees/i,
  antiPattern: /fee.*integrity|verify.*fee.*data|fee.*calculation/i,
  recommendation: 'Calculate fees based on verified tick data only. Implement fee accumulator integrity checks.'
};

const SOL2954_FLASH_LOAN_FEE_CLAIM = {
  id: 'SOL2954',
  title: 'Flash Loan Amplified Fee Claim',
  severity: 'critical' as const,
  description: 'Using flash loans to add liquidity, manipulate fees, then claim and repay in single transaction.',
  pattern: /flash.*loan|flashloan|borrow.*repay/i,
  antiPattern: /flash.*loan.*guard|atomic.*check|loan.*used.*flag/i,
  recommendation: 'Track flash loan usage. Prevent fee claims in same transaction as flash loan. Add claim cooldowns.'
};

// ============================================================================
// Account Ownership & Type Verification
// ============================================================================

const SOL2955_ACCOUNTINFO_OWNER_MISSING = {
  id: 'SOL2955',
  title: 'AccountInfo Owner Verification Missing',
  severity: 'critical' as const,
  description: 'AccountInfo without owner check allows any program to provide malicious accounts.',
  pattern: /AccountInfo|account_info|remaining_accounts/i,
  antiPattern: /owner\s*==|owner\.eq|check.*owner|owner.*key/i,
  recommendation: 'Always verify account.owner == expected_program_id. Use Anchor Account<> types when possible.'
};

const SOL2956_DISCRIMINATOR_COLLISION = {
  id: 'SOL2956',
  title: 'Account Discriminator Hash Collision',
  severity: 'high' as const,
  description: 'Similar account names may produce colliding 8-byte discriminators, enabling type confusion.',
  pattern: /discriminator|account.*type|#\[account\]/i,
  antiPattern: /unique.*discriminator|explicit.*discriminator/i,
  recommendation: 'Use explicit discriminators. Avoid similar account names. Verify discriminator uniqueness.'
};

const SOL2957_ACCOUNT_DATA_RACE = {
  id: 'SOL2957',
  title: 'Account Data Race Condition',
  severity: 'high' as const,
  description: 'Reading account data, performing CPI, then using stale data can cause inconsistencies.',
  pattern: /data\.borrow|borrow_mut|account\.data/i,
  antiPattern: /reload|refresh|re.*fetch/i,
  recommendation: 'Re-read account data after CPI calls. Never cache account data across CPI boundaries.'
};

// ============================================================================
// PDA & Seed Security
// ============================================================================

const SOL2958_USER_CONTROLLED_SEEDS = {
  id: 'SOL2958',
  title: 'User-Controlled PDA Seeds Without Validation',
  severity: 'critical' as const,
  description: 'Allowing arbitrary user input in PDA seeds enables accessing unintended accounts.',
  pattern: /find_program_address|create_program_address|seeds.*user/i,
  antiPattern: /validate.*seed|seed.*whitelist|known.*seeds/i,
  recommendation: 'Validate all seed inputs. Use fixed/known seeds where possible. Whitelist allowed seed values.'
};

const SOL2959_BUMP_SEED_INJECTION = {
  id: 'SOL2959',
  title: 'Bump Seed Injection Attack',
  severity: 'high' as const,
  description: 'Accepting user-provided bump seeds instead of canonical bumps can reference wrong accounts.',
  pattern: /bump|canonical_bump|find_program_address/i,
  antiPattern: /find.*bump|canonical|bump.*seed.*verified/i,
  recommendation: 'Always use canonical bump from find_program_address. Never accept user-provided bumps.'
};

const SOL2960_SEED_LENGTH_MANIPULATION = {
  id: 'SOL2960',
  title: 'Variable Seed Length Manipulation',
  severity: 'medium' as const,
  description: 'Variable-length seeds can collide. ["ab", "c"] and ["a", "bc"] may hash to same PDA.',
  pattern: /seeds.*=.*\[|push.*seed|seed.*vec/i,
  antiPattern: /fixed.*length.*seed|delimiter|seed.*separator/i,
  recommendation: 'Use fixed-length seeds or include length delimiters. Avoid concatenating variable-length strings.'
};

// ============================================================================
// CPI Security Deep Dive
// ============================================================================

const SOL2961_UNCHECKED_CPI_PROGRAM = {
  id: 'SOL2961',
  title: 'Unchecked CPI Target Program',
  severity: 'critical' as const,
  description: 'CPI to user-provided program ID allows calling arbitrary malicious programs.',
  pattern: /invoke|invoke_signed|CpiContext/i,
  antiPattern: /program_id\s*==|verify.*program|known.*program/i,
  recommendation: 'Verify CPI target is expected program. Use Anchor Program<> types. Hardcode trusted program IDs.'
};

const SOL2962_CPI_RETURN_DATA_SPOOFING = {
  id: 'SOL2962',
  title: 'CPI Return Data Spoofing',
  severity: 'high' as const,
  description: 'Malicious programs can return fake data via CPI. Return data must be validated.',
  pattern: /get_return_data|return_data|cpi.*return/i,
  antiPattern: /verify.*return|validate.*response|trusted.*program/i,
  recommendation: 'Only trust return data from verified programs. Validate return data structure and values.'
};

const SOL2963_CPI_ACCOUNT_REORDERING = {
  id: 'SOL2963',
  title: 'CPI Account Array Reordering',
  severity: 'high' as const,
  description: 'Incorrect account ordering in CPI can cause funds to go to wrong destinations.',
  pattern: /accounts.*=.*\[|AccountMeta|account.*infos/i,
  antiPattern: /named.*accounts|verify.*order|anchor.*context/i,
  recommendation: 'Use named accounts (Anchor). Verify account ordering matches target program expectations.'
};

const SOL2964_SIGNER_SEEDS_EXPOSURE = {
  id: 'SOL2964',
  title: 'Signer Seeds Exposed in Logs',
  severity: 'medium' as const,
  description: 'Logging PDA signer seeds can leak sensitive derivation information.',
  pattern: /msg!.*seed|log.*seed|print.*seed|debug.*seed/i,
  antiPattern: /production.*build|release.*mode/i,
  recommendation: 'Never log signer seeds. Remove debug logging in production. Use conditional compilation.'
};

// ============================================================================
// Arithmetic & Precision Attacks
// ============================================================================

const SOL2965_DIVISION_TRUNCATION_THEFT = {
  id: 'SOL2965',
  title: 'Division Truncation Enabling Theft',
  severity: 'critical' as const,
  description: 'Integer division truncation in fee/share calculations can be exploited for rounding attacks.',
  pattern: /\/ |\.div\(|checked_div/i,
  antiPattern: /round.*up|ceil|scale.*factor|precision/i,
  recommendation: 'Use higher precision internally. Round in protocol\'s favor. Implement minimum amounts.'
};

const SOL2966_SHARE_CALCULATION_ROUNDING = {
  id: 'SOL2966',
  title: 'Share Calculation Rounding Error',
  severity: 'high' as const,
  description: 'Rounding errors in share calculations compound over time, draining pool value.',
  pattern: /shares|mint.*amount|burn.*amount|ratio/i,
  antiPattern: /round.*down.*withdraw|round.*up.*deposit|precision.*guard/i,
  recommendation: 'Round against user on both deposit (down) and withdraw (up). Use sufficient decimal precision.'
};

const SOL2967_INTEREST_ACCRUAL_MANIPULATION = {
  id: 'SOL2967',
  title: 'Interest Accrual Timing Manipulation',
  severity: 'high' as const,
  description: 'Manipulating when interest accrues can extract value from lending protocols.',
  pattern: /accrue.*interest|interest.*rate|compound/i,
  antiPattern: /accrue.*before|update.*interest|rate.*sanity/i,
  recommendation: 'Always accrue interest before state changes. Validate interest rate within bounds.'
};

const SOL2968_PRICE_OVERFLOW_IN_MULTIPLICATION = {
  id: 'SOL2968',
  title: 'Price Calculation Overflow',
  severity: 'critical' as const,
  description: 'Price * amount can overflow even with checked math if intermediates overflow.',
  pattern: /price.*\*|amount.*\*.*price|value.*=.*price/i,
  antiPattern: /u128|U256|checked.*mul.*then.*div|safe.*math/i,
  recommendation: 'Use u128 or larger for price calculations. Check overflow at every step. Scale down early.'
};

// ============================================================================
// Oracle Security Patterns
// ============================================================================

const SOL2969_SINGLE_ORACLE_DEPENDENCY = {
  id: 'SOL2969',
  title: 'Single Oracle Source Dependency',
  severity: 'high' as const,
  description: 'Relying on single oracle allows manipulation via oracle-specific attacks.',
  pattern: /oracle.*price|get_price|price_feed/i,
  antiPattern: /multiple.*oracle|aggregate.*price|median.*price/i,
  recommendation: 'Use multiple oracle sources. Implement median/TWAP. Check price deviation between sources.'
};

const SOL2970_ORACLE_STALENESS_THRESHOLD = {
  id: 'SOL2970',
  title: 'Oracle Staleness Threshold Too High',
  severity: 'high' as const,
  description: 'Accepting stale oracle data enables using outdated prices for profitable trades.',
  pattern: /staleness|max.*age|last.*update|timestamp.*diff/i,
  antiPattern: /staleness.*<.*60|fresh.*price|recent.*update/i,
  recommendation: 'Set conservative staleness thresholds (< 60 seconds for DeFi). Reject stale prices.'
};

const SOL2971_ORACLE_CONFIDENCE_INTERVAL = {
  id: 'SOL2971',
  title: 'Oracle Confidence Interval Ignored',
  severity: 'medium' as const,
  description: 'Using oracle price without checking confidence interval accepts uncertain data.',
  pattern: /price.*\.|get.*price|oracle.*result/i,
  antiPattern: /confidence|price.*conf|uncertainty|deviation/i,
  recommendation: 'Check oracle confidence intervals. Reject prices with low confidence. Widen price bands.'
};

const SOL2972_TWAP_WINDOW_MANIPULATION = {
  id: 'SOL2972',
  title: 'TWAP Window Too Short',
  severity: 'high' as const,
  description: 'Short TWAP windows can be manipulated within a single block.',
  pattern: /twap|time.*weighted|average.*price/i,
  antiPattern: /twap.*window.*>.*300|long.*twap|multi.*block/i,
  recommendation: 'Use TWAP windows > 5 minutes. Implement manipulation detection. Use multiple price sources.'
};

// ============================================================================
// State Management Vulnerabilities
// ============================================================================

const SOL2973_STATE_MACHINE_VIOLATION = {
  id: 'SOL2973',
  title: 'State Machine Transition Violation',
  severity: 'high' as const,
  description: 'Invalid state transitions can put protocol in inconsistent state.',
  pattern: /state|status|phase|stage/i,
  antiPattern: /valid.*transition|state.*machine|require.*state/i,
  recommendation: 'Implement explicit state machine. Validate all transitions. Reject invalid state changes.'
};

const SOL2974_INVARIANT_CHECK_MISSING = {
  id: 'SOL2974',
  title: 'Protocol Invariant Check Missing',
  severity: 'high' as const,
  description: 'Missing invariant checks allow protocol to enter invalid states.',
  pattern: /total.*supply|balance|reserve|liquidity/i,
  antiPattern: /assert.*invariant|verify.*balance|check.*total/i,
  recommendation: 'Define and check protocol invariants. Assert balance equations. Validate totals after operations.'
};

const SOL2975_REENTRANCY_STATE_CORRUPTION = {
  id: 'SOL2975',
  title: 'Reentrancy Leading to State Corruption',
  severity: 'critical' as const,
  description: 'State changes after CPI allow reentrancy to corrupt state.',
  pattern: /invoke|CpiContext|after.*cpi/i,
  antiPattern: /reentrancy.*guard|state.*before.*cpi|lock/i,
  recommendation: 'Update state before CPI. Use reentrancy guards. Check state after CPI.'
};

// ============================================================================
// Token Security Patterns
// ============================================================================

const SOL2976_MINT_AUTHORITY_NOT_REVOKED = {
  id: 'SOL2976',
  title: 'Mint Authority Not Revoked',
  severity: 'high' as const,
  description: 'Active mint authority allows unlimited token minting.',
  pattern: /mint_authority|MintTo|mint.*tokens/i,
  antiPattern: /authority.*None|revoke.*mint|disable.*mint/i,
  recommendation: 'Revoke mint authority after initial mint. Use governance for mint authority if needed.'
};

const SOL2977_FREEZE_AUTHORITY_CENTRALIZATION = {
  id: 'SOL2977',
  title: 'Freeze Authority Centralization Risk',
  severity: 'medium' as const,
  description: 'Single entity controlling freeze authority can freeze user funds.',
  pattern: /freeze_authority|FreezeAccount|freeze.*token/i,
  antiPattern: /freeze.*revoked|no.*freeze|decentralized.*freeze/i,
  recommendation: 'Consider revoking freeze authority. Use governance for freeze decisions if needed.'
};

const SOL2978_TOKEN_ACCOUNT_OWNER_MISMATCH = {
  id: 'SOL2978',
  title: 'Token Account Owner Mismatch',
  severity: 'critical' as const,
  description: 'Not verifying token account owner allows sending tokens to wrong recipient.',
  pattern: /token.*account|TokenAccount|associated.*token/i,
  antiPattern: /owner.*==|verify.*owner|has_one.*owner/i,
  recommendation: 'Verify token account owner matches expected recipient. Use Anchor token account constraints.'
};

const SOL2979_ATA_CREATION_RACE = {
  id: 'SOL2979',
  title: 'ATA Creation Race Condition',
  severity: 'medium' as const,
  description: 'Multiple transactions creating same ATA can fail or be front-run.',
  pattern: /create.*associated|get_associated|init.*if.*needed/i,
  antiPattern: /idempotent|check.*exists|try.*create/i,
  recommendation: 'Use idempotent ATA creation. Check if ATA exists before creating. Handle creation failures.'
};

// ============================================================================
// Access Control & Authorization
// ============================================================================

const SOL2980_ADMIN_BACKDOOR = {
  id: 'SOL2980',
  title: 'Hidden Admin Backdoor Function',
  severity: 'critical' as const,
  description: 'Hidden admin functions can bypass normal access controls.',
  pattern: /admin|owner|authority|superuser/i,
  antiPattern: /documented.*admin|audit.*admin|transparent.*authority/i,
  recommendation: 'Document all admin functions. Make admin capabilities transparent. Use timelocks for admin actions.'
};

const SOL2981_AUTHORITY_TRANSFER_NO_ACCEPTANCE = {
  id: 'SOL2981',
  title: 'Authority Transfer Without Acceptance',
  severity: 'high' as const,
  description: 'Direct authority transfer without new owner acceptance can lock funds.',
  pattern: /transfer.*authority|set.*owner|change.*admin/i,
  antiPattern: /pending.*authority|accept.*authority|two.*step/i,
  recommendation: 'Implement two-step authority transfer. Require new owner to accept. Add timelock for transfers.'
};

const SOL2982_ROLE_PERMISSION_ESCALATION = {
  id: 'SOL2982',
  title: 'Role Permission Escalation',
  severity: 'critical' as const,
  description: 'Lower-privilege roles can grant themselves higher privileges.',
  pattern: /grant.*role|add.*permission|set.*role/i,
  antiPattern: /role.*hierarchy|require.*admin|permission.*check/i,
  recommendation: 'Implement strict role hierarchy. Only higher roles can grant permissions. Audit role changes.'
};

// ============================================================================
// Lending Protocol Specific
// ============================================================================

const SOL2983_BORROW_EXCEEDS_COLLATERAL = {
  id: 'SOL2983',
  title: 'Borrow Amount Exceeds Collateral Value',
  severity: 'critical' as const,
  description: 'Insufficient collateral checks allow under-collateralized borrows.',
  pattern: /borrow|loan|debt|collateral.*ratio/i,
  antiPattern: /check.*collateral|ltv.*check|health.*factor/i,
  recommendation: 'Always verify collateral value before lending. Check LTV against limits. Use fresh oracle prices.'
};

const SOL2984_LIQUIDATION_BONUS_EXPLOITATION = {
  id: 'SOL2984',
  title: 'Liquidation Bonus Exploitation',
  severity: 'high' as const,
  description: 'Excessive liquidation bonus can make self-liquidation profitable.',
  pattern: /liquidation.*bonus|liquidation.*incentive|liquidate.*reward/i,
  antiPattern: /bonus.*cap|reasonable.*bonus|anti.*self.*liquidation/i,
  recommendation: 'Cap liquidation bonus. Prevent self-liquidation. Use dynamic bonus based on health factor.'
};

const SOL2985_BAD_DEBT_SOCIALIZATION = {
  id: 'SOL2985',
  title: 'Bad Debt Socialization Mechanism Missing',
  severity: 'high' as const,
  description: 'Without bad debt handling, insolvency losses fall on last withdrawers.',
  pattern: /bad.*debt|underwater|insolvent|negative.*equity/i,
  antiPattern: /insurance.*fund|socialize.*loss|reserve.*fund/i,
  recommendation: 'Implement insurance fund. Socialize bad debt across depositors. Reserve portion of interest.'
};

// ============================================================================
// DEX/AMM Specific
// ============================================================================

const SOL2986_CONSTANT_PRODUCT_VIOLATION = {
  id: 'SOL2986',
  title: 'AMM Constant Product Invariant Violation',
  severity: 'critical' as const,
  description: 'Violating x*y=k invariant allows extracting value from AMM.',
  pattern: /reserve.*\*.*reserve|constant.*product|x.*y.*k/i,
  antiPattern: /verify.*invariant|check.*product|assert.*k/i,
  recommendation: 'Always verify constant product after swaps. Check invariant at start and end of operations.'
};

const SOL2987_SANDWICH_ATTACK_VECTOR = {
  id: 'SOL2987',
  title: 'Sandwich Attack Vulnerability',
  severity: 'high' as const,
  description: 'Large swaps without slippage protection are vulnerable to sandwich attacks.',
  pattern: /swap|exchange|trade|amm/i,
  antiPattern: /slippage.*check|min.*output|deadline|max.*impact/i,
  recommendation: 'Implement slippage protection. Add deadline checks. Use private mempools or MEV protection.'
};

const SOL2988_LP_TOKEN_INFLATION = {
  id: 'SOL2988',
  title: 'LP Token Inflation Attack',
  severity: 'critical' as const,
  description: 'First depositor can inflate LP token price to steal from others.',
  pattern: /lp.*token|liquidity.*token|pool.*share/i,
  antiPattern: /minimum.*liquidity|dead.*shares|bootstrap/i,
  recommendation: 'Mint minimum LP tokens to zero address. Require minimum initial liquidity. Set share price floor.'
};

// ============================================================================
// Governance Security
// ============================================================================

const SOL2989_FLASH_GOVERNANCE_ATTACK = {
  id: 'SOL2989',
  title: 'Flash Loan Governance Voting',
  severity: 'critical' as const,
  description: 'Flash loans enable acquiring voting power, voting, and returning in same transaction.',
  pattern: /vote|proposal|governance.*token/i,
  antiPattern: /snapshot|voting.*escrow|lock.*period/i,
  recommendation: 'Use snapshot-based voting. Require token lock period. Implement vote escrow (ve tokens).'
};

const SOL2990_PROPOSAL_EXECUTION_BYPASS = {
  id: 'SOL2990',
  title: 'Governance Proposal Execution Bypass',
  severity: 'critical' as const,
  description: 'Executing proposals without proper approval enables unauthorized actions.',
  pattern: /execute.*proposal|proposal.*execute|run.*proposal/i,
  antiPattern: /quorum.*check|vote.*threshold|timelock.*passed/i,
  recommendation: 'Verify quorum and approval before execution. Implement mandatory timelock. Check vote threshold.'
};

const SOL2991_VOTER_BRIBERY_VECTOR = {
  id: 'SOL2991',
  title: 'Governance Vote Bribery Vector',
  severity: 'medium' as const,
  description: 'Lack of vote privacy enables vote buying and bribery.',
  pattern: /cast.*vote|vote.*power|delegation/i,
  antiPattern: /private.*vote|commit.*reveal|encrypted.*vote/i,
  recommendation: 'Consider private voting (commit-reveal). Make bribery coordination difficult. Monitor unusual voting patterns.'
};

// ============================================================================
// Cross-Program Security
// ============================================================================

const SOL2992_CALLBACK_INJECTION = {
  id: 'SOL2992',
  title: 'Callback Function Injection',
  severity: 'critical' as const,
  description: 'User-controlled callback addresses enable calling arbitrary code.',
  pattern: /callback|hook|handler|on_complete/i,
  antiPattern: /whitelist.*callback|verify.*callback|known.*programs/i,
  recommendation: 'Whitelist allowed callbacks. Never accept arbitrary callback addresses. Use known program IDs.'
};

const SOL2993_COMPOSABILITY_ASSUMPTION_EXPLOIT = {
  id: 'SOL2993',
  title: 'Cross-Protocol Composability Exploit',
  severity: 'high' as const,
  description: 'Assumptions about other protocol behavior can be violated.',
  pattern: /external.*protocol|composable|integration/i,
  antiPattern: /defensive.*check|verify.*external|isolate.*call/i,
  recommendation: 'Make defensive assumptions about external protocols. Verify external call results. Isolate integration points.'
};

const SOL2994_PROGRAM_VERSION_MISMATCH = {
  id: 'SOL2994',
  title: 'Integrated Program Version Mismatch',
  severity: 'medium' as const,
  description: 'Integrating with specific program versions that may be upgraded.',
  pattern: /program_id|integrated.*program|external.*call/i,
  antiPattern: /version.*check|upgrade.*handler|compatibility/i,
  recommendation: 'Check integrated program versions. Handle upgrades gracefully. Test against multiple versions.'
};

// ============================================================================
// Miscellaneous Security
// ============================================================================

const SOL2995_RENT_EXEMPTION_CHECK = {
  id: 'SOL2995',
  title: 'Rent Exemption Check Missing',
  severity: 'medium' as const,
  description: 'Accounts without rent exemption can be garbage collected.',
  pattern: /lamports|rent|account.*create/i,
  antiPattern: /rent.*exempt|minimum.*balance|exemption.*check/i,
  recommendation: 'Ensure all accounts are rent-exempt. Check lamport balance on creation.'
};

const SOL2996_SLOT_RANDOMNESS_PREDICTION = {
  id: 'SOL2996',
  title: 'Predictable Slot-Based Randomness',
  severity: 'critical' as const,
  description: 'Using slot hashes for randomness is predictable by validators.',
  pattern: /recent.*blockhash|slot.*hash|random/i,
  antiPattern: /vrf|verifiable.*random|chainlink/i,
  recommendation: 'Use VRF for randomness. Never use slot hashes. Consider commit-reveal schemes.'
};

const SOL2997_DEBUG_CODE_IN_PRODUCTION = {
  id: 'SOL2997',
  title: 'Debug Code in Production',
  severity: 'medium' as const,
  description: 'Debug code left in production can expose sensitive information or bypass checks.',
  pattern: /debug|test.*only|devnet|localhost/i,
  antiPattern: /cfg.*release|production.*build|feature.*flag/i,
  recommendation: 'Remove debug code before deployment. Use conditional compilation. Audit for test bypasses.'
};

const SOL2998_TIMESTAMP_MANIPULATION = {
  id: 'SOL2998',
  title: 'Clock Timestamp Manipulation',
  severity: 'medium' as const,
  description: 'On-chain timestamps can be slightly manipulated by validators.',
  pattern: /Clock|unix_timestamp|timestamp/i,
  antiPattern: /timestamp.*tolerance|approximate.*time|slot.*based/i,
  recommendation: 'Allow timestamp tolerance. Use slot numbers for ordering. Never rely on exact timestamps.'
};

const SOL2999_COMPUTE_BUDGET_GRIEFING = {
  id: 'SOL2999',
  title: 'Compute Unit Exhaustion Griefing',
  severity: 'medium' as const,
  description: 'Attackers can make transactions fail by exhausting compute units.',
  pattern: /loop|iterate|for.*in|while/i,
  antiPattern: /bound.*check|max.*iteration|limit.*loop/i,
  recommendation: 'Bound all loops. Set maximum iterations. Test worst-case compute usage.'
};

const SOL3000_ERROR_HANDLING_INFORMATION_LEAK = {
  id: 'SOL3000',
  title: 'Error Message Information Leak',
  severity: 'low' as const,
  description: 'Detailed error messages can leak implementation details to attackers.',
  pattern: /err!|error!|msg!.*error/i,
  antiPattern: /generic.*error|sanitize.*error/i,
  recommendation: 'Use generic error messages in production. Log details separately. Don\'t reveal internal state.'
};

// Export pattern checker function
export function checkBatch66Patterns(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  
  if (!input.rust?.content) return findings;
  const content = input.rust.content;
  
  const patterns = [
    // Crema Finance
    SOL2951_FAKE_TICK_ACCOUNT_CREATION,
    SOL2952_TICK_OWNER_CHECK_BYPASS,
    SOL2953_FEE_ACCUMULATOR_MANIPULATION,
    SOL2954_FLASH_LOAN_FEE_CLAIM,
    // Account Ownership
    SOL2955_ACCOUNTINFO_OWNER_MISSING,
    SOL2956_DISCRIMINATOR_COLLISION,
    SOL2957_ACCOUNT_DATA_RACE,
    // PDA & Seeds
    SOL2958_USER_CONTROLLED_SEEDS,
    SOL2959_BUMP_SEED_INJECTION,
    SOL2960_SEED_LENGTH_MANIPULATION,
    // CPI Security
    SOL2961_UNCHECKED_CPI_PROGRAM,
    SOL2962_CPI_RETURN_DATA_SPOOFING,
    SOL2963_CPI_ACCOUNT_REORDERING,
    SOL2964_SIGNER_SEEDS_EXPOSURE,
    // Arithmetic
    SOL2965_DIVISION_TRUNCATION_THEFT,
    SOL2966_SHARE_CALCULATION_ROUNDING,
    SOL2967_INTEREST_ACCRUAL_MANIPULATION,
    SOL2968_PRICE_OVERFLOW_IN_MULTIPLICATION,
    // Oracle
    SOL2969_SINGLE_ORACLE_DEPENDENCY,
    SOL2970_ORACLE_STALENESS_THRESHOLD,
    SOL2971_ORACLE_CONFIDENCE_INTERVAL,
    SOL2972_TWAP_WINDOW_MANIPULATION,
    // State Management
    SOL2973_STATE_MACHINE_VIOLATION,
    SOL2974_INVARIANT_CHECK_MISSING,
    SOL2975_REENTRANCY_STATE_CORRUPTION,
    // Token Security
    SOL2976_MINT_AUTHORITY_NOT_REVOKED,
    SOL2977_FREEZE_AUTHORITY_CENTRALIZATION,
    SOL2978_TOKEN_ACCOUNT_OWNER_MISMATCH,
    SOL2979_ATA_CREATION_RACE,
    // Access Control
    SOL2980_ADMIN_BACKDOOR,
    SOL2981_AUTHORITY_TRANSFER_NO_ACCEPTANCE,
    SOL2982_ROLE_PERMISSION_ESCALATION,
    // Lending
    SOL2983_BORROW_EXCEEDS_COLLATERAL,
    SOL2984_LIQUIDATION_BONUS_EXPLOITATION,
    SOL2985_BAD_DEBT_SOCIALIZATION,
    // DEX/AMM
    SOL2986_CONSTANT_PRODUCT_VIOLATION,
    SOL2987_SANDWICH_ATTACK_VECTOR,
    SOL2988_LP_TOKEN_INFLATION,
    // Governance
    SOL2989_FLASH_GOVERNANCE_ATTACK,
    SOL2990_PROPOSAL_EXECUTION_BYPASS,
    SOL2991_VOTER_BRIBERY_VECTOR,
    // Cross-Program
    SOL2992_CALLBACK_INJECTION,
    SOL2993_COMPOSABILITY_ASSUMPTION_EXPLOIT,
    SOL2994_PROGRAM_VERSION_MISMATCH,
    // Misc
    SOL2995_RENT_EXEMPTION_CHECK,
    SOL2996_SLOT_RANDOMNESS_PREDICTION,
    SOL2997_DEBUG_CODE_IN_PRODUCTION,
    SOL2998_TIMESTAMP_MANIPULATION,
    SOL2999_COMPUTE_BUDGET_GRIEFING,
    SOL3000_ERROR_HANDLING_INFORMATION_LEAK,
  ];
  
  for (const p of patterns) {
    if (p.pattern.test(content)) {
      if (p.antiPattern && p.antiPattern.test(content)) {
        continue;
      }
      
      findings.push({
        id: p.id,
        title: p.title,
        severity: p.severity,
        description: p.description,
        location: { file: input.path },
        recommendation: p.recommendation,
      });
    }
  }
  
  return findings;
}

// Export all patterns for registration
export const batch66Patterns = [
  { id: 'SOL2951', name: 'CLMM Fake Tick Account Creation', severity: 'critical' as const },
  { id: 'SOL2952', name: 'Tick Account Owner Check Bypass', severity: 'critical' as const },
  { id: 'SOL2953', name: 'CLMM Fee Accumulator Manipulation', severity: 'critical' as const },
  { id: 'SOL2954', name: 'Flash Loan Amplified Fee Claim', severity: 'critical' as const },
  { id: 'SOL2955', name: 'AccountInfo Owner Verification Missing', severity: 'critical' as const },
  { id: 'SOL2956', name: 'Account Discriminator Hash Collision', severity: 'high' as const },
  { id: 'SOL2957', name: 'Account Data Race Condition', severity: 'high' as const },
  { id: 'SOL2958', name: 'User-Controlled PDA Seeds Without Validation', severity: 'critical' as const },
  { id: 'SOL2959', name: 'Bump Seed Injection Attack', severity: 'high' as const },
  { id: 'SOL2960', name: 'Variable Seed Length Manipulation', severity: 'medium' as const },
  { id: 'SOL2961', name: 'Unchecked CPI Target Program', severity: 'critical' as const },
  { id: 'SOL2962', name: 'CPI Return Data Spoofing', severity: 'high' as const },
  { id: 'SOL2963', name: 'CPI Account Array Reordering', severity: 'high' as const },
  { id: 'SOL2964', name: 'Signer Seeds Exposed in Logs', severity: 'medium' as const },
  { id: 'SOL2965', name: 'Division Truncation Enabling Theft', severity: 'critical' as const },
  { id: 'SOL2966', name: 'Share Calculation Rounding Error', severity: 'high' as const },
  { id: 'SOL2967', name: 'Interest Accrual Timing Manipulation', severity: 'high' as const },
  { id: 'SOL2968', name: 'Price Calculation Overflow', severity: 'critical' as const },
  { id: 'SOL2969', name: 'Single Oracle Source Dependency', severity: 'high' as const },
  { id: 'SOL2970', name: 'Oracle Staleness Threshold Too High', severity: 'high' as const },
  { id: 'SOL2971', name: 'Oracle Confidence Interval Ignored', severity: 'medium' as const },
  { id: 'SOL2972', name: 'TWAP Window Too Short', severity: 'high' as const },
  { id: 'SOL2973', name: 'State Machine Transition Violation', severity: 'high' as const },
  { id: 'SOL2974', name: 'Protocol Invariant Check Missing', severity: 'high' as const },
  { id: 'SOL2975', name: 'Reentrancy Leading to State Corruption', severity: 'critical' as const },
  { id: 'SOL2976', name: 'Mint Authority Not Revoked', severity: 'high' as const },
  { id: 'SOL2977', name: 'Freeze Authority Centralization Risk', severity: 'medium' as const },
  { id: 'SOL2978', name: 'Token Account Owner Mismatch', severity: 'critical' as const },
  { id: 'SOL2979', name: 'ATA Creation Race Condition', severity: 'medium' as const },
  { id: 'SOL2980', name: 'Hidden Admin Backdoor Function', severity: 'critical' as const },
  { id: 'SOL2981', name: 'Authority Transfer Without Acceptance', severity: 'high' as const },
  { id: 'SOL2982', name: 'Role Permission Escalation', severity: 'critical' as const },
  { id: 'SOL2983', name: 'Borrow Amount Exceeds Collateral Value', severity: 'critical' as const },
  { id: 'SOL2984', name: 'Liquidation Bonus Exploitation', severity: 'high' as const },
  { id: 'SOL2985', name: 'Bad Debt Socialization Mechanism Missing', severity: 'high' as const },
  { id: 'SOL2986', name: 'AMM Constant Product Invariant Violation', severity: 'critical' as const },
  { id: 'SOL2987', name: 'Sandwich Attack Vulnerability', severity: 'high' as const },
  { id: 'SOL2988', name: 'LP Token Inflation Attack', severity: 'critical' as const },
  { id: 'SOL2989', name: 'Flash Loan Governance Voting', severity: 'critical' as const },
  { id: 'SOL2990', name: 'Governance Proposal Execution Bypass', severity: 'critical' as const },
  { id: 'SOL2991', name: 'Governance Vote Bribery Vector', severity: 'medium' as const },
  { id: 'SOL2992', name: 'Callback Function Injection', severity: 'critical' as const },
  { id: 'SOL2993', name: 'Cross-Protocol Composability Exploit', severity: 'high' as const },
  { id: 'SOL2994', name: 'Integrated Program Version Mismatch', severity: 'medium' as const },
  { id: 'SOL2995', name: 'Rent Exemption Check Missing', severity: 'medium' as const },
  { id: 'SOL2996', name: 'Predictable Slot-Based Randomness', severity: 'critical' as const },
  { id: 'SOL2997', name: 'Debug Code in Production', severity: 'medium' as const },
  { id: 'SOL2998', name: 'Clock Timestamp Manipulation', severity: 'medium' as const },
  { id: 'SOL2999', name: 'Compute Unit Exhaustion Griefing', severity: 'medium' as const },
  { id: 'SOL3000', name: 'Error Message Information Leak', severity: 'low' as const },
];
