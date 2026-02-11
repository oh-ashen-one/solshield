/**
 * SolShield Pattern Batch 61: Advanced 2025-2026 Attack Vectors
 * 
 * Based on:
 * - Sec3 2025 Security Ecosystem Review (163 audits, 1,669 vulnerabilities)
 * - Certora Lulo Audit Findings (Jan 2025)
 * - Accretion Security Research (80% critical discovery rate)
 * - Three Sigma Rust Memory Safety on Solana (Apr 2025)
 * - BlockHacks Solana Security Analysis (Sep 2025)
 * 
 * Patterns: SOL2561-SOL2630
 */

import type { Finding, PatternInput } from './index.js';

// Oracle & Price Feed Advanced Patterns (SOL2561-SOL2575)
const ORACLE_ADVANCED_PATTERNS = [
  {
    id: 'SOL2561',
    name: 'Oracle Update Failure Silent Pass',
    severity: 'critical' as const,
    pattern: /get_price|fetch_price|oracle\.price(?![\s\S]{0,100}(stale|fresh|valid|check|error|fail|none|some))/i,
    description: 'Oracle price fetch without handling update failures. From Certora Lulo audit - oracle updates can fail silently.',
    recommendation: 'Handle oracle update failures explicitly and fail gracefully or use fallback prices.'
  },
  {
    id: 'SOL2562',
    name: 'Pyth Confidence Interval Ignored',
    severity: 'high' as const,
    pattern: /pyth[\s\S]{0,50}price(?![\s\S]{0,100}conf|confidence)/i,
    description: 'Pyth oracle used without checking confidence interval. High confidence intervals indicate unreliable prices.',
    recommendation: 'Check price.conf and reject prices where conf/price ratio exceeds threshold (e.g., 1%).'
  },
  {
    id: 'SOL2563',
    name: 'Switchboard Staleness Unchecked',
    severity: 'high' as const,
    pattern: /switchboard[\s\S]{0,50}(result|feed)(?![\s\S]{0,100}timestamp|staleness|max_age)/i,
    description: 'Switchboard feed used without staleness validation.',
    recommendation: 'Verify feed timestamp is within acceptable age (e.g., <30 seconds for volatile assets).'
  },
  {
    id: 'SOL2564',
    name: 'TWAP Window Too Short',
    severity: 'medium' as const,
    pattern: /twap[\s\S]{0,50}(window|period)[\s\S]{0,20}(60|30|15|10|5)\b/i,
    description: 'TWAP window shorter than 5 minutes is vulnerable to manipulation.',
    recommendation: 'Use TWAP windows of at least 15-30 minutes for critical price feeds.'
  },
  {
    id: 'SOL2565',
    name: 'Single Oracle Source Dependency',
    severity: 'high' as const,
    pattern: /oracle[\s\S]{0,100}price(?![\s\S]{0,200}(fallback|backup|secondary|aggregate))/i,
    description: 'Single oracle dependency without fallback. Oracle downtime = protocol halt.',
    recommendation: 'Implement fallback oracles or use aggregated price feeds from multiple sources.'
  },
  {
    id: 'SOL2566',
    name: 'Price Deviation Unchecked Between Oracles',
    severity: 'high' as const,
    pattern: /(oracle_a|oracle_1|primary)[\s\S]{0,100}(oracle_b|oracle_2|secondary)(?![\s\S]{0,100}deviation|diff|delta)/i,
    description: 'Multiple oracles used without checking deviation between them.',
    recommendation: 'Reject transactions when oracle prices deviate more than threshold (e.g., 5%).'
  },
  {
    id: 'SOL2567',
    name: 'Market Price vs Oracle Price Arbitrage',
    severity: 'critical' as const,
    pattern: /(swap|trade|exchange)[\s\S]{0,200}oracle[\s\S]{0,100}price(?![\s\S]{0,100}bound|limit|deviation)/i,
    description: 'No bounds checking between market execution and oracle price. Enables oracle arbitrage.',
    recommendation: 'Enforce maximum deviation between oracle and execution price.'
  },
  {
    id: 'SOL2568',
    name: 'Liquidation Oracle Manipulation Window',
    severity: 'critical' as const,
    pattern: /liquidat[\s\S]{0,100}(price|oracle)(?![\s\S]{0,100}delay|twap|average)/i,
    description: 'Liquidations using spot price without delay or averaging. From Mango exploit.',
    recommendation: 'Use time-delayed or TWAP prices for liquidation to prevent manipulation.'
  },
  {
    id: 'SOL2569',
    name: 'Oracle Decimal Mismatch',
    severity: 'high' as const,
    pattern: /oracle[\s\S]{0,100}(price|value)[\s\S]{0,50}(decimals|scale|exponent)(?![\s\S]{0,50}(normalize|adjust|convert))/i,
    description: 'Oracle price decimals not normalized. Different oracles use different decimal scales.',
    recommendation: 'Always normalize oracle prices to a consistent decimal scale before use.'
  },
  {
    id: 'SOL2570',
    name: 'LP Token Oracle Price Manipulation',
    severity: 'critical' as const,
    pattern: /lp_token[\s\S]{0,100}(price|value)(?![\s\S]{0,100}(fair|underlying|reserve))/i,
    description: 'LP token priced without fair value calculation. From OtterSec "$200M Bluff" research.',
    recommendation: 'Calculate LP token fair value from underlying reserves, not AMM spot price.'
  },
  {
    id: 'SOL2571',
    name: 'Flash Loan Oracle Attack Window',
    severity: 'critical' as const,
    pattern: /flash[\s\S]{0,50}(loan|borrow)[\s\S]{0,200}oracle[\s\S]{0,100}price/i,
    description: 'Oracle read susceptible to same-transaction flash loan manipulation.',
    recommendation: 'Use TWAP, previous block price, or multiple confirmation prices for critical operations.'
  },
  {
    id: 'SOL2572',
    name: 'Oracle Heartbeat Check Missing',
    severity: 'medium' as const,
    pattern: /oracle[\s\S]{0,100}(feed|source)(?![\s\S]{0,100}(heartbeat|alive|active|status))/i,
    description: 'Oracle used without checking if feed is actively updating.',
    recommendation: 'Verify oracle heartbeat/update frequency before trusting prices.'
  },
  {
    id: 'SOL2573',
    name: 'Negative Price Not Handled',
    severity: 'high' as const,
    pattern: /price[\s\S]{0,30}(i64|i128|signed)(?![\s\S]{0,50}(abs|positive|unsigned|check))/i,
    description: 'Signed price type without negative value handling. Some assets can have negative prices.',
    recommendation: 'Handle negative prices appropriately or reject if unexpected.'
  },
  {
    id: 'SOL2574',
    name: 'Price Impact Not Calculated',
    severity: 'high' as const,
    pattern: /(swap|trade|exchange)[\s\S]{0,100}amount(?![\s\S]{0,100}(impact|slippage|price_impact))/i,
    description: 'Trade execution without calculating price impact for large orders.',
    recommendation: 'Calculate and display price impact, reject if exceeds user-defined threshold.'
  },
  {
    id: 'SOL2575',
    name: 'Stale Oracle Causes Liquidation Cascade',
    severity: 'critical' as const,
    pattern: /liquidat[\s\S]{0,100}(health|ratio|factor)[\s\S]{0,100}oracle(?![\s\S]{0,100}fresh)/i,
    description: 'Liquidation using potentially stale oracle data can cause cascade liquidations.',
    recommendation: 'Verify oracle freshness before any liquidation, use conservative staleness thresholds.'
  },
];

// Referral & Fee Manipulation Patterns (SOL2576-SOL2590)
const REFERRAL_FEE_PATTERNS = [
  {
    id: 'SOL2576',
    name: 'Self-Referral Fee Extraction',
    severity: 'high' as const,
    pattern: /referr(al|er)[\s\S]{0,100}fee(?![\s\S]{0,100}(self|same|user|owner))/i,
    description: 'Referral system without self-referral prevention. From Certora Lulo audit.',
    recommendation: 'Prevent users from referring themselves to extract fees.'
  },
  {
    id: 'SOL2577',
    name: 'Referral Fee Unbounded',
    severity: 'high' as const,
    pattern: /referr(al|er)[\s\S]{0,50}(fee|percent|bps)(?![\s\S]{0,50}(max|cap|limit|bound))/i,
    description: 'Referral fee percentage not bounded. Could be set to 100%.',
    recommendation: 'Cap referral fees at reasonable maximum (e.g., 50% of protocol fee).'
  },
  {
    id: 'SOL2578',
    name: 'Fee Precision Loss Attack',
    severity: 'medium' as const,
    pattern: /fee[\s\S]{0,50}(amount|value)[\s\S]{0,30}\/[\s\S]{0,30}(100|1000|10000)(?![\s\S]{0,50}checked)/i,
    description: 'Fee calculation with potential precision loss in division.',
    recommendation: 'Calculate fees with sufficient precision, consider using fixed-point math.'
  },
  {
    id: 'SOL2579',
    name: 'Protocol Fee Bypass via Routing',
    severity: 'high' as const,
    pattern: /(route|path|hop)[\s\S]{0,100}(fee|swap)(?![\s\S]{0,100}aggregate_fee)/i,
    description: 'Multi-hop routing that could bypass protocol fees.',
    recommendation: 'Ensure fees are collected on each hop or aggregated correctly.'
  },
  {
    id: 'SOL2580',
    name: 'Fee-on-Transfer Token Handling',
    severity: 'high' as const,
    pattern: /transfer[\s\S]{0,100}(amount|value)(?![\s\S]{0,100}(actual|received|post_fee))/i,
    description: 'Token transfers without accounting for fee-on-transfer tokens.',
    recommendation: 'Check actual received amount vs expected for fee-on-transfer tokens.'
  },
  {
    id: 'SOL2581',
    name: 'Treasury Fee Drain via Dust',
    severity: 'medium' as const,
    pattern: /treasury[\s\S]{0,100}(withdraw|claim|collect)(?![\s\S]{0,100}minimum)/i,
    description: 'Treasury withdrawal without minimum amount could drain via dust attacks.',
    recommendation: 'Enforce minimum withdrawal amounts to prevent dust drain attacks.'
  },
  {
    id: 'SOL2582',
    name: 'Fee Accrual Without Claim Limit',
    severity: 'medium' as const,
    pattern: /(accru|earn|collect)[\s\S]{0,50}fee(?![\s\S]{0,100}(rate_limit|cooldown|max))/i,
    description: 'Fee accrual without rate limiting could be gamed.',
    recommendation: 'Rate limit fee claims or implement fair distribution mechanism.'
  },
  {
    id: 'SOL2583',
    name: 'Dynamic Fee Manipulation',
    severity: 'high' as const,
    pattern: /(dynamic|variable)[\s\S]{0,30}fee(?![\s\S]{0,100}(bound|range|admin_only))/i,
    description: 'Dynamic fees without bounds could be manipulated.',
    recommendation: 'Bound dynamic fees within reasonable range and protect update authority.'
  },
  {
    id: 'SOL2584',
    name: 'Flash Loan Fee Evasion',
    severity: 'high' as const,
    pattern: /flash[\s\S]{0,50}(loan|borrow)[\s\S]{0,100}fee(?![\s\S]{0,100}(minimum|floor))/i,
    description: 'Flash loan fee could be evaded through minimum amount manipulation.',
    recommendation: 'Set minimum flash loan fee floor to prevent evasion.'
  },
  {
    id: 'SOL2585',
    name: 'Withdrawal Fee Frontrun',
    severity: 'medium' as const,
    pattern: /withdraw[\s\S]{0,50}fee[\s\S]{0,50}(update|change|set)(?![\s\S]{0,100}timelock)/i,
    description: 'Withdrawal fee changes without timelock enable frontrunning users.',
    recommendation: 'Add timelock to fee changes so users can withdraw before increase.'
  },
  {
    id: 'SOL2586',
    name: 'Performance Fee Timing Attack',
    severity: 'high' as const,
    pattern: /performance[\s\S]{0,50}fee[\s\S]{0,100}(calculate|collect)(?![\s\S]{0,100}highwater)/i,
    description: 'Performance fee without high-water mark enables timing attacks.',
    recommendation: 'Implement high-water mark for performance fee calculation.'
  },
  {
    id: 'SOL2587',
    name: 'Management Fee Compounding Error',
    severity: 'medium' as const,
    pattern: /management[\s\S]{0,50}fee[\s\S]{0,50}(annual|yearly)(?![\s\S]{0,100}pro_rat)/i,
    description: 'Annual management fee not pro-rated could be gamed.',
    recommendation: 'Pro-rate management fees based on actual time elapsed.'
  },
  {
    id: 'SOL2588',
    name: 'Swap Fee Rounding Exploit',
    severity: 'medium' as const,
    pattern: /swap[\s\S]{0,50}fee[\s\S]{0,50}(round|truncat)(?![\s\S]{0,100}favor_protocol)/i,
    description: 'Swap fee rounding direction favors user over protocol.',
    recommendation: 'Round fees in favor of protocol to prevent dust extraction.'
  },
  {
    id: 'SOL2589',
    name: 'Liquidation Fee Manipulation',
    severity: 'high' as const,
    pattern: /liquidat[\s\S]{0,50}(bonus|fee|reward)(?![\s\S]{0,100}(cap|max|limit))/i,
    description: 'Unbounded liquidation bonus enables excessive extraction.',
    recommendation: 'Cap liquidation bonus at reasonable maximum (e.g., 15%).'
  },
  {
    id: 'SOL2590',
    name: 'Cross-Program Fee Bypass',
    severity: 'high' as const,
    pattern: /invoke[\s\S]{0,100}(swap|transfer)(?![\s\S]{0,100}fee_check)/i,
    description: 'CPI to external program may bypass fee collection.',
    recommendation: 'Verify fees are collected regardless of execution path.'
  },
];

// Withdrawal & Deposit Manipulation (SOL2591-SOL2605)
const WITHDRAWAL_DEPOSIT_PATTERNS = [
  {
    id: 'SOL2591',
    name: 'Withdrawal Amount Manipulation',
    severity: 'critical' as const,
    pattern: /withdraw[\s\S]{0,100}(amount|value)(?![\s\S]{0,100}(balance|available|check))/i,
    description: 'Withdrawal amount not validated against actual balance. From Certora Lulo audit.',
    recommendation: 'Always verify withdrawal amount against available balance before transfer.'
  },
  {
    id: 'SOL2592',
    name: 'First Depositor Vault Attack',
    severity: 'critical' as const,
    pattern: /deposit[\s\S]{0,100}(shares|mint)[\s\S]{0,50}(total_supply|supply)\s*==\s*0/i,
    description: 'First depositor can manipulate share price. Classic vault attack vector.',
    recommendation: 'Seed vault with initial deposit or use virtual offset for share calculation.'
  },
  {
    id: 'SOL2593',
    name: 'Share Inflation via Donation',
    severity: 'critical' as const,
    pattern: /shares[\s\S]{0,50}(assets|balance)[\s\S]{0,50}total(?![\s\S]{0,100}(virtual|offset))/i,
    description: 'Direct asset donation can inflate share price and grief small depositors.',
    recommendation: 'Use virtual offset or minimum deposit to prevent share inflation attack.'
  },
  {
    id: 'SOL2594',
    name: 'Withdrawal Queue Jump',
    severity: 'high' as const,
    pattern: /withdraw[\s\S]{0,50}queue(?![\s\S]{0,100}(order|fifo|priority))/i,
    description: 'Withdrawal queue without ordering enables queue jumping.',
    recommendation: 'Enforce FIFO or priority-based queue processing.'
  },
  {
    id: 'SOL2595',
    name: 'Deposit During Pause',
    severity: 'medium' as const,
    pattern: /paused[\s\S]{0,100}deposit(?![\s\S]{0,100}require.*!paused)/i,
    description: 'Deposits may be possible during pause state.',
    recommendation: 'Block both deposits and withdrawals during paused state.'
  },
  {
    id: 'SOL2596',
    name: 'Withdrawal Minimum Not Enforced',
    severity: 'low' as const,
    pattern: /withdraw[\s\S]{0,50}(amount|value)(?![\s\S]{0,100}(minimum|min_amount))/i,
    description: 'No minimum withdrawal amount enables dust attacks.',
    recommendation: 'Enforce minimum withdrawal to prevent state bloat and dust attacks.'
  },
  {
    id: 'SOL2597',
    name: 'Deposit Cap Bypass via Multiple Transactions',
    severity: 'medium' as const,
    pattern: /deposit[\s\S]{0,50}(cap|limit|max)(?![\s\S]{0,100}(user|total|cumulative))/i,
    description: 'Deposit cap only checks single transaction, not cumulative.',
    recommendation: 'Track cumulative deposits per user and enforce cap accordingly.'
  },
  {
    id: 'SOL2598',
    name: 'Withdrawal Delay Bypass',
    severity: 'high' as const,
    pattern: /withdraw[\s\S]{0,50}(delay|cooldown|lock)(?![\s\S]{0,100}(enforce|check|verify))/i,
    description: 'Withdrawal delay declared but not enforced in execution.',
    recommendation: 'Verify delay period has elapsed before processing withdrawal.'
  },
  {
    id: 'SOL2599',
    name: 'Instant Withdrawal During Emergency',
    severity: 'high' as const,
    pattern: /emergency[\s\S]{0,50}withdraw(?![\s\S]{0,100}(partial|limit|delay))/i,
    description: 'Emergency withdrawal without rate limit enables bank run.',
    recommendation: 'Even emergency withdrawals should have rate limits to prevent total drain.'
  },
  {
    id: 'SOL2600',
    name: 'Deposit Deadline Not Checked',
    severity: 'medium' as const,
    pattern: /deposit[\s\S]{0,100}deadline(?![\s\S]{0,100}(check|require|verify))/i,
    description: 'Deposit deadline parameter ignored in validation.',
    recommendation: 'Reject deposits after specified deadline to prevent stale transactions.'
  },
  {
    id: 'SOL2601',
    name: 'Asset Decimal Mismatch in Deposit',
    severity: 'high' as const,
    pattern: /deposit[\s\S]{0,100}(mint|token)(?![\s\S]{0,100}decimals)/i,
    description: 'Deposit amount not adjusted for token decimals.',
    recommendation: 'Normalize amounts based on token decimals before calculation.'
  },
  {
    id: 'SOL2602',
    name: 'Withdrawal Rounding Favor Attacker',
    severity: 'medium' as const,
    pattern: /withdraw[\s\S]{0,50}(amount|shares)[\s\S]{0,30}(round|floor|ceil)/i,
    description: 'Withdrawal rounding direction may favor attacker over protocol.',
    recommendation: 'Round withdrawals down (floor) to favor protocol.'
  },
  {
    id: 'SOL2603',
    name: 'Deposit Slippage Check Missing',
    severity: 'high' as const,
    pattern: /deposit[\s\S]{0,100}(shares|mint)(?![\s\S]{0,100}(min_shares|slippage))/i,
    description: 'Deposit returns shares without minimum shares check.',
    recommendation: 'Allow users to specify minimum shares expected from deposit.'
  },
  {
    id: 'SOL2604',
    name: 'Withdrawal Max Slippage Unbounded',
    severity: 'high' as const,
    pattern: /withdraw[\s\S]{0,100}slippage(?![\s\S]{0,100}(max|cap|bound))/i,
    description: 'Withdrawal slippage not bounded could result in near-zero returns.',
    recommendation: 'Enforce maximum slippage tolerance for withdrawals.'
  },
  {
    id: 'SOL2605',
    name: 'Locked Funds Recovery Missing',
    severity: 'medium' as const,
    pattern: /(stuck|lock|trap)[\s\S]{0,50}(fund|token|asset)(?![\s\S]{0,100}recover)/i,
    description: 'No mechanism to recover stuck funds from edge cases.',
    recommendation: 'Implement admin recovery function with appropriate safeguards.'
  },
];

// Advanced Access Control Patterns (SOL2606-SOL2620)
const ACCESS_CONTROL_ADVANCED_PATTERNS = [
  {
    id: 'SOL2606',
    name: 'Admin Key Single Point of Failure',
    severity: 'critical' as const,
    pattern: /admin[\s\S]{0,50}(pubkey|authority|key)(?![\s\S]{0,100}(multisig|threshold|quorum))/i,
    description: 'Single admin key controls critical functions. From Accretion audit findings.',
    recommendation: 'Use multisig or threshold signatures for admin operations.'
  },
  {
    id: 'SOL2607',
    name: 'Privilege Escalation via Upgrade',
    severity: 'critical' as const,
    pattern: /upgrade[\s\S]{0,50}(authority|program)(?![\s\S]{0,100}timelock)/i,
    description: 'Program upgrade without timelock enables immediate privilege escalation.',
    recommendation: 'Implement upgrade timelock with governance oversight.'
  },
  {
    id: 'SOL2608',
    name: 'Role Assignment Without Revocation',
    severity: 'high' as const,
    pattern: /role[\s\S]{0,50}(assign|grant|add)(?![\s\S]{0,200}(revoke|remove|delete))/i,
    description: 'Role assignment exists but revocation mechanism missing.',
    recommendation: 'Always implement role revocation alongside assignment.'
  },
  {
    id: 'SOL2609',
    name: 'Emergency Admin Backdoor',
    severity: 'critical' as const,
    pattern: /emergency[\s\S]{0,50}(admin|owner|authority)(?![\s\S]{0,100}(timelock|multisig))/i,
    description: 'Emergency admin functions without additional safeguards.',
    recommendation: 'Even emergency functions need timelock or multisig for non-emergency use.'
  },
  {
    id: 'SOL2610',
    name: 'Authority Transfer Without 2-Step',
    severity: 'high' as const,
    pattern: /authority[\s\S]{0,30}=[\s\S]{0,30}new_authority(?![\s\S]{0,100}(pending|accept))/i,
    description: 'Authority transfer immediate without 2-step process.',
    recommendation: 'Use 2-step transfer: propose then accept, to prevent accidental loss.'
  },
  {
    id: 'SOL2611',
    name: 'Guardian Set Update Without Delay',
    severity: 'critical' as const,
    pattern: /guardian[\s\S]{0,50}(set|update|change)(?![\s\S]{0,100}delay)/i,
    description: 'Guardian set can be changed immediately. From Wormhole analysis.',
    recommendation: 'Guardian changes should have significant delay (24-72 hours).'
  },
  {
    id: 'SOL2612',
    name: 'Pauser Role Without Unpauser',
    severity: 'high' as const,
    pattern: /pause[\s\S]{0,50}(only|require)(?![\s\S]{0,200}unpause)/i,
    description: 'Pause functionality exists but unpause may be missing or restricted.',
    recommendation: 'Ensure unpause mechanism exists and is properly controlled.'
  },
  {
    id: 'SOL2613',
    name: 'Config Update Without Bounds',
    severity: 'high' as const,
    pattern: /config[\s\S]{0,30}(update|set)[\s\S]{0,50}(param|value)(?![\s\S]{0,100}(valid|bound|range))/i,
    description: 'Configuration parameters can be set to arbitrary values.',
    recommendation: 'Validate config parameters against acceptable bounds.'
  },
  {
    id: 'SOL2614',
    name: 'CPI Authority Leak',
    severity: 'critical' as const,
    pattern: /invoke_signed[\s\S]{0,100}(signer|authority)(?![\s\S]{0,100}scope_check)/i,
    description: 'PDA signing authority may be used beyond intended scope via CPI.',
    recommendation: 'Verify CPI operations are within intended authority scope.'
  },
  {
    id: 'SOL2615',
    name: 'Operator Privilege Creep',
    severity: 'high' as const,
    pattern: /operator[\s\S]{0,50}(can|allow|permit)(?![\s\S]{0,100}(only|specific|limited))/i,
    description: 'Operator role has more privileges than necessary.',
    recommendation: 'Minimize operator privileges to only required operations.'
  },
  {
    id: 'SOL2616',
    name: 'Treasury Access Without Multi-Approval',
    severity: 'critical' as const,
    pattern: /treasury[\s\S]{0,50}(withdraw|transfer|spend)(?![\s\S]{0,100}(multisig|quorum|threshold))/i,
    description: 'Treasury access with single signature. From real-world DAO attacks.',
    recommendation: 'Require multi-approval for treasury operations.'
  },
  {
    id: 'SOL2617',
    name: 'Time-Based Access Not UTC',
    severity: 'medium' as const,
    pattern: /(start_time|end_time|deadline)[\s\S]{0,50}(check|compare)(?![\s\S]{0,100}utc)/i,
    description: 'Time-based access control may use inconsistent time zones.',
    recommendation: 'Always use UTC timestamps for time-based access control.'
  },
  {
    id: 'SOL2618',
    name: 'Access Control Log Missing',
    severity: 'low' as const,
    pattern: /(admin|owner|authority)[\s\S]{0,50}(action|call)(?![\s\S]{0,200}(emit|log|event))/i,
    description: 'Privileged actions not logged for audit trail.',
    recommendation: 'Emit events for all privileged operations for forensics.'
  },
  {
    id: 'SOL2619',
    name: 'Rate Limit Per User Missing',
    severity: 'medium' as const,
    pattern: /rate_limit[\s\S]{0,50}(global|total)(?![\s\S]{0,100}(per_user|individual))/i,
    description: 'Global rate limit but no per-user limit enables single user to consume quota.',
    recommendation: 'Implement both global and per-user rate limits.'
  },
  {
    id: 'SOL2620',
    name: 'Cross-Program Authority Confusion',
    severity: 'high' as const,
    pattern: /invoke[\s\S]{0,100}(authority|signer)[\s\S]{0,100}(different|external)_program/i,
    description: 'Authority from one program used to sign for different program.',
    recommendation: 'Verify authority context matches expected program.'
  },
];

// Rust Memory Safety Patterns (SOL2621-SOL2630)
const MEMORY_SAFETY_PATTERNS = [
  {
    id: 'SOL2621',
    name: 'Unsafe Block Without Justification',
    severity: 'high' as const,
    pattern: /unsafe\s*\{[\s\S]{0,200}(?!\/\/\s*(SAFETY|JUSTIFICATION|REASON))/i,
    description: 'Unsafe Rust block without safety justification comment.',
    recommendation: 'Document why unsafe is necessary and why it is safe in this context.'
  },
  {
    id: 'SOL2622',
    name: 'Zero-Copy Aliasing Risk',
    severity: 'critical' as const,
    pattern: /zero_copy[\s\S]{0,100}(borrow|ref)[\s\S]{0,100}(mut|mutable)/i,
    description: 'Zero-copy account with mutable borrow may cause aliasing. From Three Sigma research.',
    recommendation: 'Avoid mutable borrows with zero-copy accounts or use RefCell carefully.'
  },
  {
    id: 'SOL2623',
    name: 'Raw Pointer Dereference',
    severity: 'critical' as const,
    pattern: /\*\s*(const|mut)\s*\w+[\s\S]{0,50}as\s*\*(?![\s\S]{0,50}null_check)/i,
    description: 'Raw pointer dereference without null check.',
    recommendation: 'Always verify pointer is non-null before dereferencing.'
  },
  {
    id: 'SOL2624',
    name: 'Uninitialized Memory Read',
    severity: 'critical' as const,
    pattern: /MaybeUninit[\s\S]{0,50}assume_init(?![\s\S]{0,100}(after|once|when).*init)/i,
    description: 'Assuming memory is initialized without verification.',
    recommendation: 'Only call assume_init after provably initializing all bytes.'
  },
  {
    id: 'SOL2625',
    name: 'Transmute Type Size Mismatch',
    severity: 'critical' as const,
    pattern: /transmute[\s\S]{0,50}<[\s\S]{0,50},[\s\S]{0,50}>(?![\s\S]{0,100}size_of.*==)/i,
    description: 'Type transmutation without size verification.',
    recommendation: 'Verify source and destination types have identical size before transmute.'
  },
  {
    id: 'SOL2626',
    name: 'Slice Index Without Bounds',
    severity: 'high' as const,
    pattern: /\[\s*\w+\s*\](?![\s\S]{0,30}(get|get_unchecked|\.len\(\)))/i,
    description: 'Array/slice indexing without bounds check.',
    recommendation: 'Use .get() or verify index is within bounds before indexing.'
  },
  {
    id: 'SOL2627',
    name: 'Iterator Invalidation',
    severity: 'high' as const,
    pattern: /for[\s\S]{0,50}in[\s\S]{0,50}\.iter\(\)[\s\S]{0,100}(push|remove|insert)/i,
    description: 'Modifying collection while iterating over it.',
    recommendation: 'Collect modifications and apply after iteration completes.'
  },
  {
    id: 'SOL2628',
    name: 'Stack Overflow from Deep Recursion',
    severity: 'high' as const,
    pattern: /fn\s+\w+[\s\S]{0,100}\1\s*\((?![\s\S]{0,100}depth.*limit)/i,
    description: 'Recursive function without depth limit.',
    recommendation: 'Add recursion depth limit or convert to iterative approach.'
  },
  {
    id: 'SOL2629',
    name: 'Data Race in Parallel Processing',
    severity: 'critical' as const,
    pattern: /(rayon|parallel|thread)[\s\S]{0,100}(mut|write)[\s\S]{0,50}shared(?![\s\S]{0,100}(mutex|lock|atomic))/i,
    description: 'Shared mutable state in parallel code without synchronization.',
    recommendation: 'Use Mutex, RwLock, or atomic types for shared mutable state.'
  },
  {
    id: 'SOL2630',
    name: 'Integer Cast Overflow in Size Calculation',
    severity: 'high' as const,
    pattern: /(size|len|count)[\s\S]{0,30}as\s*(u32|u16|u8)(?![\s\S]{0,50}try_into)/i,
    description: 'Casting larger integer to smaller type for size may overflow.',
    recommendation: 'Use try_into() for safe casting or verify value fits in target type.'
  },
];

const ALL_BATCH_61_PATTERNS = [
  ...ORACLE_ADVANCED_PATTERNS,
  ...REFERRAL_FEE_PATTERNS,
  ...WITHDRAWAL_DEPOSIT_PATTERNS,
  ...ACCESS_CONTROL_ADVANCED_PATTERNS,
  ...MEMORY_SAFETY_PATTERNS,
];

/**
 * Run Batch 61 patterns
 */
export function checkBatch61Patterns(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  const fileName = input.path || input.rust?.filePath || 'unknown';
  
  if (!content) return findings;
  
  const lines = content.split('\n');
  
  for (const pattern of ALL_BATCH_61_PATTERNS) {
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

export const BATCH_61_PATTERN_COUNT = ALL_BATCH_61_PATTERNS.length;
