/**
 * SolGuard Pattern Batch 62: Protocol-Specific & Economic Security
 * 
 * Based on:
 * - BlockHacks $600M+ Solana Exploit Analysis
 * - Hacken 2024-2025 Web3 Security Report (80% access control exploits)
 * - arXiv "Exploring Vulnerabilities in Solana Smart Contracts" (Apr 2025)
 * - Real-world DeFi exploit patterns
 * 
 * Patterns: SOL2631-SOL2700
 */

import type { Finding, PatternInput } from './index.js';

// Lending Protocol Patterns (SOL2631-SOL2650)
const LENDING_PROTOCOL_PATTERNS = [
  {
    id: 'SOL2631',
    name: 'Borrow Without Collateral Ratio Check',
    severity: 'critical' as const,
    pattern: /borrow[\s\S]{0,100}(amount|value)(?![\s\S]{0,100}(collateral|health|ratio))/i,
    description: 'Borrow operation without collateral ratio verification.',
    recommendation: 'Always verify collateral ratio before allowing borrows.'
  },
  {
    id: 'SOL2632',
    name: 'Liquidation Threshold Same as Collateral Factor',
    severity: 'high' as const,
    pattern: /liquidation_threshold[\s\S]{0,30}==[\s\S]{0,30}collateral_factor/i,
    description: 'No buffer between borrow limit and liquidation. Users instantly liquidatable.',
    recommendation: 'Set liquidation threshold higher than collateral factor (e.g., 82.5% vs 80%).'
  },
  {
    id: 'SOL2633',
    name: 'Interest Rate Model Kink Missing',
    severity: 'medium' as const,
    pattern: /interest_rate[\s\S]{0,100}(utilization|usage)(?![\s\S]{0,100}kink)/i,
    description: 'Linear interest rate model without utilization kink.',
    recommendation: 'Use kinked model: low rates until optimal utilization, then steep increase.'
  },
  {
    id: 'SOL2634',
    name: 'Bad Debt Socialization Missing',
    severity: 'high' as const,
    pattern: /liquidat[\s\S]{0,100}(shortfall|bad_debt|loss)(?![\s\S]{0,100}(socialize|distribute|reserve))/i,
    description: 'No mechanism to handle bad debt from underwater positions.',
    recommendation: 'Implement bad debt socialization or insurance fund mechanism.'
  },
  {
    id: 'SOL2635',
    name: 'Reserve Factor Zero',
    severity: 'medium' as const,
    pattern: /reserve_factor[\s\S]{0,10}=[\s\S]{0,10}0(?![\s\S]{0,30}\d)/i,
    description: 'Zero reserve factor means no protocol revenue or insurance.',
    recommendation: 'Set reserve factor > 0 for protocol sustainability and insurance.'
  },
  {
    id: 'SOL2636',
    name: 'Liquidation Close Factor 100%',
    severity: 'high' as const,
    pattern: /close_factor[\s\S]{0,10}=[\s\S]{0,10}(100|10000|1\.0)/i,
    description: 'Full liquidation allowed. Users lose entire position unfairly.',
    recommendation: 'Limit close factor to 50% to allow partial recovery.'
  },
  {
    id: 'SOL2637',
    name: 'Stale Borrow Index',
    severity: 'high' as const,
    pattern: /borrow_index[\s\S]{0,50}(get|fetch)(?![\s\S]{0,100}(update|accrue|refresh))/i,
    description: 'Using borrow index without accruing interest first.',
    recommendation: 'Always accrue interest before using borrow index.'
  },
  {
    id: 'SOL2638',
    name: 'Supply Cap Not Per-Token',
    severity: 'medium' as const,
    pattern: /supply_cap[\s\S]{0,30}(global|total)(?![\s\S]{0,100}per_token)/i,
    description: 'Global supply cap but no per-token limit. Single token can dominate.',
    recommendation: 'Implement per-token supply caps based on liquidity.'
  },
  {
    id: 'SOL2639',
    name: 'Borrow Cap Not Enforced',
    severity: 'high' as const,
    pattern: /borrow[\s\S]{0,100}(amount|value)(?![\s\S]{0,100}(cap|limit|max))/i,
    description: 'No borrow cap allows unlimited borrowing of scarce assets.',
    recommendation: 'Enforce borrow caps based on available liquidity.'
  },
  {
    id: 'SOL2640',
    name: 'Repay More Than Owed',
    severity: 'medium' as const,
    pattern: /repay[\s\S]{0,100}amount(?![\s\S]{0,100}(min|cap|owed|debt))/i,
    description: 'Repayment amount not capped at debt owed.',
    recommendation: 'Cap repayment at outstanding debt to prevent overpayment.'
  },
  {
    id: 'SOL2641',
    name: 'Interest Accrual Timestamp Manipulation',
    severity: 'high' as const,
    pattern: /interest[\s\S]{0,50}(accrue|calculate)[\s\S]{0,50}timestamp(?![\s\S]{0,100}slot)/i,
    description: 'Interest based on timestamp instead of slot. Slot is harder to manipulate.',
    recommendation: 'Use slot-based time for interest calculations when possible.'
  },
  {
    id: 'SOL2642',
    name: 'Collateral Withdraw During Borrow',
    severity: 'critical' as const,
    pattern: /withdraw[\s\S]{0,100}collateral(?![\s\S]{0,100}(borrow|debt|health).*check)/i,
    description: 'Collateral withdrawal without checking outstanding borrows.',
    recommendation: 'Always verify health factor remains safe after collateral withdrawal.'
  },
  {
    id: 'SOL2643',
    name: 'Flash Loan Without Same-Transaction Repay',
    severity: 'critical' as const,
    pattern: /flash[\s\S]{0,50}loan[\s\S]{0,100}(?![\s\S]{0,200}(same|within|this).*transaction)/i,
    description: 'Flash loan mechanism may not enforce same-transaction repayment.',
    recommendation: 'Verify repayment occurs within same transaction using instruction introspection.'
  },
  {
    id: 'SOL2644',
    name: 'Liquidator Bonus From Depositors',
    severity: 'high' as const,
    pattern: /liquidat[\s\S]{0,50}(bonus|discount)(?![\s\S]{0,100}(reserve|protocol))/i,
    description: 'Liquidation bonus comes from depositors, not protocol.',
    recommendation: 'Fund liquidation incentives from reserve to protect depositors.'
  },
  {
    id: 'SOL2645',
    name: 'No Liquidation Protection Period',
    severity: 'medium' as const,
    pattern: /liquidat[\s\S]{0,100}(check|trigger)(?![\s\S]{0,100}(grace|delay|protection))/i,
    description: 'Users liquidated immediately without chance to add collateral.',
    recommendation: 'Consider grace period before liquidation is allowed.'
  },
  {
    id: 'SOL2646',
    name: 'Isolated Asset Not Actually Isolated',
    severity: 'high' as const,
    pattern: /isolated[\s\S]{0,50}(asset|collateral)(?![\s\S]{0,100}(only|single|exclusive))/i,
    description: 'Isolated collateral mode may still allow cross-collateralization.',
    recommendation: 'Verify isolated assets truly cannot cross-collateralize.'
  },
  {
    id: 'SOL2647',
    name: 'E-Mode Configuration Incorrect',
    severity: 'high' as const,
    pattern: /e_mode|efficiency_mode[\s\S]{0,100}(ltv|threshold)(?![\s\S]{0,100}validate)/i,
    description: 'E-mode parameters not validated for correlated assets.',
    recommendation: 'Validate e-mode assets are actually correlated before higher LTV.'
  },
  {
    id: 'SOL2648',
    name: 'Debt Ceiling Per Asset Missing',
    severity: 'medium' as const,
    pattern: /debt[\s\S]{0,50}(cap|limit|ceiling)(?![\s\S]{0,100}per_(asset|token))/i,
    description: 'Global debt ceiling but no per-asset limits.',
    recommendation: 'Set per-asset debt ceilings based on risk assessment.'
  },
  {
    id: 'SOL2649',
    name: 'Oracle Price Bounds Not Set',
    severity: 'high' as const,
    pattern: /oracle[\s\S]{0,50}price(?![\s\S]{0,100}(min_price|max_price|bound))/i,
    description: 'No minimum/maximum bounds on oracle prices.',
    recommendation: 'Set price bounds to prevent extreme oracle failures.'
  },
  {
    id: 'SOL2650',
    name: 'Liquidation Reward Exceeds Debt',
    severity: 'high' as const,
    pattern: /liquidat[\s\S]{0,100}(reward|bonus)(?![\s\S]{0,100}(cap|min.*debt))/i,
    description: 'Liquidation reward could exceed debt being repaid.',
    recommendation: 'Cap liquidation reward at repaid debt plus reasonable bonus.'
  },
];

// DEX & AMM Patterns (SOL2651-SOL2670)
const DEX_AMM_PATTERNS = [
  {
    id: 'SOL2651',
    name: 'AMM K Value Not Preserved',
    severity: 'critical' as const,
    pattern: /(swap|trade)[\s\S]{0,100}(reserve|balance)(?![\s\S]{0,100}(k_value|invariant|constant_product))/i,
    description: 'Constant product invariant (k=x*y) not verified after swap.',
    recommendation: 'Always verify k value is preserved or increased after swap.'
  },
  {
    id: 'SOL2652',
    name: 'Concentrated Liquidity Out of Range',
    severity: 'high' as const,
    pattern: /(clmm|concentrated)[\s\S]{0,100}(liquidity|position)(?![\s\S]{0,100}(range|tick|bound))/i,
    description: 'Concentrated liquidity position tick range not validated.',
    recommendation: 'Verify position tick range is valid and within pool bounds.'
  },
  {
    id: 'SOL2653',
    name: 'LP Share Inflation on First Deposit',
    severity: 'critical' as const,
    pattern: /lp[\s\S]{0,50}(share|token|mint)[\s\S]{0,100}(total.*==.*0|first.*deposit)/i,
    description: 'First LP depositor can manipulate share price.',
    recommendation: 'Mint initial LP tokens to dead address or use minimum liquidity.'
  },
  {
    id: 'SOL2654',
    name: 'Swap Output Amount Zero',
    severity: 'high' as const,
    pattern: /swap[\s\S]{0,100}(output|out|amount_out)(?![\s\S]{0,100}(>|greater|minimum|min))/i,
    description: 'Swap may return zero output for dust amounts.',
    recommendation: 'Verify output amount is non-zero and meets minimum.'
  },
  {
    id: 'SOL2655',
    name: 'Pool Fee Not Applied Correctly',
    severity: 'high' as const,
    pattern: /swap[\s\S]{0,50}(fee|commission)(?![\s\S]{0,100}(before|deduct|subtract).*output)/i,
    description: 'Fee deducted from wrong side or at wrong time.',
    recommendation: 'Deduct fee from input or add to output consistently.'
  },
  {
    id: 'SOL2656',
    name: 'Virtual Reserves Manipulation',
    severity: 'high' as const,
    pattern: /virtual[\s\S]{0,30}(reserve|balance)(?![\s\S]{0,100}(bound|limit|verify))/i,
    description: 'Virtual reserves can be manipulated to affect pricing.',
    recommendation: 'Bound virtual reserves and verify consistency with real reserves.'
  },
  {
    id: 'SOL2657',
    name: 'Price Impact Calculation Missing',
    severity: 'high' as const,
    pattern: /(swap|trade)[\s\S]{0,100}(execute|process)(?![\s\S]{0,100}price_impact)/i,
    description: 'Trade executed without calculating or limiting price impact.',
    recommendation: 'Calculate price impact and reject trades exceeding threshold.'
  },
  {
    id: 'SOL2658',
    name: 'Tick Spacing Validation Missing',
    severity: 'medium' as const,
    pattern: /tick[\s\S]{0,30}(lower|upper|index)(?![\s\S]{0,100}(spacing|modulo|divisible))/i,
    description: 'Tick values not validated against tick spacing.',
    recommendation: 'Verify ticks are divisible by tick spacing.'
  },
  {
    id: 'SOL2659',
    name: 'Sqrt Price X96 Overflow',
    severity: 'high' as const,
    pattern: /sqrt[\s\S]{0,30}price[\s\S]{0,30}(x96|q64)(?![\s\S]{0,100}(bound|overflow|check))/i,
    description: 'Fixed-point sqrt price calculations may overflow.',
    recommendation: 'Use checked math for sqrt price calculations.'
  },
  {
    id: 'SOL2660',
    name: 'Liquidity Delta Sign Confusion',
    severity: 'high' as const,
    pattern: /liquidity[\s\S]{0,30}delta[\s\S]{0,30}(i128|signed)(?![\s\S]{0,100}(positive|negative|check))/i,
    description: 'Signed liquidity delta may be confused (add vs remove).',
    recommendation: 'Explicitly handle positive (add) and negative (remove) delta.'
  },
  {
    id: 'SOL2661',
    name: 'Pool Creation Without Fee Tier',
    severity: 'medium' as const,
    pattern: /pool[\s\S]{0,50}(create|init)(?![\s\S]{0,100}fee_(tier|rate|bps))/i,
    description: 'Pool created without specifying fee tier.',
    recommendation: 'Require explicit fee tier selection on pool creation.'
  },
  {
    id: 'SOL2662',
    name: 'Swap Route Validation Missing',
    severity: 'high' as const,
    pattern: /(route|path|hop)[\s\S]{0,50}(execute|swap)(?![\s\S]{0,100}(validate|verify|check))/i,
    description: 'Multi-hop swap route not validated for consistency.',
    recommendation: 'Validate each hop in route and verify final token matches expected.'
  },
  {
    id: 'SOL2663',
    name: 'Protocol Fee Receiver Mutable',
    severity: 'medium' as const,
    pattern: /protocol_fee[\s\S]{0,50}(receiver|recipient)[\s\S]{0,30}mut/i,
    description: 'Protocol fee receiver can be changed by admin.',
    recommendation: 'Use timelock for fee receiver changes or make immutable.'
  },
  {
    id: 'SOL2664',
    name: 'Flash Swap Callback Reentrancy',
    severity: 'critical' as const,
    pattern: /flash[\s\S]{0,50}swap[\s\S]{0,100}callback(?![\s\S]{0,100}(guard|lock|reentr))/i,
    description: 'Flash swap callback may enable reentrancy.',
    recommendation: 'Add reentrancy guard around flash swap operations.'
  },
  {
    id: 'SOL2665',
    name: 'Observation Array Not Updated',
    severity: 'medium' as const,
    pattern: /observation[\s\S]{0,50}(array|buffer)(?![\s\S]{0,100}(update|write|grow))/i,
    description: 'TWAP observation array not updated on trades.',
    recommendation: 'Update observation array on every swap for accurate TWAP.'
  },
  {
    id: 'SOL2666',
    name: 'Position NFT Transfer Unchecked',
    severity: 'high' as const,
    pattern: /position[\s\S]{0,50}(nft|token)[\s\S]{0,50}transfer(?![\s\S]{0,100}(authority|owner).*check)/i,
    description: 'Position NFT transfer without ownership verification.',
    recommendation: 'Verify caller owns position NFT before allowing operations.'
  },
  {
    id: 'SOL2667',
    name: 'Pool Paused But Withdrawals Blocked',
    severity: 'high' as const,
    pattern: /pool[\s\S]{0,30}paused(?![\s\S]{0,200}withdraw.*allow)/i,
    description: 'Paused pool blocks all operations including user fund withdrawal.',
    recommendation: 'Always allow withdrawals even when pool is paused.'
  },
  {
    id: 'SOL2668',
    name: 'Zero Liquidity Check Missing',
    severity: 'high' as const,
    pattern: /swap[\s\S]{0,100}(execute|process)(?![\s\S]{0,100}liquidity.*>.*0)/i,
    description: 'Swap attempted on pool with zero liquidity.',
    recommendation: 'Verify pool has liquidity before executing swaps.'
  },
  {
    id: 'SOL2669',
    name: 'Reward Token Drain via Collect',
    severity: 'high' as const,
    pattern: /collect[\s\S]{0,50}(reward|fee)(?![\s\S]{0,100}(owner|position).*check)/i,
    description: 'Anyone can collect rewards not belonging to them.',
    recommendation: 'Verify caller owns the position before collecting rewards.'
  },
  {
    id: 'SOL2670',
    name: 'Emergency Withdraw Forfeits Rewards',
    severity: 'medium' as const,
    pattern: /emergency[\s\S]{0,30}withdraw(?![\s\S]{0,100}(reward|fee).*collect)/i,
    description: 'Emergency withdrawal loses accrued rewards.',
    recommendation: 'Collect rewards before emergency withdrawal or return them.'
  },
];

// Staking & Validator Patterns (SOL2671-SOL2685)
const STAKING_VALIDATOR_PATTERNS = [
  {
    id: 'SOL2671',
    name: 'Stake Pool Commission Unlimited',
    severity: 'high' as const,
    pattern: /commission[\s\S]{0,30}(fee|rate|percent)(?![\s\S]{0,100}(max|cap|limit))/i,
    description: 'Stake pool commission can be set to 100%.',
    recommendation: 'Cap commission at reasonable maximum (e.g., 10%).'
  },
  {
    id: 'SOL2672',
    name: 'Validator Set Not Verified',
    severity: 'high' as const,
    pattern: /validator[\s\S]{0,50}(vote|identity)(?![\s\S]{0,100}(verify|whitelist|approved))/i,
    description: 'Delegating to validators without verification.',
    recommendation: 'Maintain approved validator list or verify vote account.'
  },
  {
    id: 'SOL2673',
    name: 'Unstake Without Cooldown',
    severity: 'medium' as const,
    pattern: /unstake[\s\S]{0,100}(execute|process)(?![\s\S]{0,100}(cooldown|delay|epoch))/i,
    description: 'Instant unstake without cooldown period.',
    recommendation: 'Enforce unstaking cooldown aligned with Solana epochs.'
  },
  {
    id: 'SOL2674',
    name: 'Stake Pool Reserve Insufficient',
    severity: 'high' as const,
    pattern: /stake[\s\S]{0,30}pool[\s\S]{0,50}reserve(?![\s\S]{0,100}minimum)/i,
    description: 'Stake pool reserve for instant withdrawals may be insufficient.',
    recommendation: 'Maintain minimum reserve ratio for withdrawal liquidity.'
  },
  {
    id: 'SOL2675',
    name: 'Validator Commission Change Instant',
    severity: 'medium' as const,
    pattern: /validator[\s\S]{0,50}commission[\s\S]{0,30}(set|update)(?![\s\S]{0,100}(delay|notice|timelock))/i,
    description: 'Validator can instantly increase commission.',
    recommendation: 'Require advance notice for commission increases.'
  },
  {
    id: 'SOL2676',
    name: 'Slashing Not Handled',
    severity: 'critical' as const,
    pattern: /stake[\s\S]{0,100}(reward|yield)(?![\s\S]{0,200}(slash|penalty|loss))/i,
    description: 'Staking protocol does not handle validator slashing.',
    recommendation: 'Implement slashing detection and loss distribution.'
  },
  {
    id: 'SOL2677',
    name: 'Reward Distribution Not Pro-Rata',
    severity: 'high' as const,
    pattern: /reward[\s\S]{0,50}distribut(?![\s\S]{0,100}(pro_rata|proportion|share))/i,
    description: 'Rewards not distributed proportionally to stake.',
    recommendation: 'Distribute rewards proportional to stake share.'
  },
  {
    id: 'SOL2678',
    name: 'Stake Account Not Delegated',
    severity: 'medium' as const,
    pattern: /stake[\s\S]{0,30}account[\s\S]{0,50}(create|init)(?![\s\S]{0,100}delegat)/i,
    description: 'Stake account created but not delegated to validator.',
    recommendation: 'Delegate stake accounts to earn rewards.'
  },
  {
    id: 'SOL2679',
    name: 'Epoch Boundary Reward Timing',
    severity: 'medium' as const,
    pattern: /epoch[\s\S]{0,50}(reward|yield|return)(?![\s\S]{0,100}(boundary|transition|change))/i,
    description: 'Reward calculation may miss epoch boundary edge cases.',
    recommendation: 'Handle epoch transitions explicitly in reward calculations.'
  },
  {
    id: 'SOL2680',
    name: 'Delegation Strategy Manipulation',
    severity: 'high' as const,
    pattern: /delegat[\s\S]{0,50}(strategy|allocation)(?![\s\S]{0,100}(validate|verify|bound))/i,
    description: 'Delegation strategy can concentrate stake on few validators.',
    recommendation: 'Enforce diversification limits in delegation strategy.'
  },
  {
    id: 'SOL2681',
    name: 'Liquid Stake Token Depeg',
    severity: 'high' as const,
    pattern: /(lst|liquid_stake)[\s\S]{0,50}(token|mint)(?![\s\S]{0,100}(backing|reserve|peg))/i,
    description: 'Liquid staking token may depeg from underlying SOL.',
    recommendation: 'Ensure LST is always backed by >= equivalent staked SOL.'
  },
  {
    id: 'SOL2682',
    name: 'Stake Account Authority Not Transferred',
    severity: 'high' as const,
    pattern: /stake[\s\S]{0,30}account[\s\S]{0,50}(authority|withdraw)(?![\s\S]{0,100}(transfer|assign|pool))/i,
    description: 'Stake account authority not transferred to pool.',
    recommendation: 'Transfer stake authority to pool PDA for proper management.'
  },
  {
    id: 'SOL2683',
    name: 'Validator Vote Account Mismatch',
    severity: 'high' as const,
    pattern: /validator[\s\S]{0,50}(pubkey|address)[\s\S]{0,50}vote(?![\s\S]{0,100}(match|verify|check))/i,
    description: 'Validator identity not verified against vote account.',
    recommendation: 'Verify validator identity matches vote account.'
  },
  {
    id: 'SOL2684',
    name: 'Stake Pool SOL Counting Error',
    severity: 'high' as const,
    pattern: /total[\s\S]{0,30}(sol|lamports)[\s\S]{0,50}(count|sum)(?![\s\S]{0,100}(all|every|stake.*reserve))/i,
    description: 'Total SOL calculation may miss some accounts.',
    recommendation: 'Include all SOL: staked + reserve + rent-exempt.'
  },
  {
    id: 'SOL2685',
    name: 'Stake Pool Fee Update Without Notice',
    severity: 'medium' as const,
    pattern: /pool[\s\S]{0,30}fee[\s\S]{0,30}(update|change)(?![\s\S]{0,100}(notice|delay|timelock))/i,
    description: 'Pool fees can change instantly without user notice.',
    recommendation: 'Require advance notice for fee increases.'
  },
];

// Token Security Patterns (SOL2686-SOL2700)
const TOKEN_SECURITY_PATTERNS = [
  {
    id: 'SOL2686',
    name: 'Mint Authority Not Revoked',
    severity: 'high' as const,
    pattern: /mint[\s\S]{0,30}authority(?![\s\S]{0,100}(none|revoke|null|zero))/i,
    description: 'Token mint authority still active, enabling unlimited minting.',
    recommendation: 'Revoke mint authority for fixed-supply tokens.'
  },
  {
    id: 'SOL2687',
    name: 'Freeze Authority Centralized',
    severity: 'medium' as const,
    pattern: /freeze[\s\S]{0,30}authority(?![\s\S]{0,100}(multisig|none|revoke))/i,
    description: 'Single entity can freeze any token account.',
    recommendation: 'Use multisig for freeze authority or revoke if not needed.'
  },
  {
    id: 'SOL2688',
    name: 'Token Extension Incompatibility',
    severity: 'high' as const,
    pattern: /token_2022[\s\S]{0,100}extension(?![\s\S]{0,100}(compat|support|check))/i,
    description: 'Token-2022 extensions may conflict with protocol logic.',
    recommendation: 'Test protocol with all relevant token extensions.'
  },
  {
    id: 'SOL2689',
    name: 'Transfer Hook Reentrancy',
    severity: 'critical' as const,
    pattern: /transfer_hook[\s\S]{0,100}(invoke|call)(?![\s\S]{0,100}(guard|lock))/i,
    description: 'Transfer hook may enable reentrancy attacks.',
    recommendation: 'Add reentrancy protection around transfer hooks.'
  },
  {
    id: 'SOL2690',
    name: 'Confidential Transfer Leak',
    severity: 'high' as const,
    pattern: /confidential[\s\S]{0,50}transfer(?![\s\S]{0,100}(audit|verify|proof))/i,
    description: 'Confidential transfer amounts may leak through other means.',
    recommendation: 'Ensure all related operations maintain confidentiality.'
  },
  {
    id: 'SOL2691',
    name: 'Permanent Delegate Abuse',
    severity: 'critical' as const,
    pattern: /permanent[\s\S]{0,30}delegate(?![\s\S]{0,100}(warn|consent|aware))/i,
    description: 'Permanent delegate can drain tokens without user consent.',
    recommendation: 'Warn users about permanent delegate, require explicit consent.'
  },
  {
    id: 'SOL2692',
    name: 'Interest-Bearing Token Accrual',
    severity: 'high' as const,
    pattern: /interest[\s\S]{0,30}bearing[\s\S]{0,50}(token|mint)(?![\s\S]{0,100}(rate|accrue).*check)/i,
    description: 'Interest-bearing token rate may be manipulated.',
    recommendation: 'Validate interest rate is within acceptable bounds.'
  },
  {
    id: 'SOL2693',
    name: 'Non-Transferable Token Override',
    severity: 'high' as const,
    pattern: /non_transferable(?![\s\S]{0,100}(enforce|block|prevent))/i,
    description: 'Non-transferable token constraint may be bypassed.',
    recommendation: 'Verify transfer is actually blocked in all code paths.'
  },
  {
    id: 'SOL2694',
    name: 'Memo Required Not Checked',
    severity: 'low' as const,
    pattern: /memo[\s\S]{0,30}required(?![\s\S]{0,100}(check|verify|enforce))/i,
    description: 'Memo requirement declared but not enforced.',
    recommendation: 'Actually check memo presence when required.'
  },
  {
    id: 'SOL2695',
    name: 'Default Account State Unexpected',
    severity: 'medium' as const,
    pattern: /default[\s\S]{0,30}account[\s\S]{0,30}state(?![\s\S]{0,100}(expect|handle|check))/i,
    description: 'Token-2022 default account state may differ from expected.',
    recommendation: 'Handle both frozen and initialized default states.'
  },
  {
    id: 'SOL2696',
    name: 'Reallocate Without Size Check',
    severity: 'high' as const,
    pattern: /reallocat[\s\S]{0,50}(account|space)(?![\s\S]{0,100}(max|limit|bound))/i,
    description: 'Account reallocation without size limit.',
    recommendation: 'Limit reallocation size to prevent compute exhaustion.'
  },
  {
    id: 'SOL2697',
    name: 'CPI Guard State Ignored',
    severity: 'high' as const,
    pattern: /cpi_guard[\s\S]{0,50}(state|enabled)(?![\s\S]{0,100}check)/i,
    description: 'CPI guard state not checked before CPI operation.',
    recommendation: 'Check CPI guard state and fail if enabled when not expected.'
  },
  {
    id: 'SOL2698',
    name: 'Metadata Authority Mismatch',
    severity: 'high' as const,
    pattern: /metadata[\s\S]{0,50}authority(?![\s\S]{0,100}(verify|check|match))/i,
    description: 'Token metadata authority not verified against expected.',
    recommendation: 'Verify metadata authority matches expected before trusting data.'
  },
  {
    id: 'SOL2699',
    name: 'Token Burn Not Reducing Supply',
    severity: 'high' as const,
    pattern: /burn[\s\S]{0,100}(token|amount)(?![\s\S]{0,100}(supply.*decrement|total.*sub))/i,
    description: 'Token burn operation may not reduce total supply.',
    recommendation: 'Verify total supply decreases after burn.'
  },
  {
    id: 'SOL2700',
    name: 'Decimal Mismatch in Token Math',
    severity: 'high' as const,
    pattern: /(token_a|token_b)[\s\S]{0,50}(amount|value)[\s\S]{0,50}(add|sub|mul|div)(?![\s\S]{0,100}decimal)/i,
    description: 'Token arithmetic without considering different decimals.',
    recommendation: 'Normalize token amounts to same decimal scale before math.'
  },
];

const ALL_BATCH_62_PATTERNS = [
  ...LENDING_PROTOCOL_PATTERNS,
  ...DEX_AMM_PATTERNS,
  ...STAKING_VALIDATOR_PATTERNS,
  ...TOKEN_SECURITY_PATTERNS,
];

/**
 * Run Batch 62 patterns
 */
export function checkBatch62Patterns(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  const fileName = input.path || input.rust?.filePath || 'unknown';
  
  if (!content) return findings;
  
  const lines = content.split('\n');
  
  for (const pattern of ALL_BATCH_62_PATTERNS) {
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

export const BATCH_62_PATTERN_COUNT = ALL_BATCH_62_PATTERNS.length;
