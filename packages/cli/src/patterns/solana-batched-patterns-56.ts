/**
 * SolShield Security Patterns - Batch 56
 * 
 * 70 Patterns (SOL2211-SOL2280)
 * Sources:
 * - Neodyme PoC Framework Challenges
 * - sannykim/solsec PoC Collection
 * - Real-World Exploit Post-Mortems
 * - Protocol-Specific Security Research
 * 
 * Categories:
 * - PoC Framework Patterns (SOL2211-SOL2230)
 * - Protocol-Specific Exploits (SOL2231-SOL2255)
 * - Advanced DeFi Attack Vectors (SOL2256-SOL2280)
 */

import type { PatternInput, Finding } from './index.js';

/** Batch 56 Patterns: PoC + Protocol-Specific */
export const BATCH_56_PATTERNS = [
  // ========== PoC Framework Patterns (SOL2211-SOL2230) ==========
  {
    id: 'SOL2211',
    name: 'PoC: Port Max Withdraw Bug',
    severity: 'critical' as const,
    pattern: /max_withdraw|withdraw_max[\s\S]{0,100}(?:calculate|compute)[\s\S]{0,100}(?!floor|ceil)/i,
    description: 'Max withdraw calculation without rounding direction. Port Finance PoC.',
    recommendation: 'Use floor for withdraw calculations to prevent overdraft.'
  },
  {
    id: 'SOL2212',
    name: 'PoC: Jet Governance Token Lock',
    severity: 'high' as const,
    pattern: /governance[\s\S]{0,50}token[\s\S]{0,50}(?:lock|escrow)[\s\S]{0,100}(?!duration|until)/i,
    description: 'Governance token locking without duration. Jet Governance PoC.',
    recommendation: 'Enforce minimum lock duration for governance participation.'
  },
  {
    id: 'SOL2213',
    name: 'PoC: Cashio Infinite Mint',
    severity: 'critical' as const,
    pattern: /collateral[\s\S]{0,100}(?:deposit|provide)[\s\S]{0,100}(?:mint|issue)[\s\S]{0,100}(?!verify_root|whitelist)/i,
    description: 'Collateral deposit leading to mint without root verification. Cashio PoC.',
    recommendation: 'Verify collateral is in trusted mint whitelist.'
  },
  {
    id: 'SOL2214',
    name: 'PoC: SPL Token-Lending Rounding',
    severity: 'critical' as const,
    pattern: /(?:collateral|liquidity)[\s\S]{0,50}(?:ratio|value)[\s\S]{0,50}(?:div|\/)\s*\d+/i,
    description: 'Collateral value division. Neodyme $2.6B rounding PoC.',
    recommendation: 'Multiply before divide, use floor for protocol benefit.'
  },
  {
    id: 'SOL2215',
    name: 'PoC: Cope Roulette Revert',
    severity: 'medium' as const,
    pattern: /roulette|random[\s\S]{0,100}(?:win|lose|outcome)[\s\S]{0,100}(?!commit|reveal)/i,
    description: 'Random outcome without commit-reveal. Cope Roulette exploit.',
    recommendation: 'Use commit-reveal scheme for random outcomes.'
  },
  {
    id: 'SOL2216',
    name: 'PoC: Simulation Detection Bypass',
    severity: 'high' as const,
    pattern: /simulation|preflight[\s\S]{0,100}(?:detect|check)[\s\S]{0,100}(?!bank|slot)/i,
    description: 'Simulation detection without bank context. Opcodes research.',
    recommendation: 'Check bank state to detect simulation vs execution.'
  },
  {
    id: 'SOL2217',
    name: 'PoC: Authority Delegation Chain',
    severity: 'high' as const,
    pattern: /delegate[\s\S]{0,50}authority[\s\S]{0,100}(?:chain|nested|recursive)/i,
    description: 'Authority delegation allowing chains. Multi-hop vulnerability.',
    recommendation: 'Limit delegation depth to prevent authority confusion.'
  },
  {
    id: 'SOL2218',
    name: 'PoC: Token Approval Persistence',
    severity: 'medium' as const,
    pattern: /approve[\s\S]{0,50}delegate[\s\S]{0,100}(?!revoke|clear|reset)/i,
    description: 'Token approval without revocation mechanism. Hana revoken research.',
    recommendation: 'Provide clear approval revocation mechanism.'
  },
  {
    id: 'SOL2219',
    name: 'PoC: Stake Pool Semantic Bug',
    severity: 'high' as const,
    pattern: /stake_pool[\s\S]{0,100}(?:deposit|withdraw)[\s\S]{0,100}(?!validator_list|stake_list)/i,
    description: 'Stake pool operation without list verification. Sec3 Stake Pool PoC.',
    recommendation: 'Verify stake account is in pool validator list.'
  },
  {
    id: 'SOL2220',
    name: 'PoC: Lending Market Spoofing',
    severity: 'critical' as const,
    pattern: /lending_market[\s\S]{0,100}(?:create|init)[\s\S]{0,100}(?!authority|owner\s*==)/i,
    description: 'Lending market creation without authority binding. Solend exploit.',
    recommendation: 'Permanently bind lending market to authority at creation.'
  },
  {
    id: 'SOL2221',
    name: 'PoC: Oracle Price Staleness',
    severity: 'high' as const,
    pattern: /price[\s\S]{0,50}(?:get|fetch)[\s\S]{0,100}(?:age|stale|fresh|timestamp)/i,
    description: 'Price fetching with staleness check present but may be insufficient.',
    recommendation: 'Use strict staleness bounds (e.g., 30 seconds for DeFi).'
  },
  {
    id: 'SOL2222',
    name: 'PoC: LP Token Manipulation',
    severity: 'critical' as const,
    pattern: /lp_token[\s\S]{0,100}(?:value|worth|price)[\s\S]{0,50}(?:total_supply|reserve)/i,
    description: 'LP token value from reserves. OtterSec $200M manipulation PoC.',
    recommendation: 'Use virtual reserves or geometric mean for LP pricing.'
  },
  {
    id: 'SOL2223',
    name: 'PoC: Malicious Lending Market',
    severity: 'critical' as const,
    pattern: /malicious[\s\S]{0,50}(?:market|pool|reserve)|fake_(?:market|pool)/i,
    description: 'Malicious market pattern. Solend Rooter disclosure.',
    recommendation: 'Verify market authenticity via on-chain registry.'
  },
  {
    id: 'SOL2224',
    name: 'PoC: Guardian Quorum Bypass',
    severity: 'critical' as const,
    pattern: /guardian[\s\S]{0,100}(?:verify|check)[\s\S]{0,100}(?:signature|quorum)[\s\S]{0,100}(?!\d+\s*\/\s*\d+|threshold)/i,
    description: 'Guardian verification without quorum threshold. Wormhole pattern.',
    recommendation: 'Enforce minimum guardian signature quorum (e.g., 13/19).'
  },
  {
    id: 'SOL2225',
    name: 'PoC: SignatureSet Fabrication',
    severity: 'critical' as const,
    pattern: /signature_set|SignatureSet[\s\S]{0,100}(?:create|init)[\s\S]{0,100}(?!verify|validate)/i,
    description: 'SignatureSet creation without verification. Wormhole $326M exploit.',
    recommendation: 'Verify all signatures before creating SignatureSet.'
  },
  {
    id: 'SOL2226',
    name: 'PoC: CLMM Tick Manipulation',
    severity: 'critical' as const,
    pattern: /tick[\s\S]{0,50}(?:account|data)[\s\S]{0,100}(?:fee|liquidity)[\s\S]{0,100}(?!owner\s*==)/i,
    description: 'Tick account access without ownership. Crema $8.8M exploit.',
    recommendation: 'Verify tick account ownership before fee operations.'
  },
  {
    id: 'SOL2227',
    name: 'PoC: Bonding Curve Flash Loan',
    severity: 'critical' as const,
    pattern: /bonding_curve[\s\S]{0,100}(?:buy|mint)[\s\S]{0,100}(?!flash_loan_check|same_block)/i,
    description: 'Bonding curve without flash loan protection. Nirvana exploit.',
    recommendation: 'Add flash loan detection or multi-block price averaging.'
  },
  {
    id: 'SOL2228',
    name: 'PoC: Perp Mark Price Manipulation',
    severity: 'critical' as const,
    pattern: /mark_price|perp[\s\S]{0,100}(?:price|funding)[\s\S]{0,100}(?!oracle|twap|window)/i,
    description: 'Perpetual mark price without oracle verification. Mango pattern.',
    recommendation: 'Use oracle TWAP for mark price calculation.'
  },
  {
    id: 'SOL2229',
    name: 'PoC: Self-Trading Detection',
    severity: 'high' as const,
    pattern: /(?:buy|sell|trade)[\s\S]{0,200}(?:buy|sell|trade)[\s\S]{0,100}(?!different_owner|anti_self)/i,
    description: 'Trading without self-trade prevention. Mango Markets exploit.',
    recommendation: 'Detect and prevent self-trading for price manipulation.'
  },
  {
    id: 'SOL2230',
    name: 'PoC: Unrealized PnL Collateral',
    severity: 'critical' as const,
    pattern: /unrealized[\s\S]{0,50}(?:pnl|profit)[\s\S]{0,100}(?:collateral|borrow)/i,
    description: 'Using unrealized PnL as collateral. Mango Markets attack vector.',
    recommendation: 'Only use realized PnL for collateral calculations.'
  },

  // ========== Protocol-Specific Exploits (SOL2231-SOL2255) ==========
  {
    id: 'SOL2231',
    name: 'Pyth: Confidence Interval Check',
    severity: 'high' as const,
    pattern: /pyth[\s\S]{0,100}(?:price|feed)[\s\S]{0,100}(?!conf|confidence|uncertainty)/i,
    description: 'Pyth oracle without confidence interval check. Drift guardrails.',
    recommendation: 'Reject prices with confidence > price * threshold.'
  },
  {
    id: 'SOL2232',
    name: 'Switchboard: Aggregator Staleness',
    severity: 'high' as const,
    pattern: /switchboard[\s\S]{0,100}(?:aggregator|feed)[\s\S]{0,100}(?!latest_confirmed_round|staleness)/i,
    description: 'Switchboard aggregator without staleness check.',
    recommendation: 'Check latest_confirmed_round timestamp.'
  },
  {
    id: 'SOL2233',
    name: 'Marinade: mSOL Pricing Attack',
    severity: 'high' as const,
    pattern: /msol|marinade[\s\S]{0,100}(?:price|rate)[\s\S]{0,100}(?!exchange_rate|virtual)/i,
    description: 'mSOL pricing without exchange rate verification.',
    recommendation: 'Use Marinade exchange rate from stake pool.'
  },
  {
    id: 'SOL2234',
    name: 'Jupiter: Route Manipulation',
    severity: 'high' as const,
    pattern: /jupiter[\s\S]{0,100}(?:route|swap)[\s\S]{0,100}(?!slippage|min_out)/i,
    description: 'Jupiter swap without slippage protection.',
    recommendation: 'Always specify minimum output amount.'
  },
  {
    id: 'SOL2235',
    name: 'Drift: Oracle Guard Rails',
    severity: 'high' as const,
    pattern: /drift[\s\S]{0,100}oracle[\s\S]{0,100}(?!guard|validity|too_volatile)/i,
    description: 'Drift-style oracle without guard rails.',
    recommendation: 'Implement oracle validity checks like Drift.'
  },
  {
    id: 'SOL2236',
    name: 'Solend: Reserve Refresh',
    severity: 'high' as const,
    pattern: /reserve[\s\S]{0,100}(?:interest|rate)[\s\S]{0,100}(?!refresh|accrue|update)/i,
    description: 'Reserve state without interest refresh.',
    recommendation: 'Refresh reserve state before rate-sensitive operations.'
  },
  {
    id: 'SOL2237',
    name: 'Port: Variable Rate Model',
    severity: 'medium' as const,
    pattern: /interest_rate[\s\S]{0,100}(?:model|curve)[\s\S]{0,100}(?!bounds|cap|floor)/i,
    description: 'Interest rate model without bounds.',
    recommendation: 'Cap interest rates at reasonable maximum.'
  },
  {
    id: 'SOL2238',
    name: 'Jet: Margin Account Isolation',
    severity: 'high' as const,
    pattern: /margin[\s\S]{0,50}account[\s\S]{0,100}(?:position|collateral)[\s\S]{0,100}(?!isolation|separate)/i,
    description: 'Margin accounts without position isolation.',
    recommendation: 'Isolate positions to prevent cross-contamination.'
  },
  {
    id: 'SOL2239',
    name: 'Orca: Whirlpool Tick Array',
    severity: 'medium' as const,
    pattern: /tick_array|whirlpool[\s\S]{0,100}(?:swap|trade)[\s\S]{0,100}(?!initialized|valid)/i,
    description: 'Whirlpool swap without tick array validation.',
    recommendation: 'Verify tick arrays are initialized and valid.'
  },
  {
    id: 'SOL2240',
    name: 'Raydium: Pool Authority Leak',
    severity: 'critical' as const,
    pattern: /pool_authority|raydium[\s\S]{0,100}(?:admin|owner)[\s\S]{0,100}(?!multisig|timelock)/i,
    description: 'Raydium-style pool without admin protection. $4.4M exploit.',
    recommendation: 'Use multisig for pool administration.'
  },
  {
    id: 'SOL2241',
    name: 'Saber: Stable Swap A Factor',
    severity: 'medium' as const,
    pattern: /amplification|a_factor[\s\S]{0,100}(?:set|update)[\s\S]{0,100}(?!ramp|gradual)/i,
    description: 'Amplification factor change without ramp.',
    recommendation: 'Gradually ramp A factor changes over time.'
  },
  {
    id: 'SOL2242',
    name: 'Metaplex: Collection Authority',
    severity: 'high' as const,
    pattern: /collection[\s\S]{0,50}(?:verify|authority)[\s\S]{0,100}(?!update_authority|creator)/i,
    description: 'NFT collection verification gap.',
    recommendation: 'Verify collection authority matches expected.'
  },
  {
    id: 'SOL2243',
    name: 'Magic Eden: Royalty Enforcement',
    severity: 'medium' as const,
    pattern: /royalt[\s\S]{0,50}(?:check|enforce)[\s\S]{0,100}(?!pnft|programmable)/i,
    description: 'NFT royalty enforcement gap.',
    recommendation: 'Use pNFTs for enforced royalties.'
  },
  {
    id: 'SOL2244',
    name: 'Tensor: Compressed NFT Proof',
    severity: 'high' as const,
    pattern: /cnft|compressed[\s\S]{0,50}nft[\s\S]{0,100}(?:transfer|burn)[\s\S]{0,100}(?!proof|canopy)/i,
    description: 'Compressed NFT operation without proof.',
    recommendation: 'Verify merkle proof for all cNFT operations.'
  },
  {
    id: 'SOL2245',
    name: 'Phoenix: Order Book Crossing',
    severity: 'high' as const,
    pattern: /order_book|orderbook[\s\S]{0,100}(?:match|cross)[\s\S]{0,100}(?!self_trade|wash)/i,
    description: 'Order book without wash trading prevention.',
    recommendation: 'Detect and prevent self-crossing orders.'
  },
  {
    id: 'SOL2246',
    name: 'Zeta: Greeks Calculation',
    severity: 'medium' as const,
    pattern: /(?:delta|gamma|theta|vega)[\s\S]{0,100}(?:calculate|compute)[\s\S]{0,100}(?!black_scholes|model)/i,
    description: 'Options greeks without proper model.',
    recommendation: 'Use validated Black-Scholes or similar model.'
  },
  {
    id: 'SOL2247',
    name: 'Friktion: Vault Epoch Transition',
    severity: 'high' as const,
    pattern: /vault[\s\S]{0,50}epoch[\s\S]{0,100}(?:transition|settle)[\s\S]{0,100}(?!lock|freeze)/i,
    description: 'Vault epoch transition without locking.',
    recommendation: 'Lock deposits during epoch transitions.'
  },
  {
    id: 'SOL2248',
    name: 'Mango V4: Health Factor',
    severity: 'high' as const,
    pattern: /health[\s\S]{0,50}(?:factor|ratio)[\s\S]{0,100}(?:check|verify)[\s\S]{0,100}(?!before|prior)/i,
    description: 'Health factor checked after operation.',
    recommendation: 'Check health factor before allowing position changes.'
  },
  {
    id: 'SOL2249',
    name: 'Tulip: Strategy Migration',
    severity: 'high' as const,
    pattern: /strategy[\s\S]{0,50}(?:migrate|upgrade)[\s\S]{0,100}(?!lock|pause|governance)/i,
    description: 'Strategy migration without safeguards.',
    recommendation: 'Require governance and lockup for migrations.'
  },
  {
    id: 'SOL2250',
    name: 'UXD: Peg Mechanism',
    severity: 'high' as const,
    pattern: /peg|stablecoin[\s\S]{0,100}(?:mint|redeem)[\s\S]{0,100}(?!delta_neutral|hedge)/i,
    description: 'Stablecoin without delta-neutral hedging.',
    recommendation: 'Maintain delta-neutral position for peg stability.'
  },
  {
    id: 'SOL2251',
    name: 'Hubble: Multi-Collateral CDP',
    severity: 'high' as const,
    pattern: /cdp|collateral_debt[\s\S]{0,100}(?:multiple|multi)[\s\S]{0,100}(?!correlation|risk)/i,
    description: 'Multi-collateral CDP without correlation risk.',
    recommendation: 'Account for collateral correlation in risk model.'
  },
  {
    id: 'SOL2252',
    name: 'Hedge: Stability Pool Drain',
    severity: 'high' as const,
    pattern: /stability_pool[\s\S]{0,100}(?:withdraw|drain)[\s\S]{0,100}(?!cooldown|limit)/i,
    description: 'Stability pool without withdrawal limits.',
    recommendation: 'Add cooldown and rate limits for withdrawals.'
  },
  {
    id: 'SOL2253',
    name: 'Invariant: Concentrated Liquidity',
    severity: 'medium' as const,
    pattern: /concentrated[\s\S]{0,50}liquidity[\s\S]{0,100}(?:position|range)[\s\S]{0,100}(?!fee_growth|fees_owed)/i,
    description: 'Concentrated liquidity without fee tracking.',
    recommendation: 'Track fee growth per tick for accurate rewards.'
  },
  {
    id: 'SOL2254',
    name: 'Cropper: Fee Precision',
    severity: 'medium' as const,
    pattern: /fee[\s\S]{0,50}(?:numerator|rate)[\s\S]{0,50}(?:\/|div)\s*(?:denominator|\d+)/i,
    description: 'Fee calculation precision loss.',
    recommendation: 'Use high precision (1e9+) for fee calculations.'
  },
  {
    id: 'SOL2255',
    name: 'Swim: Cross-Chain Token Mapping',
    severity: 'high' as const,
    pattern: /cross_chain[\s\S]{0,100}(?:token|mint)[\s\S]{0,100}(?:map|registry)[\s\S]{0,100}(?!verify|authentic)/i,
    description: 'Cross-chain token without authenticity verification.',
    recommendation: 'Verify token mapping in trusted registry.'
  },

  // ========== Advanced DeFi Attack Vectors (SOL2256-SOL2280) ==========
  {
    id: 'SOL2256',
    name: 'Flash Loan Atomic Arbitrage',
    severity: 'high' as const,
    pattern: /flash_loan[\s\S]{0,200}(?:swap|exchange)[\s\S]{0,200}(?:repay)/i,
    description: 'Flash loan arbitrage pattern detected.',
    recommendation: 'Ensure flash loan repayment verification is atomic.'
  },
  {
    id: 'SOL2257',
    name: 'Sandwich Attack Vector',
    severity: 'high' as const,
    pattern: /swap[\s\S]{0,100}(?:slippage|price_impact)[\s\S]{0,100}(?:tolerance|limit)/i,
    description: 'Swap with slippage tolerance enables sandwiching.',
    recommendation: 'Use private transactions or MEV protection.'
  },
  {
    id: 'SOL2258',
    name: 'JIT Liquidity Attack',
    severity: 'medium' as const,
    pattern: /liquidity[\s\S]{0,50}(?:add|provide)[\s\S]{0,100}(?:same_tx|atomic)/i,
    description: 'Just-in-time liquidity provision.',
    recommendation: 'Add minimum liquidity duration requirements.'
  },
  {
    id: 'SOL2259',
    name: 'Time-Bandit Reorganization',
    severity: 'high' as const,
    pattern: /(?:finality|confirmation)[\s\S]{0,100}(?:wait|require)[\s\S]{0,50}\d+/i,
    description: 'Transaction finality assumption vulnerability.',
    recommendation: 'Wait for sufficient confirmations for large values.'
  },
  {
    id: 'SOL2260',
    name: 'Liquidation Auction Manipulation',
    severity: 'high' as const,
    pattern: /liquidation[\s\S]{0,50}(?:auction|bid)[\s\S]{0,100}(?!dutch|reserve)/i,
    description: 'Liquidation auction without fair pricing.',
    recommendation: 'Use Dutch auction with reserve price.'
  },
  {
    id: 'SOL2261',
    name: 'Interest Rate Spike',
    severity: 'high' as const,
    pattern: /interest[\s\S]{0,50}rate[\s\S]{0,100}(?:utilization|borrow)[\s\S]{0,100}(?!max|cap|ceiling)/i,
    description: 'Interest rate model without spike protection.',
    recommendation: 'Cap maximum interest rate during high utilization.'
  },
  {
    id: 'SOL2262',
    name: 'Governance Token Concentration',
    severity: 'medium' as const,
    pattern: /governance[\s\S]{0,50}(?:vote|power)[\s\S]{0,100}(?!delegation|decay)/i,
    description: 'Governance without vote decay.',
    recommendation: 'Implement vote decay or quadratic voting.'
  },
  {
    id: 'SOL2263',
    name: 'Proposal Execution Delay',
    severity: 'high' as const,
    pattern: /proposal[\s\S]{0,50}(?:execute|enact)[\s\S]{0,100}(?!timelock|delay|queue)/i,
    description: 'Proposal execution without delay.',
    recommendation: 'Add timelock delay for governance execution.'
  },
  {
    id: 'SOL2264',
    name: 'Vault Share Inflation',
    severity: 'critical' as const,
    pattern: /vault[\s\S]{0,50}(?:deposit|mint)[\s\S]{0,100}(?:first_deposit|initial)[\s\S]{0,100}(?!minimum|seed)/i,
    description: 'First depositor can inflate vault shares.',
    recommendation: 'Seed vault with minimum deposit or use dead shares.'
  },
  {
    id: 'SOL2265',
    name: 'Donation Attack',
    severity: 'high' as const,
    pattern: /(?:balance|reserve)[\s\S]{0,100}(?:get|read)[\s\S]{0,100}(?!expected|tracked)/i,
    description: 'Using balance instead of tracked reserves.',
    recommendation: 'Track reserves internally, not from balance.'
  },
  {
    id: 'SOL2266',
    name: 'Price Oracle TWAP Window',
    severity: 'high' as const,
    pattern: /twap[\s\S]{0,100}(?:window|period)[\s\S]{0,50}(?:\d+)/i,
    description: 'TWAP window may be too short for security.',
    recommendation: 'Use minimum 30-minute TWAP for DeFi pricing.'
  },
  {
    id: 'SOL2267',
    name: 'Collateral Factor Manipulation',
    severity: 'high' as const,
    pattern: /collateral_factor[\s\S]{0,100}(?:volatile|risky)[\s\S]{0,100}(?!reduce|conservative)/i,
    description: 'High collateral factor for volatile assets.',
    recommendation: 'Use conservative collateral factors (< 70%).'
  },
  {
    id: 'SOL2268',
    name: 'Insurance Fund Depletion',
    severity: 'critical' as const,
    pattern: /insurance[\s\S]{0,50}fund[\s\S]{0,100}(?:withdraw|use)[\s\S]{0,100}(?!threshold|minimum)/i,
    description: 'Insurance fund without minimum threshold.',
    recommendation: 'Maintain minimum insurance fund coverage.'
  },
  {
    id: 'SOL2269',
    name: 'Debt Ceiling Bypass',
    severity: 'high' as const,
    pattern: /debt[\s\S]{0,50}(?:ceiling|cap|limit)[\s\S]{0,100}(?!check|require|assert)/i,
    description: 'Debt ceiling without enforcement.',
    recommendation: 'Enforce debt ceiling on every borrow.'
  },
  {
    id: 'SOL2270',
    name: 'Reserve Factor Abuse',
    severity: 'medium' as const,
    pattern: /reserve_factor[\s\S]{0,100}(?:set|update)[\s\S]{0,100}(?!governance|timelock)/i,
    description: 'Reserve factor changes without governance.',
    recommendation: 'Require governance for reserve factor changes.'
  },
  {
    id: 'SOL2271',
    name: 'Lending Pool Isolation',
    severity: 'high' as const,
    pattern: /lending[\s\S]{0,50}pool[\s\S]{0,100}(?:share|cross)[\s\S]{0,100}(?!isolated|separate)/i,
    description: 'Lending pools sharing risk.',
    recommendation: 'Isolate high-risk lending pools.'
  },
  {
    id: 'SOL2272',
    name: 'Yield Strategy Griefing',
    severity: 'medium' as const,
    pattern: /yield[\s\S]{0,50}strategy[\s\S]{0,100}(?:harvest|compound)[\s\S]{0,100}(?!threshold|profitable)/i,
    description: 'Yield strategy vulnerable to griefing.',
    recommendation: 'Add profitability check before harvest.'
  },
  {
    id: 'SOL2273',
    name: 'Perpetual Funding Rate Spike',
    severity: 'high' as const,
    pattern: /funding[\s\S]{0,50}rate[\s\S]{0,100}(?:calculate|compute)[\s\S]{0,100}(?!cap|max|clamp)/i,
    description: 'Funding rate without caps.',
    recommendation: 'Cap funding rate to prevent extreme values.'
  },
  {
    id: 'SOL2274',
    name: 'ADL Priority Manipulation',
    severity: 'high' as const,
    pattern: /adl|auto_deleverage[\s\S]{0,100}(?:priority|ranking)[\s\S]{0,100}(?!pnl|profit)/i,
    description: 'ADL ranking without PnL consideration.',
    recommendation: 'Rank ADL by unrealized PnL percentage.'
  },
  {
    id: 'SOL2275',
    name: 'Position Limit Bypass',
    severity: 'high' as const,
    pattern: /position[\s\S]{0,50}(?:limit|max)[\s\S]{0,100}(?!aggregate|total)/i,
    description: 'Position limits without aggregation.',
    recommendation: 'Aggregate positions across all accounts.'
  },
  {
    id: 'SOL2276',
    name: 'Staking Reward Dilution',
    severity: 'medium' as const,
    pattern: /reward[\s\S]{0,50}(?:rate|per_token)[\s\S]{0,100}(?!update_before|sync)/i,
    description: 'Staking rewards without pre-update.',
    recommendation: 'Update reward rate before stake changes.'
  },
  {
    id: 'SOL2277',
    name: 'Unbonding Period Bypass',
    severity: 'high' as const,
    pattern: /unbond[\s\S]{0,100}(?:period|duration)[\s\S]{0,100}(?!enforce|check)/i,
    description: 'Unbonding period without enforcement.',
    recommendation: 'Strictly enforce unbonding cooldown.'
  },
  {
    id: 'SOL2278',
    name: 'Validator Commission Change',
    severity: 'medium' as const,
    pattern: /commission[\s\S]{0,100}(?:change|update)[\s\S]{0,100}(?!delay|epoch)/i,
    description: 'Validator commission instant change.',
    recommendation: 'Add epoch delay for commission changes.'
  },
  {
    id: 'SOL2279',
    name: 'Stake Pool Withdraw Authority',
    severity: 'high' as const,
    pattern: /stake_pool[\s\S]{0,100}(?:withdraw|unstake)[\s\S]{0,100}(?!authority|owner)/i,
    description: 'Stake pool withdrawal without authority check.',
    recommendation: 'Verify withdraw authority matches depositor.'
  },
  {
    id: 'SOL2280',
    name: 'Delegation Authority Confusion',
    severity: 'high' as const,
    pattern: /delegation[\s\S]{0,100}(?:stake|vote)[\s\S]{0,100}(?!authorized|authority)/i,
    description: 'Delegation without authority verification.',
    recommendation: 'Verify delegation authority before stake operations.'
  },
];

/**
 * Run Batch 56 patterns against input
 */
export function checkBatch56Patterns(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  const fileName = input.path || input.rust?.filePath || 'unknown';

  if (!content) return findings;

  const lines = content.split('\n');

  for (const pattern of BATCH_56_PATTERNS) {
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

export const BATCH_56_COUNT = BATCH_56_PATTERNS.length; // 70 patterns
