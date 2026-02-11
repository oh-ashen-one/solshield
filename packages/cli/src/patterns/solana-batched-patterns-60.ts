/**
 * SolShield Pattern Batch 60: Real-World Exploit Deep Analysis + Protocol-Specific (SOL2491-SOL2560)
 * 
 * Source: In-depth analysis of 38 verified Helius incidents, Protocol audits
 * 
 * Categories:
 * - Real-world exploit patterns extracted from incident analysis
 * - Protocol-specific vulnerability patterns
 * - Advanced DeFi attack vectors
 * - 2025 emerging threats
 */

import type { Finding, PatternInput } from './index.js';

interface PatternDef {
  id: string;
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  pattern: RegExp;
  description: string;
  recommendation: string;
  category?: string;
}

const BATCH_60_PATTERNS: PatternDef[] = [
  // Wormhole-Derived Patterns ($326M)
  {
    id: 'SOL2491',
    name: 'Wormhole: Signature Count Verification',
    severity: 'critical',
    pattern: /signatures[\s\S]{0,30}len\(\)(?![\s\S]{0,50}>=\s*quorum)/i,
    description: 'Multi-sig signature count without quorum check.',
    recommendation: 'Verify signature count meets quorum threshold.',
    category: 'Cross-Chain'
  },
  {
    id: 'SOL2492',
    name: 'Wormhole: Deprecated Verify Function',
    severity: 'critical',
    pattern: /verify_signatures[\s\S]{0,30}deprecated(?![\s\S]{0,50}migrate)/i,
    description: 'Using deprecated signature verification (Wormhole root cause).',
    recommendation: 'Migrate to current verification implementations.',
    category: 'Cross-Chain'
  },
  {
    id: 'SOL2493',
    name: 'Wormhole: Guardian Set Update',
    severity: 'high',
    pattern: /guardian_set[\s\S]{0,30}update(?![\s\S]{0,50}old_set_expiry)/i,
    description: 'Guardian set update without old set expiry.',
    recommendation: 'Implement guardian set expiry period.',
    category: 'Cross-Chain'
  },

  // Mango Markets Patterns ($116M)
  {
    id: 'SOL2494',
    name: 'Mango: Perp Market Manipulation',
    severity: 'critical',
    pattern: /perp[\s\S]{0,30}price(?![\s\S]{0,50}impact_limit|[\s\S]{0,50}circuit_breaker)/i,
    description: 'Perpetual market without price impact limits.',
    recommendation: 'Implement price impact limits and circuit breakers.',
    category: 'DeFi'
  },
  {
    id: 'SOL2495',
    name: 'Mango: Self-Reference Oracle',
    severity: 'critical',
    pattern: /oracle[\s\S]{0,30}(internal|self)(?![\s\S]{0,50}external_validation)/i,
    description: 'Protocol using self-referencing oracle (Mango root cause).',
    recommendation: 'Use external oracles with multiple sources.',
    category: 'Oracle'
  },
  {
    id: 'SOL2496',
    name: 'Mango: Collateral Concentration',
    severity: 'high',
    pattern: /collateral[\s\S]{0,30}(?![\s\S]{0,50}diversification|[\s\S]{0,50}limit_per_asset)/i,
    description: 'No limits on collateral concentration per asset.',
    recommendation: 'Implement per-asset collateral limits.',
    category: 'DeFi'
  },

  // Cashio Patterns ($52M)
  {
    id: 'SOL2497',
    name: 'Cashio: Collateral Chain Validation',
    severity: 'critical',
    pattern: /collateral[\s\S]{0,30}chain(?![\s\S]{0,50}validate_each|[\s\S]{0,50}root_of_trust)/i,
    description: 'Collateral chain without root-of-trust validation.',
    recommendation: 'Validate entire collateral chain to root of trust.',
    category: 'DeFi'
  },
  {
    id: 'SOL2498',
    name: 'Cashio: LP Token Verification',
    severity: 'critical',
    pattern: /lp_token[\s\S]{0,30}mint(?![\s\S]{0,50}verify_pool_mint|[\s\S]{0,50}whitelist)/i,
    description: 'LP token mint not verified against whitelist.',
    recommendation: 'Whitelist valid LP token mints.',
    category: 'DeFi'
  },
  {
    id: 'SOL2499',
    name: 'Cashio: Nested Account Trust',
    severity: 'high',
    pattern: /account[\s\S]{0,30}nested(?![\s\S]{0,50}verify_each_level)/i,
    description: 'Nested account structure without level-by-level verification.',
    recommendation: 'Verify each level of nested account structures.',
    category: 'Account'
  },

  // Crema Finance Patterns ($8.8M)
  {
    id: 'SOL2500',
    name: 'Crema: CLMM Tick Account Spoofing',
    severity: 'critical',
    pattern: /tick[\s\S]{0,30}account(?![\s\S]{0,50}owner_check|[\s\S]{0,50}pda_verify)/i,
    description: 'Tick account without ownership verification (Crema root cause).',
    recommendation: 'Verify tick account ownership via PDA.',
    category: 'AMM'
  },
  {
    id: 'SOL2501',
    name: 'Crema: Fee Claim Validation',
    severity: 'high',
    pattern: /fee[\s\S]{0,30}claim(?![\s\S]{0,50}position_owner|[\s\S]{0,50}verify_accrued)/i,
    description: 'Fee claiming without position ownership check.',
    recommendation: 'Verify position ownership before fee claims.',
    category: 'AMM'
  },
  {
    id: 'SOL2502',
    name: 'Crema: Flash Loan Fee Manipulation',
    severity: 'critical',
    pattern: /flash[\s\S]{0,30}fee[\s\S]{0,30}(?![\s\S]{0,50}before_state|[\s\S]{0,50}snapshot)/i,
    description: 'Flash loan fees calculated without pre-state snapshot.',
    recommendation: 'Snapshot state before flash loan for fee calculation.',
    category: 'DeFi'
  },

  // Slope Wallet Patterns ($8M)
  {
    id: 'SOL2503',
    name: 'Slope: Seed Phrase Transmission',
    severity: 'critical',
    pattern: /seed|mnemonic[\s\S]{0,30}(send|transmit|log)(?![\s\S]{0,50}never)/i,
    description: 'Seed phrase potentially transmitted externally.',
    recommendation: 'Never transmit seed phrases - keep client-side only.',
    category: 'Wallet'
  },
  {
    id: 'SOL2504',
    name: 'Slope: Analytics Key Exposure',
    severity: 'critical',
    pattern: /analytics|telemetry[\s\S]{0,30}(key|secret)(?![\s\S]{0,50}exclude_sensitive)/i,
    description: 'Analytics potentially capturing sensitive data.',
    recommendation: 'Explicitly exclude sensitive data from analytics.',
    category: 'Wallet'
  },

  // Nirvana Finance Patterns ($3.5M)
  {
    id: 'SOL2505',
    name: 'Nirvana: Bonding Curve Flash Loan',
    severity: 'critical',
    pattern: /bonding[\s\S]{0,30}(?![\s\S]{0,50}block_flash|[\s\S]{0,50}same_block_check)/i,
    description: 'Bonding curve without flash loan protection.',
    recommendation: 'Block same-block bonding curve operations.',
    category: 'DeFi'
  },
  {
    id: 'SOL2506',
    name: 'Nirvana: Algorithmic Peg Attack',
    severity: 'high',
    pattern: /peg[\s\S]{0,30}algorithm(?![\s\S]{0,50}dampening|[\s\S]{0,50}rate_limit)/i,
    description: 'Algorithmic peg without manipulation dampening.',
    recommendation: 'Add dampening factors to peg mechanisms.',
    category: 'DeFi'
  },

  // Raydium Patterns ($4.4M)
  {
    id: 'SOL2507',
    name: 'Raydium: Pool Authority Leak',
    severity: 'critical',
    pattern: /pool[\s\S]{0,30}authority[\s\S]{0,30}(key|secret)(?![\s\S]{0,50}never_expose)/i,
    description: 'Pool authority key potentially exposed.',
    recommendation: 'Pool authority keys must never be exposed.',
    category: 'AMM'
  },
  {
    id: 'SOL2508',
    name: 'Raydium: Admin Key Storage',
    severity: 'critical',
    pattern: /admin[\s\S]{0,30}key[\s\S]{0,30}(store|save)(?![\s\S]{0,50}hardware_wallet|[\s\S]{0,50}hsm)/i,
    description: 'Admin keys not stored in hardware security.',
    recommendation: 'Store admin keys in HSM or hardware wallet.',
    category: 'Admin'
  },

  // Pump.fun Patterns ($1.9M)
  {
    id: 'SOL2509',
    name: 'Pump.fun: Employee Access Control',
    severity: 'critical',
    pattern: /employee|internal[\s\S]{0,30}access(?![\s\S]{0,50}audit_log|[\s\S]{0,50}segregation)/i,
    description: 'Internal access without audit logging (Pump.fun insider threat).',
    recommendation: 'Log all internal access and implement segregation.',
    category: 'Admin'
  },
  {
    id: 'SOL2510',
    name: 'Pump.fun: Privileged Transaction Monitor',
    severity: 'high',
    pattern: /privileged[\s\S]{0,30}(?![\s\S]{0,50}alert|[\s\S]{0,50}monitor)/i,
    description: 'Privileged operations without real-time monitoring.',
    recommendation: 'Monitor and alert on all privileged operations.',
    category: 'Admin'
  },

  // OptiFi Patterns (Accidental lockup)
  {
    id: 'SOL2511',
    name: 'OptiFi: Shutdown Sequence',
    severity: 'critical',
    pattern: /shutdown|close[\s\S]{0,30}(?![\s\S]{0,50}withdraw_first|[\s\S]{0,50}safety_check)/i,
    description: 'Program closure without forced withdrawal (OptiFi root cause).',
    recommendation: 'Require all funds withdrawn before program closure.',
    category: 'Admin'
  },
  {
    id: 'SOL2512',
    name: 'OptiFi: Irreversible Action Guard',
    severity: 'high',
    pattern: /irreversible[\s\S]{0,30}(?![\s\S]{0,50}confirmation|[\s\S]{0,50}delay)/i,
    description: 'Irreversible actions without confirmation delay.',
    recommendation: 'Add confirmation delay for irreversible operations.',
    category: 'Admin'
  },

  // UXD Protocol Patterns
  {
    id: 'SOL2513',
    name: 'UXD: Delta-Neutral Hedge',
    severity: 'high',
    pattern: /hedge[\s\S]{0,30}delta(?![\s\S]{0,50}rebalance_threshold)/i,
    description: 'Delta-neutral position without rebalance thresholds.',
    recommendation: 'Set automated rebalance thresholds for hedges.',
    category: 'DeFi'
  },
  {
    id: 'SOL2514',
    name: 'UXD: Insurance Fund Depletion',
    severity: 'high',
    pattern: /insurance[\s\S]{0,30}fund(?![\s\S]{0,50}minimum_reserve)/i,
    description: 'Insurance fund without minimum reserve requirement.',
    recommendation: 'Maintain minimum insurance fund reserve.',
    category: 'DeFi'
  },

  // Cypher Protocol Patterns ($1M+)
  {
    id: 'SOL2515',
    name: 'Cypher: Post-Exploit Recovery',
    severity: 'high',
    pattern: /recover|restore[\s\S]{0,30}(?![\s\S]{0,50}escrow|[\s\S]{0,50}secure_custody)/i,
    description: 'Recovery without secure custody (Cypher second theft).',
    recommendation: 'Use escrow/multi-sig for recovery operations.',
    category: 'Recovery'
  },
  {
    id: 'SOL2516',
    name: 'Cypher: White-Hat Coordination',
    severity: 'medium',
    pattern: /white[\s\S]{0,5}hat[\s\S]{0,30}(?![\s\S]{0,50}verified|[\s\S]{0,50}known)/i,
    description: 'White-hat interaction without verification.',
    recommendation: 'Verify white-hat identity through known channels.',
    category: 'Recovery'
  },

  // Audius Patterns
  {
    id: 'SOL2517',
    name: 'Audius: Initialization Guard',
    severity: 'critical',
    pattern: /initialize[\s\S]{0,30}(?![\s\S]{0,50}once|[\s\S]{0,50}initialized_check)/i,
    description: 'Initialization function callable multiple times.',
    recommendation: 'Add one-time initialization guard.',
    category: 'Initialization'
  },
  {
    id: 'SOL2518',
    name: 'Audius: Governance Proxy',
    severity: 'high',
    pattern: /governance[\s\S]{0,30}proxy(?![\s\S]{0,50}verify_impl)/i,
    description: 'Governance proxy without implementation verification.',
    recommendation: 'Verify proxy implementation before calls.',
    category: 'Governance'
  },

  // Tulip Protocol Patterns
  {
    id: 'SOL2519',
    name: 'Tulip: Vault Strategy Risk',
    severity: 'high',
    pattern: /vault[\s\S]{0,30}strategy(?![\s\S]{0,50}risk_score|[\s\S]{0,50}audit)/i,
    description: 'Vault strategy without risk assessment.',
    recommendation: 'Audit and score vault strategy risks.',
    category: 'DeFi'
  },
  {
    id: 'SOL2520',
    name: 'Tulip: Yield Aggregation Risk',
    severity: 'medium',
    pattern: /yield[\s\S]{0,30}aggregate(?![\s\S]{0,50}diversif|[\s\S]{0,50}limit)/i,
    description: 'Yield aggregation without diversification limits.',
    recommendation: 'Diversify yield sources and set limits.',
    category: 'DeFi'
  },

  // Solend Advanced Patterns
  {
    id: 'SOL2521',
    name: 'Solend: Reserve Config Auth',
    severity: 'critical',
    pattern: /reserve[\s\S]{0,30}config[\s\S]{0,30}update(?![\s\S]{0,50}admin_check)/i,
    description: 'Reserve config update without admin verification.',
    recommendation: 'Verify admin authority for reserve config updates.',
    category: 'Lending'
  },
  {
    id: 'SOL2522',
    name: 'Solend: Liquidation Threshold Guard',
    severity: 'high',
    pattern: /liquidation[\s\S]{0,30}threshold[\s\S]{0,30}(?![\s\S]{0,50}bounds_check)/i,
    description: 'Liquidation threshold modifiable without bounds.',
    recommendation: 'Set immutable bounds on liquidation thresholds.',
    category: 'Lending'
  },
  {
    id: 'SOL2523',
    name: 'Solend: Borrow Rate Spike',
    severity: 'medium',
    pattern: /borrow[\s\S]{0,30}rate(?![\s\S]{0,50}max_rate|[\s\S]{0,50}cap)/i,
    description: 'Borrow rate without maximum cap.',
    recommendation: 'Cap maximum borrow rates.',
    category: 'Lending'
  },

  // io.net Patterns
  {
    id: 'SOL2524',
    name: 'io.net: Worker Node Verification',
    severity: 'high',
    pattern: /worker[\s\S]{0,30}node(?![\s\S]{0,50}stake|[\s\S]{0,50}verify)/i,
    description: 'Worker nodes without stake or verification.',
    recommendation: 'Require stake and verification for workers.',
    category: 'Infrastructure'
  },
  {
    id: 'SOL2525',
    name: 'io.net: Compute Proof Validation',
    severity: 'high',
    pattern: /compute[\s\S]{0,30}proof(?![\s\S]{0,50}verify|[\s\S]{0,50}challenge)/i,
    description: 'Compute proofs without challenge-response.',
    recommendation: 'Implement proof-of-compute challenges.',
    category: 'Infrastructure'
  },

  // SVT Token Patterns
  {
    id: 'SOL2526',
    name: 'SVT: Mint Authority Handoff',
    severity: 'critical',
    pattern: /mint[\s\S]{0,30}authority[\s\S]{0,30}(?![\s\S]{0,50}revoke|[\s\S]{0,50}null)/i,
    description: 'Mint authority not revoked after initial distribution.',
    recommendation: 'Revoke mint authority after token distribution.',
    category: 'Token'
  },
  {
    id: 'SOL2527',
    name: 'SVT: Supply Verification',
    severity: 'high',
    pattern: /total[\s\S]{0,30}supply(?![\s\S]{0,50}verify|[\s\S]{0,50}max)/i,
    description: 'Total supply without maximum verification.',
    recommendation: 'Verify total supply against maximum.',
    category: 'Token'
  },

  // Network-Level Attack Patterns
  {
    id: 'SOL2528',
    name: 'Grape: Transaction Flood Protection',
    severity: 'high',
    pattern: /transaction[\s\S]{0,30}(?![\s\S]{0,50}rate_limit|[\s\S]{0,50}throttle)/i,
    description: 'No transaction rate limiting (Grape DDoS pattern).',
    recommendation: 'Implement transaction rate limits.',
    category: 'Network'
  },
  {
    id: 'SOL2529',
    name: 'Candy Machine: Bot Protection',
    severity: 'high',
    pattern: /mint[\s\S]{0,30}public(?![\s\S]{0,50}captcha|[\s\S]{0,50}allowlist)/i,
    description: 'Public mint without bot protection.',
    recommendation: 'Add captcha or allowlist for public mints.',
    category: 'NFT'
  },
  {
    id: 'SOL2530',
    name: 'Jito: Bundle Priority Manipulation',
    severity: 'medium',
    pattern: /bundle[\s\S]{0,30}priority(?![\s\S]{0,50}fair_ordering)/i,
    description: 'Bundle priority without fair ordering guarantees.',
    recommendation: 'Consider fair ordering mechanisms.',
    category: 'MEV'
  },

  // Core Protocol Vulnerability Patterns
  {
    id: 'SOL2531',
    name: 'Turbine: Block Propagation',
    severity: 'high',
    pattern: /block[\s\S]{0,30}propagat(?![\s\S]{0,50}timeout|[\s\S]{0,50}fallback)/i,
    description: 'Block propagation without timeout handling.',
    recommendation: 'Handle block propagation timeouts gracefully.',
    category: 'Core'
  },
  {
    id: 'SOL2532',
    name: 'Durable Nonce: Advancement Check',
    severity: 'high',
    pattern: /nonce[\s\S]{0,30}(?![\s\S]{0,50}advance|[\s\S]{0,50}verify_recent)/i,
    description: 'Durable nonce without advancement verification.',
    recommendation: 'Verify nonce advancement before use.',
    category: 'Core'
  },
  {
    id: 'SOL2533',
    name: 'JIT Cache: Compilation Safety',
    severity: 'high',
    pattern: /jit[\s\S]{0,30}compile(?![\s\S]{0,50}sandbox|[\s\S]{0,50}verify)/i,
    description: 'JIT compilation without sandboxing.',
    recommendation: 'Sandbox JIT compilation processes.',
    category: 'Core'
  },

  // Supply Chain Attack Patterns
  {
    id: 'SOL2534',
    name: 'Web3.js: Package Integrity',
    severity: 'critical',
    pattern: /@solana[\s\S]{0,30}(?![\s\S]{0,50}integrity|[\s\S]{0,50}checksum)/i,
    description: 'Solana packages without integrity verification.',
    recommendation: 'Verify package integrity with checksums.',
    category: 'Supply Chain'
  },
  {
    id: 'SOL2535',
    name: 'NPM: Dependency Lock',
    severity: 'high',
    pattern: /dependencies[\s\S]{0,30}(?![\s\S]{0,50}lock|[\s\S]{0,50}exact)/i,
    description: 'Dependencies without lock file.',
    recommendation: 'Use lock files and exact versions.',
    category: 'Supply Chain'
  },
  {
    id: 'SOL2536',
    name: 'CDN: Frontend Integrity',
    severity: 'high',
    pattern: /script[\s\S]{0,30}src[\s\S]{0,30}(?![\s\S]{0,50}integrity)/i,
    description: 'CDN scripts without SRI integrity.',
    recommendation: 'Add SRI integrity attributes to CDN scripts.',
    category: 'Supply Chain'
  },

  // Advanced Protocol Patterns
  {
    id: 'SOL2537',
    name: 'Jupiter: Route Aggregation Safety',
    severity: 'high',
    pattern: /route[\s\S]{0,30}aggregate(?![\s\S]{0,50}slippage|[\s\S]{0,50}deadline)/i,
    description: 'Route aggregation without slippage protection.',
    recommendation: 'Enforce slippage and deadline on aggregated routes.',
    category: 'DEX'
  },
  {
    id: 'SOL2538',
    name: 'Marinade: Stake Pool Manipulation',
    severity: 'high',
    pattern: /stake[\s\S]{0,30}pool[\s\S]{0,30}(?![\s\S]{0,50}validator_set)/i,
    description: 'Stake pool without validator set verification.',
    recommendation: 'Verify validator set for stake pool operations.',
    category: 'Staking'
  },
  {
    id: 'SOL2539',
    name: 'Drift: Perp Funding Rate',
    severity: 'medium',
    pattern: /funding[\s\S]{0,30}rate(?![\s\S]{0,50}cap|[\s\S]{0,50}bounds)/i,
    description: 'Perpetual funding rate without bounds.',
    recommendation: 'Cap funding rates to prevent manipulation.',
    category: 'Perps'
  },
  {
    id: 'SOL2540',
    name: 'Phoenix: Order Book Integrity',
    severity: 'high',
    pattern: /order[\s\S]{0,30}book(?![\s\S]{0,50}verify_sorted)/i,
    description: 'Order book without sort verification.',
    recommendation: 'Verify order book sort integrity.',
    category: 'DEX'
  },

  // Stablecoin Specific
  {
    id: 'SOL2541',
    name: 'USDC: Blacklist Check',
    severity: 'high',
    pattern: /usdc[\s\S]{0,30}transfer(?![\s\S]{0,50}blacklist_check)/i,
    description: 'USDC transfer without blacklist consideration.',
    recommendation: 'Check USDC blacklist before transfers.',
    category: 'Token'
  },
  {
    id: 'SOL2542',
    name: 'Stablecoin: Depeg Detection',
    severity: 'high',
    pattern: /stablecoin[\s\S]{0,30}(?![\s\S]{0,50}peg_check|[\s\S]{0,50}deviation)/i,
    description: 'Stablecoin operations without depeg detection.',
    recommendation: 'Implement depeg detection and circuit breakers.',
    category: 'Token'
  },

  // Governance Advanced
  {
    id: 'SOL2543',
    name: 'DAO: Proposal Spam Protection',
    severity: 'medium',
    pattern: /proposal[\s\S]{0,30}create(?![\s\S]{0,50}stake_required|[\s\S]{0,50}deposit)/i,
    description: 'Proposal creation without stake requirement.',
    recommendation: 'Require stake or deposit for proposals.',
    category: 'Governance'
  },
  {
    id: 'SOL2544',
    name: 'DAO: Execution Delay',
    severity: 'high',
    pattern: /execute[\s\S]{0,30}proposal(?![\s\S]{0,50}timelock|[\s\S]{0,50}delay)/i,
    description: 'Proposal execution without timelock.',
    recommendation: 'Add timelock delay for proposal execution.',
    category: 'Governance'
  },
  {
    id: 'SOL2545',
    name: 'DAO: Quorum Manipulation',
    severity: 'high',
    pattern: /quorum[\s\S]{0,30}(?![\s\S]{0,50}snapshot|[\s\S]{0,50}fixed)/i,
    description: 'Quorum calculation without snapshot.',
    recommendation: 'Use snapshot for quorum calculations.',
    category: 'Governance'
  },

  // NFT Marketplace Patterns
  {
    id: 'SOL2546',
    name: 'NFT: Royalty Enforcement',
    severity: 'medium',
    pattern: /royalt(?![\s\S]{0,50}enforce|[\s\S]{0,50}programmable)/i,
    description: 'NFT royalties not enforced on-chain.',
    recommendation: 'Use programmable NFTs for royalty enforcement.',
    category: 'NFT'
  },
  {
    id: 'SOL2547',
    name: 'NFT: Collection Verification',
    severity: 'high',
    pattern: /collection[\s\S]{0,30}(?![\s\S]{0,50}verified|[\s\S]{0,50}authority)/i,
    description: 'NFT collection without verification.',
    recommendation: 'Verify collection authority.',
    category: 'NFT'
  },
  {
    id: 'SOL2548',
    name: 'NFT: Metadata Mutability',
    severity: 'medium',
    pattern: /metadata[\s\S]{0,30}update(?![\s\S]{0,50}authority_check)/i,
    description: 'NFT metadata updates without authority check.',
    recommendation: 'Verify update authority for metadata changes.',
    category: 'NFT'
  },

  // Bridge Patterns
  {
    id: 'SOL2549',
    name: 'Bridge: Source Finality',
    severity: 'critical',
    pattern: /bridge[\s\S]{0,30}receive(?![\s\S]{0,50}finality_wait)/i,
    description: 'Bridge receiving without source finality.',
    recommendation: 'Wait for source chain finality.',
    category: 'Cross-Chain'
  },
  {
    id: 'SOL2550',
    name: 'Bridge: Relayer Incentives',
    severity: 'medium',
    pattern: /relayer[\s\S]{0,30}(?![\s\S]{0,50}incentive|[\s\S]{0,50}fee)/i,
    description: 'Bridge relayer without incentive alignment.',
    recommendation: 'Align relayer incentives with protocol.',
    category: 'Cross-Chain'
  },

  // Advanced Security Patterns
  {
    id: 'SOL2551',
    name: 'Reentrancy: CPI State Check',
    severity: 'critical',
    pattern: /invoke[\s\S]{0,50}[\s\S]{0,30}state(?![\s\S]{0,50}before_cpi)/i,
    description: 'State accessed after CPI without re-check.',
    recommendation: 'Re-check state after CPI calls.',
    category: 'Reentrancy'
  },
  {
    id: 'SOL2552',
    name: 'Reentrancy: Guard Pattern',
    severity: 'high',
    pattern: /pub fn[\s\S]{0,100}invoke(?![\s\S]{0,200}reentrancy_guard|[\s\S]{0,200}mutex)/i,
    description: 'Function with CPI lacks reentrancy guard.',
    recommendation: 'Add reentrancy guard to CPI functions.',
    category: 'Reentrancy'
  },

  // Memory & Compute Patterns
  {
    id: 'SOL2553',
    name: 'Compute: Budget Estimation',
    severity: 'medium',
    pattern: /compute[\s\S]{0,30}budget(?![\s\S]{0,50}estimate|[\s\S]{0,50}buffer)/i,
    description: 'Compute budget without safety buffer.',
    recommendation: 'Add buffer to compute budget estimates.',
    category: 'Performance'
  },
  {
    id: 'SOL2554',
    name: 'Memory: Heap Allocation',
    severity: 'medium',
    pattern: /vec!|Vec::new(?![\s\S]{0,50}with_capacity)/i,
    description: 'Vector without pre-allocation.',
    recommendation: 'Use with_capacity for known sizes.',
    category: 'Performance'
  },

  // Error Handling
  {
    id: 'SOL2555',
    name: 'Error: Generic Handler',
    severity: 'medium',
    pattern: /catch[\s\S]{0,30}(?![\s\S]{0,50}specific|[\s\S]{0,50}match)/i,
    description: 'Generic error handling hiding specific failures.',
    recommendation: 'Handle specific errors appropriately.',
    category: 'Error'
  },
  {
    id: 'SOL2556',
    name: 'Error: Silent Failure',
    severity: 'high',
    pattern: /\.ok\(\)|\.unwrap_or(?![\s\S]{0,50}log|[\s\S]{0,50}emit)/i,
    description: 'Error silently converted to default.',
    recommendation: 'Log or emit events for error cases.',
    category: 'Error'
  },

  // Monitoring & Observability
  {
    id: 'SOL2557',
    name: 'Audit: Trail Missing',
    severity: 'medium',
    pattern: /admin[\s\S]{0,30}action(?![\s\S]{0,50}emit!|[\s\S]{0,50}log)/i,
    description: 'Admin actions without audit trail.',
    recommendation: 'Log all admin actions for audit.',
    category: 'Audit'
  },
  {
    id: 'SOL2558',
    name: 'Metrics: TVL Tracking',
    severity: 'low',
    pattern: /deposit|withdraw(?![\s\S]{0,100}total_value)/i,
    description: 'Value operations without TVL tracking.',
    recommendation: 'Track TVL for monitoring.',
    category: 'Metrics'
  },

  // Upgrade Patterns
  {
    id: 'SOL2559',
    name: 'Upgrade: Migration Safety',
    severity: 'high',
    pattern: /upgrade[\s\S]{0,30}(?![\s\S]{0,50}migrate|[\s\S]{0,50}compatible)/i,
    description: 'Program upgrade without migration plan.',
    recommendation: 'Plan data migration for upgrades.',
    category: 'Upgrade'
  },
  {
    id: 'SOL2560',
    name: 'Upgrade: Rollback Capability',
    severity: 'medium',
    pattern: /upgrade[\s\S]{0,30}(?![\s\S]{0,50}rollback|[\s\S]{0,50}previous)/i,
    description: 'Upgrade without rollback capability.',
    recommendation: 'Maintain rollback capability for upgrades.',
    category: 'Upgrade'
  }
];

export function checkBatch60Patterns(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  const fileName = input.path || input.rust?.filePath || 'unknown';
  
  if (!content) return findings;
  
  const lines = content.split('\n');
  
  for (const pattern of BATCH_60_PATTERNS) {
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
          description: pattern.description + (pattern.category ? ` [Category: ${pattern.category}]` : ''),
          location: { file: fileName, line: lineNum },
          recommendation: pattern.recommendation,
          code: snippet.substring(0, 200)
        });
      }
    } catch (error) {
      // Skip pattern if regex fails
    }
  }
  
  return findings;
}

export const BATCH_60_COUNT = BATCH_60_PATTERNS.length;
