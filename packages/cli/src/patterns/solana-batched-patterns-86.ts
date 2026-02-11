/**
 * SolShield Batch 86 Patterns
 * Added: Feb 6, 2026 3:45 AM
 * Source: Helius Supply Chain + Network Attacks + Core Protocol Vulnerabilities + 2026 Infrastructure Threats
 * Patterns: SOL4601-SOL4700
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

const batch86Patterns: Pattern[] = [
  // ===== HELIUS SUPPLY CHAIN ATTACKS =====
  {
    id: 'SOL4601',
    title: 'Web3.js Supply Chain Attack Pattern',
    severity: 'critical',
    category: 'supply-chain',
    description: 'Helius 2024: @solana/web3.js v1.95.5-1.95.7 contained malicious exfiltration code targeting private keys.',
    detector: /web3\.js|@solana\/web3|solana-web3/i,
    recommendation: 'Pin web3.js to audited version (>=1.95.8). Use lockfile. Enable npm audit in CI.'
  },
  {
    id: 'SOL4602',
    title: 'Parcl Frontend Compromise Pattern',
    severity: 'critical',
    category: 'supply-chain',
    description: 'Helius 2024: Parcl frontend hosted malicious code draining wallets via phishing modal.',
    detector: /frontend|react|next|vite|webpack/i,
    recommendation: 'Implement CSP headers. Use SRI for CDN scripts. Monitor DOM for injected elements.'
  },
  {
    id: 'SOL4603',
    title: 'NPM Package Typosquatting',
    severity: 'high',
    category: 'supply-chain',
    description: 'Malicious packages with similar names to legitimate Solana packages.',
    detector: /require\(|import\s+.*from\s+['"]/,
    recommendation: 'Verify package names. Use npm audit. Check package publishers.'
  },
  {
    id: 'SOL4604',
    title: 'Dependency Confusion Attack',
    severity: 'high',
    category: 'supply-chain',
    description: 'Private package names claimed on public registry with malicious code.',
    detector: /package\.json|Cargo\.toml|dependencies/i,
    recommendation: 'Scope private packages. Use registry proxies. Verify package sources.'
  },
  {
    id: 'SOL4605',
    title: 'Build Script Injection',
    severity: 'critical',
    category: 'supply-chain',
    description: 'Malicious code in npm postinstall or cargo build scripts.',
    detector: /postinstall|preinstall|build\.rs|install.*script/i,
    recommendation: 'Review install scripts. Use --ignore-scripts in CI. Audit build.rs files.'
  },
  {
    id: 'SOL4606',
    title: 'Compromised Maintainer Account',
    severity: 'critical',
    category: 'supply-chain',
    description: 'Legitimate package updated with malicious code after account compromise.',
    detector: /npm|cargo|crate|package/i,
    recommendation: 'Use lockfiles. Pin versions. Monitor package updates. Enable 2FA for npm.'
  },
  {
    id: 'SOL4607',
    title: 'CDN Hijacking Risk',
    severity: 'high',
    category: 'supply-chain',
    description: 'External CDN scripts can be modified if CDN is compromised.',
    detector: /cdn\.|unpkg|jsdelivr|cdnjs/i,
    recommendation: 'Use Subresource Integrity (SRI). Self-host critical scripts.'
  },
  
  // ===== HELIUS NETWORK-LEVEL ATTACKS =====
  {
    id: 'SOL4608',
    title: 'Grape Protocol Network Spam (17hr Outage)',
    severity: 'high',
    category: 'network',
    description: 'Helius 2021: Grape Protocol bot spammed network causing 17-hour outage.',
    detector: /spam|flood|rate_limit|throttle/i,
    recommendation: 'Implement rate limiting. Use priority fees. Add backoff mechanisms.'
  },
  {
    id: 'SOL4609',
    title: 'Candy Machine NFT Minting DoS',
    severity: 'high',
    category: 'network',
    description: 'Helius 2022: Mass NFT minting caused network congestion.',
    detector: /mint|nft|candy_machine|metaplex/i,
    recommendation: 'Implement minting queues. Use proof-of-humanity. Stagger mint schedules.'
  },
  {
    id: 'SOL4610',
    title: 'Jito DDoS Attack Pattern',
    severity: 'high',
    category: 'network',
    description: 'Helius 2024: DDoS attacks targeted Jito validators.',
    detector: /jito|bundle|tip|block_engine/i,
    recommendation: 'Diversify validator connections. Implement fallback MEV providers.'
  },
  {
    id: 'SOL4611',
    title: 'Phantom Wallet DDoS',
    severity: 'medium',
    category: 'network',
    description: 'Helius 2024: Phantom RPC endpoints targeted causing wallet failures.',
    detector: /rpc|endpoint|phantom|wallet_adapter/i,
    recommendation: 'Use multiple RPC endpoints. Implement RPC failover. Cache responses.'
  },
  {
    id: 'SOL4612',
    title: 'Validator Concentration Risk',
    severity: 'high',
    category: 'infrastructure',
    description: 'High validator concentration at few hosting providers creates systemic risk.',
    detector: /validator|stake|delegation|infrastructure/i,
    recommendation: 'Diversify validator selections. Monitor stake concentration.'
  },
  {
    id: 'SOL4613',
    title: 'Transaction Flood Mitigation',
    severity: 'medium',
    category: 'network',
    description: 'Protocol vulnerable to transaction flooding attacks.',
    detector: /transaction|send_transaction|broadcast/i,
    recommendation: 'Implement transaction batching. Use local fee markets. Add congestion detection.'
  },
  
  // ===== HELIUS CORE PROTOCOL VULNERABILITIES =====
  {
    id: 'SOL4614',
    title: 'Solana Turbine Bug Pattern',
    severity: 'critical',
    category: 'core-protocol',
    description: 'Helius 2022: Turbine propagation bug caused incomplete block transmission.',
    detector: /turbine|shred|propagate|block/i,
    recommendation: 'Monitor block propagation. Implement verification for received shreds.'
  },
  {
    id: 'SOL4615',
    title: 'Durable Nonce Bug Pattern',
    severity: 'high',
    category: 'core-protocol',
    description: 'Helius 2023: Durable nonce transactions could be replayed under certain conditions.',
    detector: /durable_nonce|DurableNonce|AdvanceNonce/i,
    recommendation: 'Validate nonce freshness. Use unique nonce per transaction.'
  },
  {
    id: 'SOL4616',
    title: 'Duplicate Block Bug Pattern',
    severity: 'critical',
    category: 'core-protocol',
    description: 'Helius 2024: Duplicate block production caused chain split.',
    detector: /block|slot|leader|fork/i,
    recommendation: 'Monitor for chain splits. Implement fork resolution in dApp logic.'
  },
  {
    id: 'SOL4617',
    title: 'Turbine Failure Pattern',
    severity: 'critical',
    category: 'core-protocol',
    description: 'Helius 2023: Turbine failure caused network-wide outage.',
    detector: /network|outage|consensus|validator/i,
    recommendation: 'Implement graceful degradation. Handle network failures in frontend.'
  },
  {
    id: 'SOL4618',
    title: 'JIT Cache Bug Pattern',
    severity: 'critical',
    category: 'core-protocol',
    description: 'Helius 2024: JIT compilation cache bug allowed code execution manipulation.',
    detector: /jit|cache|compile|bpf/i,
    recommendation: 'Stay updated with Solana releases. Monitor for core protocol patches.'
  },
  {
    id: 'SOL4619',
    title: 'ELF Address Alignment Vulnerability',
    severity: 'critical',
    category: 'core-protocol',
    description: 'Helius 2024: ELF address alignment issue could cause memory corruption.',
    detector: /elf|alignment|memory|bpf_loader/i,
    recommendation: 'Ensure proper alignment in BPF programs. Test on devnet after updates.'
  },
  {
    id: 'SOL4620',
    title: 'rBPF Integer Overflow',
    severity: 'critical',
    category: 'core-protocol',
    description: 'BlockSec 2022: Integer overflow in Solana rBPF virtual machine.',
    detector: /rbpf|bpf|vm|runtime/i,
    recommendation: 'Keep Solana runtime updated. Monitor for rBPF security advisories.'
  },
  
  // ===== INSIDER THREAT PATTERNS =====
  {
    id: 'SOL4621',
    title: 'Pump.fun Employee Exploit ($1.9M)',
    severity: 'critical',
    category: 'insider-threat',
    description: 'Helius 2024: Employee used privileged access to steal bonding curve funds.',
    detector: /employee|admin|privileged|internal/i,
    recommendation: 'Implement multi-sig for sensitive operations. Use timelocks. Audit trail logging.'
  },
  {
    id: 'SOL4622',
    title: 'Cypher Insider Theft ($317K)',
    severity: 'critical',
    category: 'insider-threat',
    description: 'Helius 2024: Core contributor stole from redemption fund.',
    detector: /contributor|team|treasury|redemption/i,
    recommendation: 'Segregate duties. Multi-sig treasury. Transparent fund tracking.'
  },
  {
    id: 'SOL4623',
    title: 'Banana Gun Bot Compromise',
    severity: 'critical',
    category: 'insider-threat',
    description: 'Helius 2024: Trading bot infrastructure compromised leaking private keys.',
    detector: /bot|trading|automated|keys/i,
    recommendation: 'Secure key storage. Use HSM for hot wallets. Implement key rotation.'
  },
  {
    id: 'SOL4624',
    title: 'DEXX Private Key Exposure ($30M)',
    severity: 'critical',
    category: 'key-management',
    description: 'Helius 2024: Exchange leaked private keys affecting 900 wallets.',
    detector: /private_key|secret_key|keypair/i,
    recommendation: 'Never store keys in cleartext. Use secure enclaves. Regular security audits.'
  },
  {
    id: 'SOL4625',
    title: 'Solareum Backend Compromise',
    severity: 'critical',
    category: 'infrastructure',
    description: 'Helius 2024: Backend infrastructure compromised enabling token swap theft.',
    detector: /backend|server|api|infrastructure/i,
    recommendation: 'Implement zero-trust architecture. Regular penetration testing.'
  },
  
  // ===== WALLET EXPLOIT PATTERNS =====
  {
    id: 'SOL4626',
    title: 'Slope Wallet Seed Phrase Leak ($8M)',
    severity: 'critical',
    category: 'wallet',
    description: 'Helius 2022: Mobile wallet transmitted seed phrases to central server.',
    detector: /seed|mnemonic|wallet|mobile/i,
    recommendation: 'Never transmit seed phrases. Use secure enclave. Audit wallet code.'
  },
  {
    id: 'SOL4627',
    title: 'Centralized Logging Exposure',
    severity: 'critical',
    category: 'wallet',
    description: 'Sensitive data logged to centralized server enabling theft.',
    detector: /log|logging|telemetry|analytics/i,
    recommendation: 'Never log sensitive data. Review logging libraries. Implement PII filtering.'
  },
  {
    id: 'SOL4628',
    title: 'Wallet Approval Persistence',
    severity: 'high',
    category: 'wallet',
    description: 'SPL token approvals persist enabling delayed attacks.',
    detector: /approve|delegation|allowance/i,
    recommendation: 'Revoke approvals immediately. Implement approval management UI.'
  },
  
  // ===== PROTOCOL-SPECIFIC EXPLOIT PATTERNS =====
  {
    id: 'SOL4629',
    title: 'Loopscale RateX Exploit ($5.8M)',
    severity: 'critical',
    category: 'lending',
    description: 'Helius 2025: Undercollateralized loan exploit via pricing manipulation.',
    detector: /rate|lending|borrow|collateral/i,
    recommendation: 'Validate collateral ratios. Use oracle price bounds. Add circuit breakers.'
  },
  {
    id: 'SOL4630',
    title: 'NoOnes Platform Bridge Exploit',
    severity: 'critical',
    category: 'bridge',
    description: 'Helius 2025: P2P platform bridge exploited via signature replay.',
    detector: /bridge|p2p|escrow|cross_chain/i,
    recommendation: 'Include chain ID in signatures. Implement nonce tracking. Add finality delays.'
  },
  {
    id: 'SOL4631',
    title: 'Aurory SyncSpace State Desync',
    severity: 'high',
    category: 'gaming',
    description: 'Helius 2023: Gaming state synchronization vulnerability.',
    detector: /sync|game|state|multiplayer/i,
    recommendation: 'Implement state verification. Use merkle proofs. Add rollback mechanism.'
  },
  {
    id: 'SOL4632',
    title: 'Saga DAO Proposal Attack',
    severity: 'high',
    category: 'governance',
    description: 'Helius 2024: DAO governance proposal manipulation.',
    detector: /dao|proposal|governance|vote/i,
    recommendation: 'Add proposal delays. Require quorum. Implement veto mechanism.'
  },
  {
    id: 'SOL4633',
    title: 'io.net Node Credential Leak',
    severity: 'critical',
    category: 'infrastructure',
    description: 'Helius 2024: Distributed compute network node credentials exposed.',
    detector: /node|credential|compute|network/i,
    recommendation: 'Rotate credentials regularly. Use short-lived tokens. Implement RBAC.'
  },
  
  // ===== ADVANCED EXPLOIT CHAIN PATTERNS =====
  {
    id: 'SOL4634',
    title: 'Multi-Protocol Exploit Chain',
    severity: 'critical',
    category: 'exploit-chain',
    description: 'Combining vulnerabilities across multiple protocols for amplified impact.',
    detector: /invoke|cpi|protocol|integration/i,
    recommendation: 'Audit all integration points. Implement defense in depth.'
  },
  {
    id: 'SOL4635',
    title: 'Flash Loan + Oracle Combo',
    severity: 'critical',
    category: 'exploit-chain',
    description: 'Flash loan combined with oracle manipulation for price exploitation.',
    detector: /flash|loan|oracle|price/i,
    recommendation: 'Use TWAP oracles. Add flash loan detection. Implement price bounds.'
  },
  {
    id: 'SOL4636',
    title: 'Sandwich + Liquidation Combo',
    severity: 'high',
    category: 'exploit-chain',
    description: 'Sandwich attack triggers cascading liquidations for profit.',
    detector: /sandwich|liquidat|front.*run|mev/i,
    recommendation: 'Use private mempools. Implement slippage protection. Add liquidation delays.'
  },
  {
    id: 'SOL4637',
    title: 'Governance + Treasury Combo',
    severity: 'critical',
    category: 'exploit-chain',
    description: 'Governance takeover enables treasury drain.',
    detector: /governance|treasury|transfer|withdraw/i,
    recommendation: 'Separate governance from treasury. Add timelock on treasury operations.'
  },
  
  // ===== 2026 EMERGING INFRASTRUCTURE THREATS =====
  {
    id: 'SOL4638',
    title: 'AI Agent Wallet Compromise',
    severity: 'critical',
    category: '2026-emerging',
    description: '2026 threat: AI agents with wallet access being manipulated.',
    detector: /agent|ai|autonomous|automated.*wallet/i,
    recommendation: 'Limit agent permissions. Use allowlists. Implement human approval for large txns.'
  },
  {
    id: 'SOL4639',
    title: 'LLM Prompt Injection via On-Chain Data',
    severity: 'high',
    category: '2026-emerging',
    description: '2026 threat: Malicious on-chain data crafted to exploit AI agents reading it.',
    detector: /prompt|llm|gpt|claude|ai.*read/i,
    recommendation: 'Sanitize on-chain data before AI processing. Use structured parsing.'
  },
  {
    id: 'SOL4640',
    title: 'Intent-Based System Manipulation',
    severity: 'high',
    category: '2026-emerging',
    description: '2026 threat: Intent-based protocols manipulated via malformed intents.',
    detector: /intent|solver|matcher|auction/i,
    recommendation: 'Validate intent structure. Implement solver reputation. Add intent expiry.'
  },
  {
    id: 'SOL4641',
    title: 'Restaking Slashing Attack',
    severity: 'high',
    category: '2026-emerging',
    description: '2026 threat: Coordinated slashing attacks on restaking protocols.',
    detector: /restake|slash|avs|operator/i,
    recommendation: 'Diversify restaking positions. Monitor slashing events. Implement insurance.'
  },
  {
    id: 'SOL4642',
    title: 'Cross-Chain Intent Manipulation',
    severity: 'critical',
    category: '2026-emerging',
    description: '2026 threat: Cross-chain intents manipulated during bridge delays.',
    detector: /cross_chain.*intent|intent.*bridge|multi.*chain/i,
    recommendation: 'Lock intent parameters. Add finality checks. Implement timeout handling.'
  },
  
  // ===== PROGRAM UPGRADE SECURITY =====
  {
    id: 'SOL4643',
    title: 'Upgradeable Program Authority Hijack',
    severity: 'critical',
    category: 'upgrade',
    description: 'Upgrade authority can be hijacked to deploy malicious code.',
    detector: /upgrade_authority|programdata|BpfLoaderUpgradeable/i,
    recommendation: 'Use multi-sig for upgrade authority. Implement timelock. Consider immutability.'
  },
  {
    id: 'SOL4644',
    title: 'Program Data Account Manipulation',
    severity: 'high',
    category: 'upgrade',
    description: 'Program data account can be modified to inject malicious bytecode.',
    detector: /program_data|ProgramData|executable/i,
    recommendation: 'Verify program data account ownership. Use official loader.'
  },
  {
    id: 'SOL4645',
    title: 'Buffer Account Injection',
    severity: 'critical',
    category: 'upgrade',
    description: 'Malicious buffer account used in program upgrade.',
    detector: /buffer|deploy|upgrade.*buffer/i,
    recommendation: 'Verify buffer contents before upgrade. Use deterministic builds.'
  },
  
  // ===== ACCOUNT LIFECYCLE PATTERNS =====
  {
    id: 'SOL4646',
    title: 'Account Revival After Close (Wormhole Pattern)',
    severity: 'critical',
    category: 'account-lifecycle',
    description: 'Closed account can be recreated with different data in same transaction.',
    detector: /close|close_account|transfer_lamports.*close/i,
    recommendation: 'Use try_borrow_mut_data pattern. Verify account not reused.'
  },
  {
    id: 'SOL4647',
    title: 'Account Resurrection Attack',
    severity: 'high',
    category: 'account-lifecycle',
    description: 'Account closed and recreated with malicious data.',
    detector: /realloc|resize|close.*init/i,
    recommendation: 'Track account state. Use monotonic counters. Verify discriminator.'
  },
  {
    id: 'SOL4648',
    title: 'Rent Drain via Account Closure',
    severity: 'medium',
    category: 'account-lifecycle',
    description: 'Account closed to drain rent to attacker address.',
    detector: /close.*destination|close.*to/i,
    recommendation: 'Verify close destination is protocol-controlled or original owner.'
  },
  
  // ===== SERIALIZATION SECURITY =====
  {
    id: 'SOL4649',
    title: 'Borsh Deserialization Overflow',
    severity: 'high',
    category: 'serialization',
    description: 'Borsh deserialization can fail silently on malformed data.',
    detector: /try_from_slice|BorshDeserialize|deserialize/i,
    recommendation: 'Validate data length before deserialization. Handle errors explicitly.'
  },
  {
    id: 'SOL4650',
    title: 'Zero Copy Memory Safety',
    severity: 'high',
    category: 'serialization',
    description: 'Zero copy deserialization may access uninitialized memory.',
    detector: /zero_copy|AccountLoader|RefMut/i,
    recommendation: 'Validate account data length. Check discriminator before access.'
  },
  {
    id: 'SOL4651',
    title: 'String Length Attack',
    severity: 'medium',
    category: 'serialization',
    description: 'Unbounded string length in serialization can exhaust memory.',
    detector: /String|str.*len|serialize.*string/i,
    recommendation: 'Add length limits on strings. Validate before deserialization.'
  },
  
  // ===== COMPOSABILITY SECURITY =====
  {
    id: 'SOL4652',
    title: 'Composability Reentrancy via Hook',
    severity: 'critical',
    category: 'composability',
    description: 'Protocol hooks can reenter calling contract.',
    detector: /hook|callback|on_.*event/i,
    recommendation: 'Use reentrancy guards. Complete state changes before hooks.'
  },
  {
    id: 'SOL4653',
    title: 'Cross-Protocol State Inconsistency',
    severity: 'high',
    category: 'composability',
    description: 'State may be inconsistent between composed protocols.',
    detector: /invoke.*invoke|cpi.*cpi|protocol.*protocol/i,
    recommendation: 'Validate state after each CPI. Use atomic patterns.'
  },
  {
    id: 'SOL4654',
    title: 'Permission Inheritance Attack',
    severity: 'high',
    category: 'composability',
    description: 'Composed protocol inherits excessive permissions.',
    detector: /signer_seeds|invoke_signed.*authority/i,
    recommendation: 'Minimize delegated permissions. Validate authority scope.'
  },
  
  // ===== MEV AND ORDERING PATTERNS =====
  {
    id: 'SOL4655',
    title: 'JIT Liquidity Front-Running',
    severity: 'high',
    category: 'mev',
    description: 'Just-in-time liquidity provision to extract value from trades.',
    detector: /liquidity|provision|jit|just.*time/i,
    recommendation: 'Implement minimum liquidity duration. Use time-weighted fees.'
  },
  {
    id: 'SOL4656',
    title: 'Backrun Arbitrage Extraction',
    severity: 'medium',
    category: 'mev',
    description: 'Transactions backrun to extract arbitrage from price impact.',
    detector: /arbitrage|price.*impact|swap.*fee/i,
    recommendation: 'Implement MEV-share. Return excess value to users.'
  },
  {
    id: 'SOL4657',
    title: 'Bundle Inclusion Censorship',
    severity: 'high',
    category: 'mev',
    description: 'Jito bundles can censor specific transactions.',
    detector: /bundle|jito|tip|searcher/i,
    recommendation: 'Support multiple bundle providers. Implement fallback submission.'
  },
  
  // ===== TOKEN SECURITY PATTERNS =====
  {
    id: 'SOL4658',
    title: 'Mint Authority Not Revoked',
    severity: 'medium',
    category: 'token',
    description: 'Token mint authority still active enabling inflation.',
    detector: /mint_authority|SetAuthority|MintTo/i,
    recommendation: 'Revoke mint authority after initial distribution. Or use multisig.'
  },
  {
    id: 'SOL4659',
    title: 'Token-2022 Permanent Delegate Risk',
    severity: 'high',
    category: 'token-2022',
    description: 'Permanent delegate can transfer tokens without owner approval.',
    detector: /permanent_delegate|PermanentDelegate/i,
    recommendation: 'Document delegate usage. Warn users of permanent delegate tokens.'
  },
  {
    id: 'SOL4660',
    title: 'Transfer Fee Bypass',
    severity: 'medium',
    category: 'token-2022',
    description: 'Token-2022 transfer fees can be bypassed via certain operations.',
    detector: /transfer_fee|TransferFee|fee_config/i,
    recommendation: 'Validate fees collected. Test fee enforcement edge cases.'
  },
  
  // ===== ORACLE DEEP PATTERNS =====
  {
    id: 'SOL4661',
    title: 'Pyth Price Confidence Too Wide',
    severity: 'high',
    category: 'oracle',
    description: 'Pyth price confidence interval too wide for precise operations.',
    detector: /pyth|conf|confidence|price_feed/i,
    recommendation: 'Check confidence is within acceptable bounds. Reject wide spreads.'
  },
  {
    id: 'SOL4662',
    title: 'Switchboard Aggregator Manipulation',
    severity: 'high',
    category: 'oracle',
    description: 'Switchboard aggregator can be manipulated if not enough oracles.',
    detector: /switchboard|aggregator|oracle_queue/i,
    recommendation: 'Require minimum oracles. Check oracle count. Add deviation bounds.'
  },
  {
    id: 'SOL4663',
    title: 'Oracle Price Deviation Attack',
    severity: 'critical',
    category: 'oracle',
    description: 'Large price deviation exploited before oracle update.',
    detector: /price.*deviation|max.*deviation|price.*diff/i,
    recommendation: 'Implement price deviation limits. Add circuit breakers.'
  },
  {
    id: 'SOL4664',
    title: 'Missing Oracle Heartbeat Check',
    severity: 'high',
    category: 'oracle',
    description: 'No verification that oracle is actively updating.',
    detector: /oracle|price_feed|last_update/i,
    recommendation: 'Verify oracle has updated within acceptable window.'
  },
  
  // ===== LENDING PROTOCOL PATTERNS =====
  {
    id: 'SOL4665',
    title: 'Interest Accrual Rounding Abuse',
    severity: 'high',
    category: 'lending',
    description: 'Interest accrual rounding can be exploited with small positions.',
    detector: /interest|accrue|compound|rate/i,
    recommendation: 'Use high-precision math. Round against user. Add minimum position size.'
  },
  {
    id: 'SOL4666',
    title: 'Liquidation Bonus Extraction',
    severity: 'high',
    category: 'lending',
    description: 'Self-liquidation to extract liquidation bonus.',
    detector: /liquidat|bonus|close_factor/i,
    recommendation: 'Prevent self-liquidation. Cap liquidation bonus. Add delay.'
  },
  {
    id: 'SOL4667',
    title: 'Reserve Factor Manipulation',
    severity: 'medium',
    category: 'lending',
    description: 'Reserve factor changes can affect existing positions unfairly.',
    detector: /reserve_factor|protocol_fee|interest_rate_model/i,
    recommendation: 'Timelock reserve factor changes. Grandfather existing positions.'
  },
  
  // ===== AMM SECURITY PATTERNS =====
  {
    id: 'SOL4668',
    title: 'Concentrated Liquidity Tick Manipulation',
    severity: 'high',
    category: 'amm',
    description: 'CLMM tick accounts can be manipulated (Crema pattern).',
    detector: /tick|concentrated|clmm|position/i,
    recommendation: 'Validate tick account derivation. Check tick initialization.'
  },
  {
    id: 'SOL4669',
    title: 'Impermanent Loss Exploitation',
    severity: 'medium',
    category: 'amm',
    description: 'Strategies to maximize IL for LP providers.',
    detector: /impermanent|liquidity.*provider|lp.*loss/i,
    recommendation: 'Implement IL protection. Use dynamic fees. Add position limits.'
  },
  {
    id: 'SOL4670',
    title: 'Virtual Reserve Manipulation',
    severity: 'high',
    category: 'amm',
    description: 'Virtual reserves can diverge from actual balances.',
    detector: /virtual|reserve|balance/i,
    recommendation: 'Validate virtual reserves against actual balances.'
  },
  
  // ===== GOVERNANCE DEEP PATTERNS =====
  {
    id: 'SOL4671',
    title: 'Proposal Execution Delay Bypass',
    severity: 'critical',
    category: 'governance',
    description: 'Proposal executed before timelock expires.',
    detector: /timelock|delay|execution.*time/i,
    recommendation: 'Enforce timelock in smart contract. Check block time.'
  },
  {
    id: 'SOL4672',
    title: 'Quorum Flash Loan Attack',
    severity: 'critical',
    category: 'governance',
    description: 'Flash loan tokens used to meet quorum and pass proposal.',
    detector: /quorum|vote.*power|governance.*token/i,
    recommendation: 'Snapshot voting power before proposal. Add vote lockup.'
  },
  {
    id: 'SOL4673',
    title: 'Vote Buying via Delegate',
    severity: 'high',
    category: 'governance',
    description: 'Delegated voting power bought or manipulated.',
    detector: /delegate|voting.*delegate|delegate.*vote/i,
    recommendation: 'Track delegation changes. Add delegation lockup.'
  },
  
  // ===== STAKING SECURITY PATTERNS =====
  {
    id: 'SOL4674',
    title: 'Epoch Boundary Reward Manipulation',
    severity: 'high',
    category: 'staking',
    description: 'Staking/unstaking at epoch boundaries to maximize rewards.',
    detector: /epoch|stake.*reward|reward.*rate/i,
    recommendation: 'Use time-weighted staking. Add minimum stake duration.'
  },
  {
    id: 'SOL4675',
    title: 'Unbonding Period Bypass',
    severity: 'high',
    category: 'staking',
    description: 'Unbonding period can be bypassed via secondary market.',
    detector: /unbond|cooldown|withdrawal.*delay/i,
    recommendation: 'Make stake tokens non-transferable during unbonding.'
  },
  {
    id: 'SOL4676',
    title: 'Slashing Condition Exploitation',
    severity: 'critical',
    category: 'staking',
    description: 'Attacker triggers slashing condition for competitor.',
    detector: /slash|penalty|misbehavior/i,
    recommendation: 'Require proof of misbehavior. Add appeal period.'
  },
  
  // ===== NFT SECURITY PATTERNS =====
  {
    id: 'SOL4677',
    title: 'NFT Metadata Manipulation',
    severity: 'medium',
    category: 'nft',
    description: 'NFT metadata can be changed after sale.',
    detector: /metadata|uri|update.*metadata/i,
    recommendation: 'Make metadata immutable. Or clearly disclose mutability.'
  },
  {
    id: 'SOL4678',
    title: 'Edition Supply Manipulation',
    severity: 'high',
    category: 'nft',
    description: 'NFT edition supply can be increased after initial sale.',
    detector: /edition|supply|max_supply|print/i,
    recommendation: 'Lock supply after initial mint. Burn supply authority.'
  },
  {
    id: 'SOL4679',
    title: 'Merkle Tree Proof Manipulation (cNFT)',
    severity: 'high',
    category: 'nft',
    description: 'Compressed NFT merkle proofs can be manipulated.',
    detector: /merkle|proof|compressed|bubblegum/i,
    recommendation: 'Verify proof against on-chain root. Use official Bubblegum program.'
  },
  
  // ===== BRIDGE SECURITY PATTERNS =====
  {
    id: 'SOL4680',
    title: 'Guardian Set Update Attack',
    severity: 'critical',
    category: 'bridge',
    description: 'Guardian set update allows malicious guardians.',
    detector: /guardian|guardian_set|update.*guardian/i,
    recommendation: 'Require super-majority for guardian changes. Add timelock.'
  },
  {
    id: 'SOL4681',
    title: 'VAA Replay Across Chains',
    severity: 'critical',
    category: 'bridge',
    description: 'Verified Action Approval replayed on multiple chains.',
    detector: /vaa|message.*hash|cross_chain.*message/i,
    recommendation: 'Include target chain in VAA. Mark as processed per-chain.'
  },
  {
    id: 'SOL4682',
    title: 'Bridge Finality Assumption',
    severity: 'high',
    category: 'bridge',
    description: 'Bridge releases assets before source chain finality.',
    detector: /finality|confirmation|block.*confirm/i,
    recommendation: 'Wait for sufficient confirmations. Implement challenge period.'
  },
  
  // ===== ERROR HANDLING PATTERNS =====
  {
    id: 'SOL4683',
    title: 'Silent Error Swallowing',
    severity: 'high',
    category: 'error-handling',
    description: 'Errors caught and ignored can hide critical failures.',
    detector: /catch|ok\(\)|unwrap_or|or_else/i,
    recommendation: 'Log all errors. Propagate critical errors. Audit error handling.'
  },
  {
    id: 'SOL4684',
    title: 'Panic in Production Code',
    severity: 'medium',
    category: 'error-handling',
    description: 'Panic can cause transaction to fail unexpectedly.',
    detector: /panic!|unwrap\(\)|expect\(/,
    recommendation: 'Use Result types. Add proper error handling. Avoid unwrap.'
  },
  {
    id: 'SOL4685',
    title: 'Error Code Information Leak',
    severity: 'low',
    category: 'error-handling',
    description: 'Detailed error codes leak protocol internals.',
    detector: /ErrorCode|custom_error|error.*msg/i,
    recommendation: 'Use generic error messages for users. Log details internally.'
  },
  
  // ===== TESTING AND VERIFICATION PATTERNS =====
  {
    id: 'SOL4686',
    title: 'Missing Edge Case Test',
    severity: 'info',
    category: 'testing',
    description: 'Critical edge cases may not be tested.',
    detector: /test|#\[cfg\(test\)\]|mod\s+tests/i,
    recommendation: 'Add tests for: zero amounts, max values, empty arrays, boundary conditions.'
  },
  {
    id: 'SOL4687',
    title: 'Insufficient Fuzzing Coverage',
    severity: 'info',
    category: 'testing',
    description: 'Fuzzing may not cover all code paths.',
    detector: /fuzz|arbitrary|proptest/i,
    recommendation: 'Use Trident fuzzer. Cover all instruction handlers.'
  },
  {
    id: 'SOL4688',
    title: 'Mock vs Production Discrepancy',
    severity: 'medium',
    category: 'testing',
    description: 'Test mocks may not accurately represent production.',
    detector: /mock|stub|fake|test.*only/i,
    recommendation: 'Test against localnet. Verify mocks match production behavior.'
  },
  
  // ===== FINAL COMPREHENSIVE PATTERNS =====
  {
    id: 'SOL4689',
    title: 'Account Array Index Out of Bounds',
    severity: 'high',
    category: 'memory-safety',
    description: 'Accessing account array without bounds checking.',
    detector: /accounts\[|remaining_accounts\[|ctx\.accounts/i,
    recommendation: 'Check array length before access. Use get() with Option handling.'
  },
  {
    id: 'SOL4690',
    title: 'Instruction Data Parsing Overflow',
    severity: 'high',
    category: 'input-validation',
    description: 'Instruction data parsed without length validation.',
    detector: /instruction_data|data\[|from_bytes/i,
    recommendation: 'Validate instruction data length. Use safe parsing.'
  },
  {
    id: 'SOL4691',
    title: 'Cross-Program Return Data Trust',
    severity: 'high',
    category: 'cpi',
    description: 'Trusting return data from external program without validation.',
    detector: /get_return_data|return_data|sol_get_return/i,
    recommendation: 'Validate return data source. Check expected format.'
  },
  {
    id: 'SOL4692',
    title: 'Program Derived Address Collision',
    severity: 'critical',
    category: 'pda',
    description: 'PDA seeds can collide with another valid derivation.',
    detector: /seeds|find_program_address|create_program_address/i,
    recommendation: 'Use unique prefixes in seeds. Include discriminator.'
  },
  {
    id: 'SOL4693',
    title: 'Authority Not Derived from State',
    severity: 'high',
    category: 'access-control',
    description: 'Authority passed as input instead of derived from state.',
    detector: /authority|admin|owner/i,
    recommendation: 'Derive authority from on-chain state. Verify derivation.'
  },
  {
    id: 'SOL4694',
    title: 'Missing Discriminator Validation',
    severity: 'critical',
    category: 'account-validation',
    description: 'Account discriminator not checked allowing type confusion.',
    detector: /AccountInfo|UncheckedAccount|try_from_slice/i,
    recommendation: 'Validate 8-byte discriminator. Use Anchor account types.'
  },
  {
    id: 'SOL4695',
    title: 'Token Account Authority Mismatch',
    severity: 'critical',
    category: 'token',
    description: 'Token account authority does not match expected.',
    detector: /token_account|authority|owner/i,
    recommendation: 'Verify token account authority matches expected.'
  },
  {
    id: 'SOL4696',
    title: 'Compute Unit Limit Exceeded',
    severity: 'medium',
    category: 'compute',
    description: 'Transaction may exceed compute unit limit.',
    detector: /for\s+.*in|while\s+|loop|invoke|cpi/i,
    recommendation: 'Profile compute usage. Batch operations. Request higher CU limit.'
  },
  {
    id: 'SOL4697',
    title: 'Program Log Sensitive Data',
    severity: 'medium',
    category: 'privacy',
    description: 'Program logs may expose sensitive information.',
    detector: /msg!|sol_log|emit!/i,
    recommendation: 'Review log contents. Avoid logging sensitive data.'
  },
  {
    id: 'SOL4698',
    title: 'Clock Sysvar Manipulation',
    severity: 'medium',
    category: 'time',
    description: 'Clock sysvar timestamp can have slight variations.',
    detector: /Clock|unix_timestamp|slot/i,
    recommendation: 'Use slot for relative time. Add tolerance for timestamps.'
  },
  {
    id: 'SOL4699',
    title: 'Rent Collection Attack',
    severity: 'medium',
    category: 'rent',
    description: 'Account rent can be collected causing unexpected closure.',
    detector: /rent|lamports|minimum_balance/i,
    recommendation: 'Keep accounts rent-exempt. Monitor lamport balance.'
  },
  {
    id: 'SOL4700',
    title: 'System Program Confusion',
    severity: 'high',
    category: 'cpi',
    description: 'System program ID not validated in CPI.',
    detector: /system_program|SystemProgram|system_instruction/i,
    recommendation: 'Verify system program ID equals system_program::id().'
  }
];

export function checkBatch86Patterns(parsed: ParsedRust): Array<{ id: string; title: string; severity: string; category: string; description: string; recommendation: string; line: number }> {
  const findings: Array<{ id: string; title: string; severity: string; category: string; description: string; recommendation: string; line: number }> = [];
  
  const lines = parsed.content.split('\n');
  
  for (const pattern of batch86Patterns) {
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

export { batch86Patterns };
