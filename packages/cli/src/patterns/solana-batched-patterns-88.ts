/**
 * SolShield Batch 88 Patterns
 * 
 * Source: Helius Complete History (38 Incidents) + Solsec PoC Deep Dives + 2026 Advanced Patterns
 * Patterns SOL4801-SOL4900
 * Created: Feb 6, 2026 4:30 AM
 */

import type { Finding, PatternInput } from './index.js';

interface PatternDef {
  id: string;
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  pattern: RegExp;
  description: string;
  recommendation: string;
}

const BATCH_88_PATTERNS: PatternDef[] = [
  // Helius Verified Incident Patterns (38 Incidents Analysis)
  {
    id: 'SOL4801',
    name: 'Solend Auth Bypass - UpdateReserveConfig Flaw',
    severity: 'critical',
    pattern: /update.*reserve.*config|UpdateReserveConfig(?![\s\S]{0,150}authority\s*==|[\s\S]{0,150}has_one\s*=\s*lending_market)/i,
    description: 'Based on Solend Aug 2021 exploit. Attacker bypassed admin checks by creating their own lending market and passing it as account. Put $2M at risk.',
    recommendation: 'Verify lending_market authority matches expected admin. Use has_one constraint on lending_market with admin authority.'
  },
  {
    id: 'SOL4802',
    name: 'Liquidation Threshold Manipulation',
    severity: 'critical',
    pattern: /liquidation.*threshold|liquidation_threshold(?![\s\S]{0,100}require!|[\s\S]{0,100}min_threshold|[\s\S]{0,100}MINIMUM_)/i,
    description: 'Solend exploit allowed attacker to lower liquidation threshold, making all borrows liquidatable. Combined with inflated bonus = profit.',
    recommendation: 'Add minimum liquidation threshold constant. Implement circuit breakers for parameter changes.'
  },
  {
    id: 'SOL4803',
    name: 'Liquidation Bonus Inflation',
    severity: 'critical',
    pattern: /liquidation.*bonus|liquidation_bonus(?![\s\S]{0,100}MAX_BONUS|[\s\S]{0,100}cap|[\s\S]{0,100}maximum)/i,
    description: 'Attackers can inflate liquidation bonuses to profit from forced liquidations. Solend exploit attempted 100%+ bonuses.',
    recommendation: 'Cap liquidation bonus to reasonable maximum (e.g., 15%). Add timelock for bonus changes.'
  },
  {
    id: 'SOL4804',
    name: 'Wormhole Guardian Signature Forgery',
    severity: 'critical',
    pattern: /guardian.*signature|verify.*guardian(?![\s\S]{0,100}valid_signature|[\s\S]{0,100}SignatureSet|[\s\S]{0,100}quorum)/i,
    description: 'Wormhole $326M exploit. Signature verification flaw allowed forging valid signatures without Guardian validation.',
    recommendation: 'Implement robust signature verification with complete input validation. Verify all Guardian signatures in quorum.'
  },
  {
    id: 'SOL4805',
    name: 'Bridge wETH Mint Without Collateral',
    severity: 'critical',
    pattern: /mint.*wrapped|wrapped.*mint|wETH|wSOL(?![\s\S]{0,150}collateral_check|[\s\S]{0,150}deposit_verified)/i,
    description: 'Wormhole allowed minting 120,000 wETH without depositing equivalent ETH collateral. Cross-chain bridges must verify deposits.',
    recommendation: 'Verify deposit on source chain before minting on destination. Use atomic swaps or verified message proofs.'
  },
  {
    id: 'SOL4806',
    name: 'Cashio Saber Arrow Mint Field Missing',
    severity: 'critical',
    pattern: /saber.*arrow|arrow.*account|lp.*token.*mint(?![\s\S]{0,100}mint\s*==|[\s\S]{0,100}validate_mint)/i,
    description: 'Cashio $52.8M exploit. Missing validation of mint field in saber_swap.arrow account enabled fake LP token collateral.',
    recommendation: 'Always validate mint addresses in LP token accounts. Verify LP token comes from whitelisted pool.'
  },
  {
    id: 'SOL4807',
    name: 'Infinite Mint Glitch Pattern',
    severity: 'critical',
    pattern: /mint.*amount|amount.*mint(?![\s\S]{0,100}max_supply|[\s\S]{0,100}supply_cap|[\s\S]{0,100}total_supply\s*<)/i,
    description: 'Cashio infinite mint glitch allowed minting 2 billion CASH tokens with worthless collateral.',
    recommendation: 'Implement supply caps and minting rate limits. Validate collateral value before any minting.'
  },
  {
    id: 'SOL4808',
    name: 'Root of Trust Chain Broken',
    severity: 'critical',
    pattern: /collateral.*account|backing.*token(?![\s\S]{0,100}verify_chain|[\s\S]{0,100}root_of_trust|[\s\S]{0,100}whitelist)/i,
    description: 'Cashio broke root of trust chain. Attacker used fake accounts with worthless collateral due to missing chain verification.',
    recommendation: 'Establish and verify complete root of trust chain. Whitelist all acceptable collateral tokens/pools.'
  },
  {
    id: 'SOL4809',
    name: 'Crema CLMM Fake Tick Account',
    severity: 'critical',
    pattern: /tick.*account|tick_array(?![\s\S]{0,100}owner\s*==|[\s\S]{0,100}seeds.*pool|[\s\S]{0,100}has_one)/i,
    description: 'Crema $8.8M exploit. Attacker created fake tick account bypassing owner verification, manipulated fee data.',
    recommendation: 'Verify tick account ownership and PDA derivation. Tick accounts must be derived from pool seeds.'
  },
  {
    id: 'SOL4810',
    name: 'CLMM Transaction Fee Data Manipulation',
    severity: 'critical',
    pattern: /fee.*owed|fee.*data|accumulated.*fee(?![\s\S]{0,100}verify_calculation|[\s\S]{0,100}total_fees\s*<=)/i,
    description: 'Crema exploit manipulated transaction fee data to claim excessive fees. Flash loan amplified the attack.',
    recommendation: 'Verify fee calculations match actual trades. Implement fee claim limits per position.'
  },
  
  // Audius Governance Exploit Patterns
  {
    id: 'SOL4811',
    name: 'Audius Malicious Proposal Execution',
    severity: 'critical',
    pattern: /proposal.*execute|execute.*proposal(?![\s\S]{0,100}validate_proposal|[\s\S]{0,100}timelock|[\s\S]{0,100}quorum_reached)/i,
    description: 'Audius $6.1M exploit. Attacker submitted and executed malicious proposals bypassing validation, reconfigured treasury.',
    recommendation: 'Implement proposal validation, timelocks, and minimum quorum requirements before execution.'
  },
  {
    id: 'SOL4812',
    name: 'Treasury Permission Reconfiguration',
    severity: 'critical',
    pattern: /treasury.*permission|treasury.*config|reconfigure.*treasury(?![\s\S]{0,100}multisig|[\s\S]{0,100}timelock)/i,
    description: 'Audius attacker reconfigured treasury permissions via governance, transferred 18.5M AUDIO tokens.',
    recommendation: 'Use multisig with timelock for treasury configuration. Implement emergency pause for suspicious changes.'
  },
  
  // Nirvana Finance Flash Loan Bonding Curve
  {
    id: 'SOL4813',
    name: 'Nirvana Bonding Curve Flash Loan Attack',
    severity: 'critical',
    pattern: /bonding.*curve.*price|price.*bonding(?![\s\S]{0,100}flash_loan_guard|[\s\S]{0,100}price_cap|[\s\S]{0,100}rate_limit)/i,
    description: 'Nirvana $3.5M exploit. Flash loan + bonding curve manipulation = minting tokens at inflated rate, draining stablecoins.',
    recommendation: 'Add flash loan protection to bonding operations. Implement price movement caps and rate limits.'
  },
  {
    id: 'SOL4814',
    name: 'Rising Floor Price Mechanism Bypass',
    severity: 'high',
    pattern: /floor.*price|rising.*floor|price.*floor(?![\s\S]{0,100}verify_reserve|[\s\S]{0,100}backing_ratio)/i,
    description: 'Nirvana\'s rising floor mechanism was bypassed. Price mechanisms need reserve backing verification.',
    recommendation: 'Verify reserve backing matches floor price claims. Use external oracles as secondary check.'
  },
  
  // Slope Wallet Private Key Leak
  {
    id: 'SOL4815',
    name: 'Slope Wallet Mnemonic Logging',
    severity: 'critical',
    pattern: /log.*mnemonic|mnemonic.*log|seed_phrase.*log|log.*seed|console.*private/i,
    description: 'Slope Wallet $8M loss. Mnemonics logged to centralized Sentry server, later exploited to drain wallets.',
    recommendation: 'NEVER log mnemonics, private keys, or seed phrases. Audit all logging code paths.'
  },
  {
    id: 'SOL4816',
    name: 'Centralized Telemetry Key Exposure',
    severity: 'critical',
    pattern: /sentry|telemetry|analytics(?![\s\S]{0,50}exclude.*key|[\s\S]{0,50}filter.*secret)/i,
    description: 'Slope sent sensitive wallet data to Sentry telemetry. Centralized logging of user data = security risk.',
    recommendation: 'Filter all sensitive data from telemetry. Use local-only logging for wallet operations.'
  },
  
  // OptiFi Lockup Bug
  {
    id: 'SOL4817',
    name: 'OptiFi Accidental Program Close',
    severity: 'critical',
    pattern: /program.*close|close.*program|shutdown.*market(?![\s\S]{0,100}require_empty|[\s\S]{0,100}zero_balance)/i,
    description: 'OptiFi $661K locked forever. Admin accidentally called close on program with active user deposits.',
    recommendation: 'Require zero balances/no active positions before program/market closure. Add confirmation steps.'
  },
  {
    id: 'SOL4818',
    name: 'Irreversible Protocol Shutdown',
    severity: 'high',
    pattern: /shutdown|terminate|close_program(?![\s\S]{0,100}migration_path|[\s\S]{0,100}recovery)/i,
    description: 'OptiFi shutdown was irreversible, locking $661K user funds permanently. Programs need migration paths.',
    recommendation: 'Implement migration/recovery mechanisms. Never permanently lock user funds without escape hatch.'
  },
  
  // Mango Markets Oracle Manipulation ($116M)
  {
    id: 'SOL4819',
    name: 'Mango MNGO Perp Price Manipulation',
    severity: 'critical',
    pattern: /perp.*price|perpetual.*oracle(?![\s\S]{0,100}twap|[\s\S]{0,100}time_weighted|[\s\S]{0,100}window)/i,
    description: 'Mango $116M exploit. Attacker manipulated MNGO perp price using thin liquidity, used unrealized gains as collateral.',
    recommendation: 'Use TWAP for collateral valuation. Implement price deviation checks and liquidity-based limits.'
  },
  {
    id: 'SOL4820',
    name: 'Unrealized PnL as Collateral',
    severity: 'critical',
    pattern: /unrealized.*pnl|unrealized.*profit|pnl.*collateral(?![\s\S]{0,100}time_delay|[\s\S]{0,100}settlement)/i,
    description: 'Mango allowed unrealized PnL as collateral for borrowing. Attacker borrowed against inflated unrealized gains.',
    recommendation: 'Require settlement/time delay before unrealized PnL can be used as collateral. Limit PnL-backed borrowing.'
  },
  {
    id: 'SOL4821',
    name: 'Thin Liquidity Oracle Manipulation',
    severity: 'critical',
    pattern: /thin.*liquidity|low.*liquidity.*price(?![\s\S]{0,100}minimum_liquidity|[\s\S]{0,100}volume_check)/i,
    description: 'Mango MNGO-PERP had thin liquidity, making price easy to manipulate. $116M exploit used this.',
    recommendation: 'Implement minimum liquidity requirements for oracle price validity. Use multiple sources.'
  },
  
  // UXD Protocol Mango Dependency
  {
    id: 'SOL4822',
    name: 'UXD Cascading Protocol Dependency',
    severity: 'high',
    pattern: /mango.*integration|external.*protocol(?![\s\S]{0,100}risk_limit|[\s\S]{0,100}fallback)/i,
    description: 'UXD lost $20M due to Mango exploit cascade. Protocol dependency on compromised external protocol.',
    recommendation: 'Implement exposure limits to external protocols. Have fallback mechanisms for protocol failures.'
  },
  
  // Tulip Protocol Leveraged Yield
  {
    id: 'SOL4823',
    name: 'Tulip Leveraged Yield Vulnerability',
    severity: 'high',
    pattern: /leveraged.*yield|yield.*leverage(?![\s\S]{0,100}max_leverage|[\s\S]{0,100}collateral_ratio)/i,
    description: 'Tulip v1 leveraged yield impacted by Mango exploit. Levered positions amplify protocol dependency risks.',
    recommendation: 'Cap maximum leverage. Implement circuit breakers for external protocol failures.'
  },
  
  // Raydium Admin Key Compromise ($4.4M)
  {
    id: 'SOL4824',
    name: 'Raydium Admin Private Key Compromise',
    severity: 'critical',
    pattern: /admin.*key|pool_authority.*key(?![\s\S]{0,100}multisig|[\s\S]{0,100}hardware_wallet)/i,
    description: 'Raydium $4.4M loss from admin key compromise. Single admin key = single point of failure.',
    recommendation: 'Use multisig for all admin operations. Store admin keys in hardware wallets with air gap.'
  },
  {
    id: 'SOL4825',
    name: 'Pool Fee Withdrawal Without Multisig',
    severity: 'critical',
    pattern: /withdraw.*fee|fee.*withdrawal|pool.*fee(?![\s\S]{0,100}multisig|[\s\S]{0,100}timelock|[\s\S]{0,100}governance)/i,
    description: 'Raydium attacker withdrew accumulated pool fees using compromised admin key. No multisig protection.',
    recommendation: 'Require multisig + timelock for all pool fee withdrawals. Implement withdrawal limits.'
  },
  
  // Cypher Protocol Insider Theft
  {
    id: 'SOL4826',
    name: 'Cypher Insider Access Abuse',
    severity: 'critical',
    pattern: /insider.*access|employee.*withdraw|team.*authority(?![\s\S]{0,100}audit_log|[\s\S]{0,100}separation_of_duties)/i,
    description: 'Cypher $1.04M initial + $317K later stolen by insider. Former employee Barrett Hoak had retained access.',
    recommendation: 'Implement access revocation procedures. Require multisig for all admin actions. Audit all access.'
  },
  {
    id: 'SOL4827',
    name: 'Post-Exploit Access Retention',
    severity: 'critical',
    pattern: /retained.*access|legacy.*key|old.*admin(?![\s\S]{0,100}key_rotation|[\s\S]{0,100}revoke)/i,
    description: 'Cypher insider retained access after initial exploit, stealing additional $317K in 2024.',
    recommendation: 'Rotate all keys after any security incident. Audit and revoke all non-essential access.'
  },
  
  // SVT Token Fake Approval
  {
    id: 'SOL4828',
    name: 'SVT Fake Approval Permission Exploit',
    severity: 'critical',
    pattern: /fake.*approval|approval.*exploit|token.*approve(?![\s\S]{0,100}verify_source|[\s\S]{0,100}user_initiated)/i,
    description: 'SVT Token $265K loss via fake approval. CertiK alert detected. Users unknowingly approved malicious drainer.',
    recommendation: 'Verify approval source is legitimate. Implement approval amount limits and expiry.'
  },
  
  // io.net GPU Sybil Attack
  {
    id: 'SOL4829',
    name: 'DePIN GPU Sybil Attack',
    severity: 'high',
    pattern: /gpu.*node|node.*verification|sybil.*detection(?![\s\S]{0,100}proof_of_work|[\s\S]{0,100}stake_requirement)/i,
    description: 'io.net faced Sybil attack via fake GPU nodes for airdrop farming. DePIN platforms need robust node verification.',
    recommendation: 'Implement proof-of-work challenges for node verification. Require stake for node registration.'
  },
  
  // Synthetify DAO Treasury Raid
  {
    id: 'SOL4830',
    name: 'DAO Treasury Unauthorized Transfer',
    severity: 'critical',
    pattern: /dao.*treasury.*transfer|treasury.*withdraw(?![\s\S]{0,100}proposal_approved|[\s\S]{0,100}timelock|[\s\S]{0,100}multisig)/i,
    description: 'Synthetify DAO treasury exploit via unauthorized transfer. Governance + treasury security critical.',
    recommendation: 'Require approved proposal + timelock + multisig for treasury transfers. Implement rate limits.'
  },
  
  // Aurory NFT Gaming Exploit
  {
    id: 'SOL4831',
    name: 'Gaming NFT Reward Manipulation',
    severity: 'high',
    pattern: /game.*reward|nft.*reward|play.*to.*earn(?![\s\S]{0,100}verify_gameplay|[\s\S]{0,100}anti_cheat)/i,
    description: 'Aurory gaming exploit manipulated NFT rewards. Gaming protocols need robust anti-cheat and verification.',
    recommendation: 'Implement server-side gameplay verification. Add anti-cheat mechanisms and reward rate limits.'
  },
  
  // Thunder Terminal MongoDB Flaw
  {
    id: 'SOL4832',
    name: 'MongoDB Session Token Extraction',
    severity: 'critical',
    pattern: /mongodb|session.*token|nosql(?![\s\S]{0,100}sanitize|[\s\S]{0,100}encrypt.*token)/i,
    description: 'Thunder Terminal $240K loss. Attacker exploited MongoDB flaw to extract session tokens and drain wallets.',
    recommendation: 'Encrypt all session tokens at rest. Implement database access controls and injection prevention.'
  },
  {
    id: 'SOL4833',
    name: 'Third-Party Service Database Compromise',
    severity: 'critical',
    pattern: /third.*party.*db|external.*database|service.*integration(?![\s\S]{0,100}encryption|[\s\S]{0,100}isolated)/i,
    description: 'Thunder Terminal\'s MongoDB was third-party service. Database security critical for trading bots.',
    recommendation: 'Encrypt sensitive data in external databases. Use database isolation and access logging.'
  },
  
  // Saga DAO MEV Exploit
  {
    id: 'SOL4834',
    name: 'NFT DAO MEV Sandwich Attack',
    severity: 'high',
    pattern: /nft.*auction|auction.*bid|dao.*nft(?![\s\S]{0,100}commit_reveal|[\s\S]{0,100}private_mempool)/i,
    description: 'Saga DAO NFT auction manipulated via MEV. Public bids frontrun by searchers.',
    recommendation: 'Use commit-reveal schemes for auctions. Implement private mempools or auction mechanisms.'
  },
  
  // Solareum Honeypot Contract
  {
    id: 'SOL4835',
    name: 'Solareum Honeypot Contract Pattern',
    severity: 'critical',
    pattern: /withdraw.*disabled|sell.*blocked|honeypot(?![\s\S]{0,100}legitimate|[\s\S]{0,100}audit)/i,
    description: 'Solareum $500K loss. Token contract was honeypot - users could buy but not sell.',
    recommendation: 'Audit token contracts for withdrawal restrictions. Use verified contract templates.'
  },
  
  // Pump.fun Employee Exploit
  {
    id: 'SOL4836',
    name: 'Pump.fun Bonding Curve Employee Abuse',
    severity: 'critical',
    pattern: /bonding.*curve.*access|employee.*bonding(?![\s\S]{0,100}no_privileged_access|[\s\S]{0,100}audit)/i,
    description: 'Pump.fun $1.9M via former employee with privileged access to bonding curve contracts.',
    recommendation: 'Remove all privileged employee access to live contracts. Use permissionless designs.'
  },
  {
    id: 'SOL4837',
    name: 'Employee Privilege Escalation',
    severity: 'critical',
    pattern: /employee.*access|staff.*privilege|team.*key(?![\s\S]{0,100}revoke_on_departure|[\s\S]{0,100}least_privilege)/i,
    description: 'Pump.fun employee had excessive access. Insider threat from former team members is real.',
    recommendation: 'Implement least-privilege principle. Revoke all access immediately upon departure.'
  },
  
  // Banana Gun Bot Compromise
  {
    id: 'SOL4838',
    name: 'Telegram Bot Oracle Injection',
    severity: 'critical',
    pattern: /telegram.*bot.*oracle|bot.*price.*feed(?![\s\S]{0,100}verify_source|[\s\S]{0,100}signed_data)/i,
    description: 'Banana Gun $1.4M loss. Trading bot\'s price oracle was compromised, executing at manipulated prices.',
    recommendation: 'Verify oracle data signatures. Use multiple price sources with deviation checks.'
  },
  {
    id: 'SOL4839',
    name: 'Trading Bot API Key Exposure',
    severity: 'critical',
    pattern: /api.*key.*bot|bot.*credential|trading.*bot.*key(?![\s\S]{0,100}encrypted|[\s\S]{0,100}hsm)/i,
    description: 'Trading bots hold user funds. API key compromise = total loss. Banana Gun refunded users.',
    recommendation: 'Store API keys in HSM/encrypted storage. Implement IP whitelisting and withdrawal limits.'
  },
  
  // DEXX Private Key Leak ($30M)
  {
    id: 'SOL4840',
    name: 'DEXX Centralized Key Storage',
    severity: 'critical',
    pattern: /centralized.*key|key.*storage|private_key.*server(?![\s\S]{0,100}hsm|[\s\S]{0,100}mpc|[\s\S]{0,100}tee)/i,
    description: 'DEXX $30M loss. Private keys stored on centralized server were leaked. Largest 2024 Solana loss.',
    recommendation: 'Use MPC or HSM for key management. Never store plain private keys on servers.'
  },
  {
    id: 'SOL4841',
    name: 'Non-Custodial Claims With Custodial Reality',
    severity: 'critical',
    pattern: /non.*custodial|self.*custody(?![\s\S]{0,100}verify_client_side|[\s\S]{0,100}no_server_keys)/i,
    description: 'DEXX claimed non-custodial but stored keys server-side. Verify custody claims match implementation.',
    recommendation: 'Audit custody model. True non-custodial means keys NEVER touch servers.'
  },
  
  // NoOnes P2P Bridge Exploit
  {
    id: 'SOL4842',
    name: 'NoOnes Bridge Validation Flaw',
    severity: 'critical',
    pattern: /p2p.*bridge|bridge.*validation(?![\s\S]{0,100}proof_verification|[\s\S]{0,100}merkle_root)/i,
    description: 'NoOnes $8.5M loss from P2P bridge exploit. ZachXBT alert helped detection.',
    recommendation: 'Implement robust cross-chain proof verification. Use merkle proofs for transaction validation.'
  },
  
  // Loopscale RateX Bug ($5.8M)
  {
    id: 'SOL4843',
    name: 'Loopscale RateX Collateral Bug',
    severity: 'critical',
    pattern: /rate.*collateral|collateral.*rate(?![\s\S]{0,100}verify_rate|[\s\S]{0,100}bound_check)/i,
    description: 'Loopscale $5.8M loss via RateX-based collateral bug. All funds recovered via negotiation.',
    recommendation: 'Verify rate calculations have bounds. Implement collateral validation with multiple checks.'
  },
  
  // Parcl Front-End Supply Chain
  {
    id: 'SOL4844',
    name: 'Parcl Frontend CDN Compromise',
    severity: 'critical',
    pattern: /cdn.*script|frontend.*inject|javascript.*cdn(?![\s\S]{0,100}sri|[\s\S]{0,100}integrity_check)/i,
    description: 'Parcl frontend compromised via malicious script injection. Supply chain attack on CDN.',
    recommendation: 'Use Subresource Integrity (SRI) for all external scripts. Self-host critical dependencies.'
  },
  
  // Web3.js Supply Chain ($160K)
  {
    id: 'SOL4845',
    name: 'Web3.js NPM Package Backdoor',
    severity: 'critical',
    pattern: /@solana\/web3\.js|solana.*web3(?![\s\S]{0,50}pinned_version|[\s\S]{0,50}lock_file)/i,
    description: 'Web3.js $160K loss via NPM backdoor. Compromised versions 1.95.6-1.95.7 contained key drainer.',
    recommendation: 'Pin exact dependency versions. Use lockfiles. Audit dependency updates. Use npm audit.'
  },
  {
    id: 'SOL4846',
    name: 'NPM Package Key Exfiltration',
    severity: 'critical',
    pattern: /npm.*install|package.*json(?![\s\S]{0,100}audit|[\s\S]{0,100}verified_checksum)/i,
    description: 'Web3.js backdoor exfiltrated private keys via postinstall script. Supply chain attacks are real.',
    recommendation: 'Run npm audit before install. Review postinstall scripts. Use package-lock.json.'
  },
  
  // Grape Protocol Network-Level
  {
    id: 'SOL4847',
    name: 'Network Spam Attack 17-Hour Outage',
    severity: 'critical',
    pattern: /spam.*attack|transaction.*flood|ddos.*network(?![\s\S]{0,100}rate_limit|[\s\S]{0,100}spam_filter)/i,
    description: 'Grape Protocol spam attack caused 17-hour Solana outage Sep 2021. Network-level vulnerability.',
    recommendation: 'Implement transaction rate limits and spam filtering at protocol level.'
  },
  
  // Candy Machine NFT Minting
  {
    id: 'SOL4848',
    name: 'NFT Minting Bot Congestion',
    severity: 'high',
    pattern: /mint.*bot|nft.*bot|mass.*mint(?![\s\S]{0,100}captcha|[\s\S]{0,100}rate_limit)/i,
    description: 'Candy Machine NFT minting caused network congestion. Bot activity overwhelmed validators.',
    recommendation: 'Implement minting rate limits. Use captcha or proof-of-humanity for NFT mints.'
  },
  
  // Jito DDoS Attack
  {
    id: 'SOL4849',
    name: 'Jito Mempool DDoS',
    severity: 'high',
    pattern: /jito.*mempool|bundle.*spam|mev.*ddos(?![\s\S]{0,100}stake_required|[\s\S]{0,100}reputation)/i,
    description: 'Jito faced DDoS via bundle spam Feb 2025. MEV infrastructure is attack target.',
    recommendation: 'Require stake for bundle submission. Implement reputation-based rate limiting.'
  },
  
  // Phantom Wallet DDoS
  {
    id: 'SOL4850',
    name: 'Wallet RPC Endpoint DDoS',
    severity: 'high',
    pattern: /rpc.*endpoint|wallet.*rpc(?![\s\S]{0,100}load_balancer|[\s\S]{0,100}fallback_rpc)/i,
    description: 'Phantom wallet faced DDoS on RPC endpoints Mar 2025. Wallet infrastructure needs resilience.',
    recommendation: 'Use multiple RPC providers with automatic failover. Implement request caching.'
  },
  
  // Solana Core Protocol Vulnerabilities
  {
    id: 'SOL4851',
    name: 'Turbine Data Propagation Bug',
    severity: 'critical',
    pattern: /turbine|data.*propagation|shred(?![\s\S]{0,100}verify_shred|[\s\S]{0,100}erasure_coding)/i,
    description: 'Solana Turbine bug 2022 caused network instability. Data propagation layer is critical.',
    recommendation: 'Implement robust shred verification. Use erasure coding for data recovery.'
  },
  {
    id: 'SOL4852',
    name: 'Durable Nonce Replay Vulnerability',
    severity: 'critical',
    pattern: /durable.*nonce|nonce.*replay(?![\s\S]{0,100}advance_nonce|[\s\S]{0,100}unique_nonce)/i,
    description: 'Solana durable nonce bug allowed potential transaction replay. Fixed in 2022.',
    recommendation: 'Always advance nonce after use. Verify nonce state before transaction execution.'
  },
  {
    id: 'SOL4853',
    name: 'Duplicate Block Production',
    severity: 'critical',
    pattern: /duplicate.*block|block.*production(?![\s\S]{0,100}leader_verification|[\s\S]{0,100}slot_unique)/i,
    description: 'Duplicate block bug 2023 could cause chain forks. Validator consensus critical.',
    recommendation: 'Verify leader schedule before block production. Implement fork detection.'
  },
  {
    id: 'SOL4854',
    name: 'JIT Cache Execution Bug',
    severity: 'critical',
    pattern: /jit.*cache|cache.*execution|bpf.*jit(?![\s\S]{0,100}cache_invalidation|[\s\S]{0,100}verify_compiled)/i,
    description: 'JIT cache bug 2024 caused 5-hour outage. Compiled program caching needs validation.',
    recommendation: 'Implement cache invalidation checks. Verify compiled code matches source.'
  },
  {
    id: 'SOL4855',
    name: 'ELF Address Alignment Vulnerability',
    severity: 'critical',
    pattern: /elf.*alignment|address.*alignment|memory.*align(?![\s\S]{0,100}verify_alignment|[\s\S]{0,100}aligned\()/i,
    description: 'ELF address alignment bug 2024 could cause program crashes. Memory safety critical.',
    recommendation: 'Verify ELF section alignment. Use #[repr(align)] for critical structures.'
  },
  
  // Cope Roulette Reverting Transaction Exploit
  {
    id: 'SOL4856',
    name: 'Cope Roulette Revert Exploit Pattern',
    severity: 'critical',
    pattern: /revert.*check|simulation.*detect|simulate.*revert(?![\s\S]{0,100}random_seed|[\s\S]{0,100}commitment)/i,
    description: 'Cope Roulette exploit: simulate transaction, revert if unfavorable, retry until win. Solsec PoC.',
    recommendation: 'Use commit-reveal schemes for randomness. Make outcome independent of simulation.'
  },
  {
    id: 'SOL4857',
    name: 'Predictable Random Outcome',
    severity: 'critical',
    pattern: /random.*outcome|gambling.*random(?![\s\S]{0,100}vrf|[\s\S]{0,100}commit_reveal|[\s\S]{0,100}external_entropy)/i,
    description: 'Gambling/lottery contracts vulnerable if outcome can be predicted before commitment.',
    recommendation: 'Use VRF (Verifiable Random Function) or commit-reveal for unpredictable outcomes.'
  },
  
  // Port Finance Rounding Attack
  {
    id: 'SOL4858',
    name: 'Port Finance $2.6B Rounding Attack',
    severity: 'critical',
    pattern: /rounding.*error|rounding.*attack|interest.*rounding(?![\s\S]{0,100}floor_only|[\s\S]{0,100}round_down)/i,
    description: 'Port Finance rounding bug put $2.6B at risk. Neodyme disclosure. Small rounding errors compound.',
    recommendation: 'Always round in protocol\'s favor (floor for rewards, ceil for debts). Use high precision.'
  },
  {
    id: 'SOL4859',
    name: 'Lending Interest Calculation Precision',
    severity: 'high',
    pattern: /interest.*calculation|calculate.*interest(?![\s\S]{0,100}high_precision|[\s\S]{0,100}u128|[\s\S]{0,100}decimal)/i,
    description: 'Interest calculations need high precision to prevent exploitation via many small transactions.',
    recommendation: 'Use u128/u256 for intermediate calculations. Implement minimum amounts.'
  },
  
  // Jet Protocol Break Bug
  {
    id: 'SOL4860',
    name: 'Jet Protocol Break Statement Bug',
    severity: 'critical',
    pattern: /break[\s]*;|early.*return(?![\s\S]{0,100}validate_state|[\s\S]{0,100}post_condition)/i,
    description: 'Jet Protocol bug: misplaced break statement allowed full treasury withdrawal. Jayne disclosure.',
    recommendation: 'Review all break/return statements. Ensure state validation after early exits.'
  },
  {
    id: 'SOL4861',
    name: 'Unintended Loop Exit Vulnerability',
    severity: 'high',
    pattern: /for\s*\([\s\S]{0,50}break|while[\s\S]{0,50}break(?![\s\S]{0,30}after_check)/,
    description: 'Unintended break in loops can skip critical validation. Jet Protocol exploit pattern.',
    recommendation: 'Validate loop completion. Ensure all iterations execute critical checks.'
  },
  
  // Schrodinger NFT + Incinerator Attack Chain
  {
    id: 'SOL4862',
    name: 'Exploit Chaining Pattern',
    severity: 'critical',
    pattern: /chain.*exploit|combined.*attack|sequential.*vulnerability(?![\s\S]{0,100}defense_in_depth)/i,
    description: 'Schrodinger NFT: small exploits chained into major attack. samczsun explains exploit chaining.',
    recommendation: 'Implement defense-in-depth. Each layer should independently prevent exploitation.'
  },
  {
    id: 'SOL4863',
    name: 'NFT Incinerator Contract Abuse',
    severity: 'high',
    pattern: /incinerator|burn.*nft|nft.*burn(?![\s\S]{0,100}verify_owner|[\s\S]{0,100}authentic_mint)/i,
    description: 'Incinerator contracts can be abused to claim rewards for burning fake NFTs.',
    recommendation: 'Verify NFT mint authority and collection before accepting burns.'
  },
  
  // Solend Malicious Lending Market
  {
    id: 'SOL4864',
    name: 'Fake Lending Market Creation',
    severity: 'critical',
    pattern: /create.*market|new.*lending.*market(?![\s\S]{0,100}authorized|[\s\S]{0,100}whitelist)/i,
    description: 'Rooter disclosed: anyone could create lending market in Solend, bypassing intended access controls.',
    recommendation: 'Restrict market creation to authorized accounts. Validate all market parameters.'
  },
  
  // SPL Token Approve Revocation
  {
    id: 'SOL4865',
    name: 'SPL Token Approval Not Revoked',
    severity: 'high',
    pattern: /approve.*token|token.*approval(?![\s\S]{0,100}revoke|[\s\S]{0,100}expiry|[\s\S]{0,100}limited)/i,
    description: 'Hana\'s tool: users forget to revoke token approvals, leaving funds at risk.',
    recommendation: 'Prompt users to revoke approvals. Implement approval expiry or limited amounts.'
  },
  
  // OtterSec LP Token Oracle Manipulation
  {
    id: 'SOL4866',
    name: 'LP Token Fair Pricing Bypass',
    severity: 'critical',
    pattern: /lp.*token.*price|lp.*oracle(?![\s\S]{0,100}fair_price|[\s\S]{0,100}reserve_ratio)/i,
    description: 'OtterSec $200M bluff: LP token oracle manipulation via AMM price movement.',
    recommendation: 'Use fair pricing formulas for LP tokens. Calculate from reserves, not spot price.'
  },
  {
    id: 'SOL4867',
    name: 'AMM Price to Oracle Manipulation',
    severity: 'critical',
    pattern: /amm.*price|spot.*price.*oracle(?![\s\S]{0,100}twap|[\s\S]{0,100}manipulation_check)/i,
    description: 'Moving AMM price to manipulate oracle, then exploit lending protocol. OtterSec research.',
    recommendation: 'Never use spot AMM prices for oracle. Use TWAP with long enough window.'
  },
  
  // Drift Oracle Guardrails
  {
    id: 'SOL4868',
    name: 'Missing Oracle Guardrails',
    severity: 'high',
    pattern: /oracle.*price[\s\S]{0,50}(?!guardrail|guard|valid|stale|confidence)/i,
    description: 'Drift implements oracle guardrails. Protocols should have price deviation limits.',
    recommendation: 'Implement Drift-style guardrails: price bands, staleness checks, confidence intervals.'
  },
  
  // Neodyme Lending Vulnerability $2.6B
  {
    id: 'SOL4869',
    name: 'SPL Lending Rounding Vulnerability',
    severity: 'critical',
    pattern: /spl.*lending|lending.*rounding(?![\s\S]{0,100}floor|[\s\S]{0,100}minimum_amount)/i,
    description: 'Neodyme found: innocent rounding error in SPL lending put $2.6B at risk.',
    recommendation: 'Use floor for interest calculations. Implement minimum deposit/withdraw amounts.'
  },
  
  // BlockSec rBPF Integer Overflow
  {
    id: 'SOL4870',
    name: 'rBPF Virtual Machine Overflow',
    severity: 'critical',
    pattern: /rbpf|bpf.*vm|vm.*integer(?![\s\S]{0,100}bounds_check|[\s\S]{0,100}checked_)/i,
    description: 'BlockSec found integer overflow in Solana rBPF VM. Core infrastructure vulnerability.',
    recommendation: 'Use checked arithmetic in VM implementations. Audit all low-level code.'
  },
  
  // Sec3 Arithmetic Overflow/Underflow
  {
    id: 'SOL4871',
    name: 'Unchecked Math Operations',
    severity: 'high',
    pattern: /\+\s*\d+|\-\s*\d+|\*\s*\d+(?![\s\S]{0,30}checked_|[\s\S]{0,30}saturating_)/,
    description: 'Sec3: Don\'t use +, -, /, * directly. Always use checked operations.',
    recommendation: 'Use checked_add, checked_sub, checked_mul, checked_div, or saturating variants.'
  },
  
  // Armani Sealevel Attack Patterns
  {
    id: 'SOL4872',
    name: 'Sealevel Missing Owner Check',
    severity: 'critical',
    pattern: /AccountInfo[\s\S]{0,100}(?!owner\s*==|key\s*==|has_one)/,
    description: 'Armani Sealevel Attacks: Missing owner check allows passing malicious accounts.',
    recommendation: 'Always check account.owner == expected_program before trusting account data.'
  },
  {
    id: 'SOL4873',
    name: 'Sealevel Missing Signer Check',
    severity: 'critical',
    pattern: /authority[\s\S]{0,50}AccountInfo(?![\s\S]{0,30}is_signer|[\s\S]{0,30}Signer)/i,
    description: 'Armani: Authority accounts must verify is_signer to prevent unauthorized actions.',
    recommendation: 'Use Signer<> type in Anchor or verify is_signer manually in native.'
  },
  {
    id: 'SOL4874',
    name: 'Sealevel Account Data Confusion',
    severity: 'critical',
    pattern: /deserialize|try_from_slice(?![\s\S]{0,50}discriminator|[\s\S]{0,50}account_type)/i,
    description: 'Armani: Deserialization without type checking allows account confusion attacks.',
    recommendation: 'Verify 8-byte discriminator before deserializing. Use Anchor #[account] types.'
  },
  {
    id: 'SOL4875',
    name: 'Sealevel Initialization Check Missing',
    severity: 'critical',
    pattern: /init[\s\S]{0,30}=[\s\S]{0,30}(false|0)(?![\s\S]{0,50}require!|[\s\S]{0,50}assert)/,
    description: 'Armani: Missing initialization check allows reinitializing accounts with attacker data.',
    recommendation: 'Check is_initialized before any account modification. Use init constraint.'
  },
  
  // Advanced 2026 Patterns
  {
    id: 'SOL4876',
    name: 'AI Agent Wallet Security',
    severity: 'critical',
    pattern: /ai.*agent|agent.*wallet|autonomous.*transaction(?![\s\S]{0,100}spending_limit|[\s\S]{0,100}approval)/i,
    description: '2026: AI agents need spending limits and human approval for large transactions.',
    recommendation: 'Implement spending limits, transaction whitelists, and human-in-the-loop for high-value ops.'
  },
  {
    id: 'SOL4877',
    name: 'Token-2022 Transfer Hook Reentrancy',
    severity: 'critical',
    pattern: /transfer.*hook|TransferHook(?![\s\S]{0,100}reentrancy_guard|[\s\S]{0,100}nonreentrant)/i,
    description: 'Token-2022 transfer hooks can enable reentrancy. Guard against recursive calls.',
    recommendation: 'Implement reentrancy guard in transfer hooks. Update state before external calls.'
  },
  {
    id: 'SOL4878',
    name: 'Token-2022 Confidential Transfer Validation',
    severity: 'critical',
    pattern: /confidential.*transfer|encrypted.*amount(?![\s\S]{0,100}verify_proof|[\s\S]{0,100}range_proof)/i,
    description: 'Confidential transfers need proper zero-knowledge proof validation.',
    recommendation: 'Always verify ZK proofs for confidential transfers. Validate range proofs.'
  },
  {
    id: 'SOL4879',
    name: 'Permanent Delegate Abuse',
    severity: 'high',
    pattern: /permanent.*delegate|PermanentDelegate(?![\s\S]{0,100}user_consent|[\s\S]{0,100}warning)/i,
    description: 'Token-2022 permanent delegate can burn/transfer without approval. High risk extension.',
    recommendation: 'Warn users about permanent delegates. Consider disallowing for high-value tokens.'
  },
  {
    id: 'SOL4880',
    name: 'Compressed NFT Proof Manipulation',
    severity: 'critical',
    pattern: /merkle.*proof|cnft.*proof(?![\s\S]{0,100}verify_root|[\s\S]{0,100}concurrent_merkle)/i,
    description: 'Compressed NFT proofs must be verified against current merkle root.',
    recommendation: 'Always verify proof against on-chain merkle root. Handle concurrent modifications.'
  },
  
  // Validator Concentration Risks
  {
    id: 'SOL4881',
    name: 'Validator Stake Concentration',
    severity: 'high',
    pattern: /validator.*stake|stake.*concentration(?![\s\S]{0,100}decentralization|[\s\S]{0,100}diverse)/i,
    description: 'High stake concentration in few validators = centralization risk. Affects security.',
    recommendation: 'Encourage stake distribution. Monitor Nakamoto coefficient for protocol health.'
  },
  {
    id: 'SOL4882',
    name: 'Geographic Validator Concentration',
    severity: 'medium',
    pattern: /validator.*location|geographic.*concentration(?![\s\S]{0,100}diverse|[\s\S]{0,100}distributed)/i,
    description: 'Validators concentrated in single jurisdiction = regulatory and infrastructure risk.',
    recommendation: 'Encourage geographic diversity. Avoid single-point-of-failure locations.'
  },
  
  // LUT (Lookup Table) Security
  {
    id: 'SOL4883',
    name: 'Address Lookup Table Spoofing',
    severity: 'high',
    pattern: /lookup.*table|address.*lut(?![\s\S]{0,100}verify_authority|[\s\S]{0,100}trusted_table)/i,
    description: 'Malicious lookup tables can redirect to attacker accounts. Verify LUT authority.',
    recommendation: 'Only use LUTs from trusted sources. Verify table authority before using.'
  },
  
  // DePIN Security
  {
    id: 'SOL4884',
    name: 'DePIN Node Verification Bypass',
    severity: 'high',
    pattern: /node.*verification|depin.*node(?![\s\S]{0,100}proof_of_work|[\s\S]{0,100}hardware_attestation)/i,
    description: 'DePIN protocols vulnerable to fake nodes (io.net Sybil). Need hardware attestation.',
    recommendation: 'Implement hardware attestation, proof-of-work challenges, or stake requirements.'
  },
  {
    id: 'SOL4885',
    name: 'DePIN Reward Manipulation',
    severity: 'high',
    pattern: /depin.*reward|compute.*reward(?![\s\S]{0,100}verify_work|[\s\S]{0,100}proof_of_compute)/i,
    description: 'DePIN rewards can be farmed with fake work. Verify actual computation/storage.',
    recommendation: 'Implement verifiable computation proofs. Random sampling of work quality.'
  },
  
  // Blink Actions Security
  {
    id: 'SOL4886',
    name: 'Blink Action URL Injection',
    severity: 'critical',
    pattern: /blink.*action|action.*url(?![\s\S]{0,100}sanitize|[\s\S]{0,100}whitelist)/i,
    description: 'Blink actions can embed malicious transactions. Verify action URLs.',
    recommendation: 'Whitelist allowed action domains. Show clear transaction preview before signing.'
  },
  {
    id: 'SOL4887',
    name: 'Social Media Blink Phishing',
    severity: 'high',
    pattern: /twitter.*blink|social.*action(?![\s\S]{0,100}verified_creator|[\s\S]{0,100}trusted_source)/i,
    description: 'Malicious blinks embedded in social media can steal funds.',
    recommendation: 'Only interact with blinks from verified creators. Check destination before signing.'
  },
  
  // Priority Fee Manipulation
  {
    id: 'SOL4888',
    name: 'Priority Fee Front-running',
    severity: 'medium',
    pattern: /priority.*fee|compute.*unit.*price(?![\s\S]{0,100}dynamic_fee|[\s\S]{0,100}private_mempool)/i,
    description: 'Priority fees visible in mempool enable front-running. Use private mempools.',
    recommendation: 'Use Jito or private transaction submission. Implement slippage protection.'
  },
  
  // Cross-Margin Liquidation
  {
    id: 'SOL4889',
    name: 'Cross-Margin Cascade Liquidation',
    severity: 'critical',
    pattern: /cross.*margin|portfolio.*margin(?![\s\S]{0,100}isolated_mode|[\s\S]{0,100}position_limit)/i,
    description: 'Cross-margin can cause cascade liquidations. One position loss affects all.',
    recommendation: 'Offer isolated margin mode. Implement position size limits per asset.'
  },
  
  // Restaking Security
  {
    id: 'SOL4890',
    name: 'Restaking Slashing Risk',
    severity: 'high',
    pattern: /restaking|restake|liquid.*staking(?![\s\S]{0,100}slashing_insurance|[\s\S]{0,100}risk_disclosure)/i,
    description: 'Restaking compounds slashing risk. One slash can affect multiple protocols.',
    recommendation: 'Disclose restaking risks. Implement slashing insurance or caps.'
  },
  
  // Intent-Based Architecture
  {
    id: 'SOL4891',
    name: 'Intent Solver Manipulation',
    severity: 'critical',
    pattern: /intent.*solver|solve.*intent(?![\s\S]{0,100}verify_execution|[\s\S]{0,100}user_signature)/i,
    description: 'Intent-based systems rely on solvers. Malicious solvers can exploit intents.',
    recommendation: 'Verify solver execution matches intent. Require user signature on final transaction.'
  },
  
  // Real-Time Oracle Security
  {
    id: 'SOL4892',
    name: 'Pyth Pull Oracle Stale Data',
    severity: 'high',
    pattern: /pyth.*price|pull.*oracle(?![\s\S]{0,100}publishTime|[\s\S]{0,100}staleness_check)/i,
    description: 'Pyth pull oracles can return stale data if not refreshed. Check publishTime.',
    recommendation: 'Always check Pyth publishTime. Reject prices older than acceptable threshold.'
  },
  {
    id: 'SOL4893',
    name: 'Switchboard On-Demand Latency',
    severity: 'medium',
    pattern: /switchboard.*oracle|on_demand.*oracle(?![\s\S]{0,100}latency_check|[\s\S]{0,100}freshness)/i,
    description: 'On-demand oracles have latency. High-frequency operations need fresher data.',
    recommendation: 'Use appropriate oracle for use case. Check data freshness for time-sensitive ops.'
  },
  
  // Session Key Security
  {
    id: 'SOL4894',
    name: 'Session Key Over-Permission',
    severity: 'high',
    pattern: /session.*key|session.*token(?![\s\S]{0,100}scope_limit|[\s\S]{0,100}expiry)/i,
    description: 'Session keys with too many permissions = security risk. Thunder Terminal exploit.',
    recommendation: 'Limit session key scope to minimum required. Add short expiry times.'
  },
  {
    id: 'SOL4895',
    name: 'Glow Wallet Session Key Abuse',
    severity: 'high',
    pattern: /glow.*session|wallet.*session(?![\s\S]{0,100}user_approval|[\s\S]{0,100}transaction_limit)/i,
    description: 'Session keys in wallets need transaction limits and user approval for sensitive ops.',
    recommendation: 'Require user confirmation for session key creation. Limit transaction value/count.'
  },
  
  // Governance Timing Attacks
  {
    id: 'SOL4896',
    name: 'Governance Proposal Flash Attack',
    severity: 'critical',
    pattern: /proposal.*vote|governance.*vote(?![\s\S]{0,100}lock_period|[\s\S]{0,100}voting_delay)/i,
    description: 'Flash loan to borrow governance tokens, vote, return. Audius pattern.',
    recommendation: 'Implement voting power snapshot at proposal creation. Add voting delay period.'
  },
  {
    id: 'SOL4897',
    name: 'Governance Quorum Manipulation',
    severity: 'critical',
    pattern: /quorum.*check|governance.*quorum(?![\s\S]{0,100}snapshot_block|[\s\S]{0,100}time_lock)/i,
    description: 'Quorum can be gamed by waiting for low participation. Add minimum thresholds.',
    recommendation: 'Use relative quorum (% of total supply). Implement minimum participation threshold.'
  },
  
  // Multisig Security
  {
    id: 'SOL4898',
    name: 'Squads Multisig Configuration',
    severity: 'high',
    pattern: /squads|multisig(?![\s\S]{0,100}threshold_check|[\s\S]{0,100}member_verify)/i,
    description: 'Multisig configurations must be verified. Low threshold = centralization risk.',
    recommendation: 'Set appropriate threshold (e.g., 3/5). Verify all signers are independent parties.'
  },
  {
    id: 'SOL4899',
    name: 'Multisig Member Key Compromise',
    severity: 'critical',
    pattern: /multisig.*member|signer.*key(?![\s\S]{0,100}hardware_wallet|[\s\S]{0,100}mpc)/i,
    description: 'Single multisig member key compromise reduces security. Raydium lost $4.4M this way.',
    recommendation: 'Require hardware wallets for multisig members. Implement MPC where possible.'
  },
  {
    id: 'SOL4900',
    name: 'Emergency Response Timelock Bypass',
    severity: 'critical',
    pattern: /emergency.*bypass|timelock.*override(?![\s\S]{0,100}guardian|[\s\S]{0,100}security_council)/i,
    description: 'Emergency bypasses of timelocks need strict governance. Audius-style attacks.',
    recommendation: 'Emergency actions require security council approval. Log and alert on all bypasses.'
  },
];

/**
 * Run Batch 88 patterns against input
 */
export function checkBatch88Patterns(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  const fileName = input.path || input.rust?.filePath || 'unknown';
  
  if (!content) return findings;
  
  const lines = content.split('\n');
  
  for (const pattern of BATCH_88_PATTERNS) {
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

export default BATCH_88_PATTERNS;
