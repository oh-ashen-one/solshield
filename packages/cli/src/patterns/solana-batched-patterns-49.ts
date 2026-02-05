/**
 * SolGuard Batched Patterns - Batch 49
 * Helius Exploit Database 2020-2023
 * SOL1721-SOL1790 (70 patterns)
 * 
 * Source: Helius "Solana Hacks, Bugs, and Exploits: A Complete History"
 * https://www.helius.dev/blog/solana-hacks
 */

import type { Finding, PatternInput } from './index.js';

interface BatchedPattern {
  id: string;
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  pattern: RegExp;
  description: string;
  recommendation: string;
}

const BATCH_49_PATTERNS: BatchedPattern[] = [
  // Solend Auth Bypass (Aug 2021) - $2M at risk
  {
    id: 'SOL1721',
    name: 'UpdateReserveConfig Auth Bypass',
    severity: 'critical',
    pattern: /update.*reserve.*config|UpdateReserveConfig(?![\s\S]{0,100}admin_check|[\s\S]{0,100}authority_check)/i,
    description: 'Reserve config update without proper admin validation. Solend lost $2M at risk from this.',
    recommendation: 'Verify admin/authority owns the lending market, not just any account.'
  },
  {
    id: 'SOL1722',
    name: 'Lending Market Ownership Spoof',
    severity: 'critical',
    pattern: /lending_market|LendingMarket(?![\s\S]{0,100}owner\s*==|[\s\S]{0,100}has_one)/i,
    description: 'Lending market account can be spoofed with attacker-owned market.',
    recommendation: 'Verify lending market is the expected canonical market address.'
  },
  {
    id: 'SOL1723',
    name: 'Liquidation Threshold Manipulation',
    severity: 'critical',
    pattern: /liquidation_threshold|liquidation_bonus(?![\s\S]{0,100}bounds|[\s\S]{0,100}max_|[\s\S]{0,100}min_)/i,
    description: 'Liquidation parameters can be manipulated without bounds checking.',
    recommendation: 'Enforce minimum/maximum bounds on liquidation parameters.'
  },
  {
    id: 'SOL1724',
    name: 'Circuit Breaker Missing',
    severity: 'high',
    pattern: /liquidat|withdraw|borrow(?![\s\S]{0,200}circuit_breaker|[\s\S]{0,200}rate_limit|[\s\S]{0,200}pause)/i,
    description: 'Critical operations lack circuit breaker protection.',
    recommendation: 'Implement circuit breakers and rate limits for critical operations.'
  },
  
  // Wormhole Bridge Exploit (Feb 2022) - $326M
  {
    id: 'SOL1725',
    name: 'Wormhole Guardian Signature Forge',
    severity: 'critical',
    pattern: /guardian.*signature|verify_signature.*guardian(?![\s\S]{0,100}secp256k1_recover|[\s\S]{0,100}ed25519)/i,
    description: 'Guardian signature verification can be bypassed. Wormhole lost $326M from this.',
    recommendation: 'Use cryptographic signature verification, not just account presence.'
  },
  {
    id: 'SOL1726',
    name: 'SignatureSet Account Spoofing',
    severity: 'critical',
    pattern: /SignatureSet|signature_set(?![\s\S]{0,100}verify_owner|[\s\S]{0,100}check_program)/i,
    description: 'SignatureSet account can be spoofed without owner verification.',
    recommendation: 'Verify SignatureSet account is owned by the bridge program.'
  },
  {
    id: 'SOL1727',
    name: 'Cross-Chain Mint Without Collateral',
    severity: 'critical',
    pattern: /mint.*wrapped|bridge.*mint(?![\s\S]{0,200}collateral|[\s\S]{0,200}deposit)/i,
    description: 'Wrapped tokens can be minted without verifying collateral deposit.',
    recommendation: 'Verify collateral deposit on source chain before minting wrapped tokens.'
  },
  {
    id: 'SOL1728',
    name: 'VAA Verification Bypass',
    severity: 'critical',
    pattern: /VAA|verify_vaa|parse_vaa(?![\s\S]{0,100}verify|[\s\S]{0,100}validate)/i,
    description: 'VAA (Verified Action Approval) can be forged without proper verification.',
    recommendation: 'Always verify VAA signatures against guardian set.'
  },
  
  // Cashio Exploit (Mar 2022) - $52.8M
  {
    id: 'SOL1729',
    name: 'Cashio Infinite Mint Glitch',
    severity: 'critical',
    pattern: /mint.*cash|CASH.*mint(?![\s\S]{0,100}collateral_check|[\s\S]{0,100}verify_backing)/i,
    description: 'Stablecoin minting without collateral validation. Cashio lost $52.8M.',
    recommendation: 'Verify all collateral accounts are valid and properly backed.'
  },
  {
    id: 'SOL1730',
    name: 'Saber LP Token Validation Missing',
    severity: 'critical',
    pattern: /saber_swap|arrow.*account|LP.*token(?![\s\S]{0,100}verify_mint|[\s\S]{0,100}whitelist)/i,
    description: 'Saber LP token validation can be bypassed with fake tokens.',
    recommendation: 'Verify LP token mint matches expected whitelisted mints.'
  },
  {
    id: 'SOL1731',
    name: 'Collateral Root of Trust Missing',
    severity: 'critical',
    pattern: /collateral|backing(?![\s\S]{0,100}root_of_trust|[\s\S]{0,100}canonical)/i,
    description: 'Collateral validation lacks root of trust verification.',
    recommendation: 'Establish and verify a root of trust for all collateral accounts.'
  },
  {
    id: 'SOL1732',
    name: 'Fake Account Chain Attack',
    severity: 'critical',
    pattern: /account.*chain|nested.*account(?![\s\S]{0,100}verify_all|[\s\S]{0,100}trace_back)/i,
    description: 'Attacker can create chain of fake accounts to bypass validation.',
    recommendation: 'Trace back the entire account chain to a root of trust.'
  },
  
  // Crema Finance Exploit (Jul 2022) - $8.8M
  {
    id: 'SOL1733',
    name: 'Crema Fake Tick Account',
    severity: 'critical',
    pattern: /tick.*account|TickAccount(?![\s\S]{0,100}owner_check|[\s\S]{0,100}verify_program)/i,
    description: 'Tick account can be forged. Crema Finance lost $8.8M.',
    recommendation: 'Verify tick account is owned by the CLMM program.'
  },
  {
    id: 'SOL1734',
    name: 'CLMM Fee Data Manipulation',
    severity: 'critical',
    pattern: /transaction_fee|fee_data|clmm.*fee(?![\s\S]{0,100}verify|[\s\S]{0,100}validate)/i,
    description: 'CLMM fee data can be manipulated with fake tick accounts.',
    recommendation: 'Verify fee data comes from verified tick accounts.'
  },
  {
    id: 'SOL1735',
    name: 'Flash Loan Fee Claim Exploit',
    severity: 'critical',
    pattern: /flash_loan[\s\S]{0,100}claim.*fee|fee.*claim[\s\S]{0,100}flash/i,
    description: 'Flash loans can be used to claim excessive fees.',
    recommendation: 'Add flash loan protection to fee claim functions.'
  },
  {
    id: 'SOL1736',
    name: 'Pool Drain via Multiple Pools',
    severity: 'critical',
    pattern: /multiple.*pool|pool.*drain(?![\s\S]{0,100}limit|[\s\S]{0,100}isolation)/i,
    description: 'Multiple pools can be drained in single transaction.',
    recommendation: 'Implement per-pool isolation and transaction limits.'
  },
  
  // Audius Governance Exploit (Jul 2022) - $6.1M
  {
    id: 'SOL1737',
    name: 'Audius Malicious Proposal',
    severity: 'critical',
    pattern: /governance.*proposal|submit.*proposal(?![\s\S]{0,100}timelock|[\s\S]{0,100}delay)/i,
    description: 'Malicious proposals can be submitted and executed. Audius lost $6.1M.',
    recommendation: 'Add timelock delays to all governance proposals.'
  },
  {
    id: 'SOL1738',
    name: 'Treasury Permission Reconfiguration',
    severity: 'critical',
    pattern: /treasury.*permission|reconfigure.*treasury(?![\s\S]{0,100}multisig|[\s\S]{0,100}timelock)/i,
    description: 'Treasury permissions can be changed via malicious proposal.',
    recommendation: 'Require multisig + timelock for treasury permission changes.'
  },
  {
    id: 'SOL1739',
    name: 'Governance Proposal Validation Bypass',
    severity: 'critical',
    pattern: /proposal.*validation|validate.*proposal(?![\s\S]{0,100}quorum|[\s\S]{0,100}threshold)/i,
    description: 'Proposal validation can be bypassed.',
    recommendation: 'Enforce strict validation including quorum and voting thresholds.'
  },
  {
    id: 'SOL1740',
    name: 'Token Transfer via Governance',
    severity: 'critical',
    pattern: /governance[\s\S]{0,100}transfer|transfer[\s\S]{0,100}governance(?![\s\S]{0,100}limit|[\s\S]{0,100}cap)/i,
    description: 'Governance can be exploited to transfer treasury tokens.',
    recommendation: 'Add transfer limits and caps to governance actions.'
  },
  
  // Nirvana Finance Exploit (Jul 2022) - $3.5M
  {
    id: 'SOL1741',
    name: 'Nirvana Bonding Curve Flash Loan',
    severity: 'critical',
    pattern: /bonding_curve[\s\S]{0,100}flash|flash[\s\S]{0,100}bonding(?![\s\S]{0,100}protection)/i,
    description: 'Bonding curve vulnerable to flash loan attack. Nirvana lost $3.5M.',
    recommendation: 'Add flash loan protection to bonding curve operations.'
  },
  {
    id: 'SOL1742',
    name: 'ANA Token Mint Rate Manipulation',
    severity: 'critical',
    pattern: /mint_rate|token.*rate(?![\s\S]{0,100}cap|[\s\S]{0,100}limit|[\s\S]{0,100}max)/i,
    description: 'Token mint rate can be manipulated via price manipulation.',
    recommendation: 'Cap mint rate and use TWAP for pricing.'
  },
  {
    id: 'SOL1743',
    name: 'Rising Floor Price Bypass',
    severity: 'high',
    pattern: /floor_price|rising_floor(?![\s\S]{0,100}verify|[\s\S]{0,100}enforce)/i,
    description: 'Floor price mechanism can be bypassed.',
    recommendation: 'Enforce floor price with protocol-owned liquidity.'
  },
  {
    id: 'SOL1744',
    name: 'Protocol Owned Liquidity Drain',
    severity: 'critical',
    pattern: /protocol_owned_liquidity|POL(?![\s\S]{0,100}lock|[\s\S]{0,100}timelock)/i,
    description: 'Protocol-owned liquidity can be drained.',
    recommendation: 'Lock POL with timelocks and withdrawal limits.'
  },
  
  // Slope Wallet Hack (Aug 2022) - $8M
  {
    id: 'SOL1745',
    name: 'Slope Private Key Logging',
    severity: 'critical',
    pattern: /private_key.*log|log.*private_key|mnemonic.*send/i,
    description: 'Private keys being logged or transmitted. Slope lost $8M from key leak.',
    recommendation: 'NEVER log or transmit private keys/mnemonics.'
  },
  {
    id: 'SOL1746',
    name: 'Seed Phrase Telemetry',
    severity: 'critical',
    pattern: /seed_phrase.*telemetry|analytics.*seed|track.*mnemonic/i,
    description: 'Seed phrases being sent to analytics/telemetry.',
    recommendation: 'Remove all telemetry from key material handling.'
  },
  {
    id: 'SOL1747',
    name: 'Unencrypted Key Storage',
    severity: 'critical',
    pattern: /store.*private_key|save.*seed(?![\s\S]{0,50}encrypt|[\s\S]{0,50}cipher)/i,
    description: 'Keys stored without encryption.',
    recommendation: 'Always encrypt keys before storage.'
  },
  {
    id: 'SOL1748',
    name: 'Third-Party Key Access',
    severity: 'critical',
    pattern: /third_party[\s\S]{0,50}key|external.*private_key/i,
    description: 'Third-party services have access to key material.',
    recommendation: 'Keys must never leave the secure enclave.'
  },
  
  // Mango Markets Exploit (Oct 2022) - $116M
  {
    id: 'SOL1749',
    name: 'Mango Oracle Price Manipulation',
    severity: 'critical',
    pattern: /perp.*price|perpetual.*oracle(?![\s\S]{0,100}twap|[\s\S]{0,100}window)/i,
    description: 'Perpetual oracle price can be manipulated. Mango lost $116M.',
    recommendation: 'Use TWAP with multiple oracle sources for perp pricing.'
  },
  {
    id: 'SOL1750',
    name: 'Collateral Value Inflation',
    severity: 'critical',
    pattern: /collateral.*value|mark_to_market(?![\s\S]{0,100}cap|[\s\S]{0,100}limit)/i,
    description: 'Collateral value can be artificially inflated.',
    recommendation: 'Cap collateral value increase per time window.'
  },
  {
    id: 'SOL1751',
    name: 'Cross-Margin Account Exploitation',
    severity: 'critical',
    pattern: /cross_margin|margin.*account(?![\s\S]{0,100}isolation|[\s\S]{0,100}limit)/i,
    description: 'Cross-margin accounts can amplify attack impact.',
    recommendation: 'Implement position limits and margin isolation.'
  },
  {
    id: 'SOL1752',
    name: 'Self-Trading for Price Manipulation',
    severity: 'critical',
    pattern: /self_trade|wash_trade(?![\s\S]{0,100}detect|[\s\S]{0,100}prevent)/i,
    description: 'Self-trading can manipulate oracle prices.',
    recommendation: 'Detect and prevent wash trading patterns.'
  },
  
  // Raydium Exploit (Dec 2022) - $4.4M
  {
    id: 'SOL1753',
    name: 'Raydium Admin Key Compromise',
    severity: 'critical',
    pattern: /admin_key|pool_authority(?![\s\S]{0,100}multisig|[\s\S]{0,100}hardware)/i,
    description: 'Admin key was compromised. Raydium lost $4.4M.',
    recommendation: 'Use hardware wallet multisig for admin keys.'
  },
  {
    id: 'SOL1754',
    name: 'Pool Withdraw Function Abuse',
    severity: 'critical',
    pattern: /admin.*withdraw|withdraw.*admin(?![\s\S]{0,100}timelock|[\s\S]{0,100}limit)/i,
    description: 'Admin can withdraw all pool funds without limits.',
    recommendation: 'Add timelocks and limits to admin withdrawals.'
  },
  {
    id: 'SOL1755',
    name: 'Trojan Horse Update',
    severity: 'critical',
    pattern: /upgrade.*program|update.*contract(?![\s\S]{0,100}timelock|[\s\S]{0,100}verify)/i,
    description: 'Malicious program upgrade deployed via compromised key.',
    recommendation: 'Add timelock and community verification for upgrades.'
  },
  {
    id: 'SOL1756',
    name: 'Fee Account Drain',
    severity: 'high',
    pattern: /fee_account|accumulated_fees(?![\s\S]{0,100}multisig|[\s\S]{0,100}timelock)/i,
    description: 'Fee accounts can be drained by admin.',
    recommendation: 'Require multisig for fee account access.'
  },
  
  // Cypher Protocol Exploit (Aug 2023) - $1M + $317K
  {
    id: 'SOL1757',
    name: 'Cypher Sub-Account Isolation Failure',
    severity: 'critical',
    pattern: /sub_account|subaccount(?![\s\S]{0,100}isolation|[\s\S]{0,100}verify_owner)/i,
    description: 'Sub-account isolation failed. Cypher lost $1M+.',
    recommendation: 'Enforce strict sub-account isolation and owner verification.'
  },
  {
    id: 'SOL1758',
    name: 'Insider Theft via Redeemer',
    severity: 'critical',
    pattern: /redeem.*fund|redeemer.*access(?![\s\S]{0,100}multisig|[\s\S]{0,100}audit)/i,
    description: 'Insider (Hoak) stole funds via redemption access.',
    recommendation: 'Require multisig and audit trails for fund access.'
  },
  {
    id: 'SOL1759',
    name: 'Team Member Key Access',
    severity: 'high',
    pattern: /team.*key|employee.*access(?![\s\S]{0,100}rotation|[\s\S]{0,100}revoke)/i,
    description: 'Team members retain key access after leaving.',
    recommendation: 'Implement key rotation when team members change.'
  },
  {
    id: 'SOL1760',
    name: 'Partial Reimbursement Risk',
    severity: 'medium',
    pattern: /reimburs|compensat(?![\s\S]{0,100}insurance|[\s\S]{0,100}fund)/i,
    description: 'Protocol lacks insurance fund for full user reimbursement.',
    recommendation: 'Maintain insurance fund for potential exploits.'
  },
  
  // Network and Core Protocol Patterns
  {
    id: 'SOL1761',
    name: 'Grape Protocol DoS',
    severity: 'high',
    pattern: /flood.*transaction|spam.*network(?![\s\S]{0,100}rate_limit|[\s\S]{0,100}filter)/i,
    description: 'Network can be DoSed via transaction flooding. Grape caused 17-hour outage.',
    recommendation: 'Implement rate limiting and transaction filtering.'
  },
  {
    id: 'SOL1762',
    name: 'Candy Machine Bot Exploit',
    severity: 'high',
    pattern: /candy_machine|nft.*mint(?![\s\S]{0,100}bot_protection|[\s\S]{0,100}captcha)/i,
    description: 'NFT minting vulnerable to bot attacks causing network congestion.',
    recommendation: 'Add bot protection and rate limiting to minting.'
  },
  {
    id: 'SOL1763',
    name: 'Turbine Block Propagation Bug',
    severity: 'critical',
    pattern: /turbine|block.*propagat(?![\s\S]{0,100}verify|[\s\S]{0,100}validate)/i,
    description: 'Turbine block propagation can fail causing network halt.',
    recommendation: 'Implement robust block validation and propagation checks.'
  },
  {
    id: 'SOL1764',
    name: 'Durable Nonce Vulnerability',
    severity: 'high',
    pattern: /durable_nonce|advance_nonce(?![\s\S]{0,100}verify|[\s\S]{0,100}validate)/i,
    description: 'Durable nonce can be exploited for replay attacks.',
    recommendation: 'Always verify nonce state before transaction execution.'
  },
  {
    id: 'SOL1765',
    name: 'Duplicate Block Production',
    severity: 'critical',
    pattern: /duplicate.*block|block.*duplicate(?![\s\S]{0,100}detect|[\s\S]{0,100}reject)/i,
    description: 'Duplicate blocks can cause consensus issues.',
    recommendation: 'Implement duplicate block detection and rejection.'
  },
  {
    id: 'SOL1766',
    name: 'JIT Cache Exploitation',
    severity: 'critical',
    pattern: /jit.*cache|cache.*exploit(?![\s\S]{0,100}validate|[\s\S]{0,100}verify)/i,
    description: 'JIT cache can be exploited causing network halt.',
    recommendation: 'Implement JIT cache validation and bounds checking.'
  },
  {
    id: 'SOL1767',
    name: 'ELF Address Alignment',
    severity: 'critical',
    pattern: /elf.*address|address.*alignment(?![\s\S]{0,100}check|[\s\S]{0,100}validate)/i,
    description: 'ELF address alignment issues can crash validators.',
    recommendation: 'Validate ELF address alignment before execution.'
  },
  
  // Supply Chain Attacks
  {
    id: 'SOL1768',
    name: 'Parcl Front-End Compromise',
    severity: 'critical',
    pattern: /frontend.*inject|inject.*frontend(?![\s\S]{0,100}csp|[\s\S]{0,100}integrity)/i,
    description: 'Front-end can be compromised to steal user funds.',
    recommendation: 'Implement CSP and subresource integrity checks.'
  },
  {
    id: 'SOL1769',
    name: 'Web3.js Supply Chain',
    severity: 'critical',
    pattern: /web3\.js|@solana\/web3(?![\s\S]{0,100}verify|[\s\S]{0,100}audit)/i,
    description: 'Web3.js package was compromised in supply chain attack.',
    recommendation: 'Pin dependency versions and verify package integrity.'
  },
  {
    id: 'SOL1770',
    name: 'NPM Package Backdoor',
    severity: 'critical',
    pattern: /npm.*install|package.*json(?![\s\S]{0,100}audit|[\s\S]{0,100}lockfile)/i,
    description: 'NPM packages can contain backdoors stealing keys.',
    recommendation: 'Use lockfiles, audit dependencies, verify publishers.'
  },
  
  // Additional Exploit Patterns 2022-2023
  {
    id: 'SOL1771',
    name: 'OptiFi Accidental Closure',
    severity: 'critical',
    pattern: /close.*program|program.*close(?![\s\S]{0,100}confirm|[\s\S]{0,100}backup)/i,
    description: 'Program accidentally closed, locking $661K. OptiFi incident.',
    recommendation: 'Add confirmation and backup before program closure.'
  },
  {
    id: 'SOL1772',
    name: 'UXD Protocol Bug',
    severity: 'high',
    pattern: /rebalance|delta.*neutral(?![\s\S]{0,100}verify|[\s\S]{0,100}check)/i,
    description: 'Delta-neutral rebalancing can fail.',
    recommendation: 'Verify rebalancing calculations before execution.'
  },
  {
    id: 'SOL1773',
    name: 'Tulip Protocol Vulnerability',
    severity: 'high',
    pattern: /vault.*strategy|strategy.*vault(?![\s\S]{0,100}audit|[\s\S]{0,100}verify)/i,
    description: 'Vault strategy can be exploited.',
    recommendation: 'Audit and verify all vault strategies.'
  },
  {
    id: 'SOL1774',
    name: 'SVT Token Honeypot',
    severity: 'critical',
    pattern: /sell.*restrict|transfer.*lock(?![\s\S]{0,100}transparent|[\s\S]{0,100}document)/i,
    description: 'Token has hidden sell restrictions (honeypot). SVT incident.',
    recommendation: 'Verify transfer restrictions are transparent.'
  },
  {
    id: 'SOL1775',
    name: 'io.net Sybil Attack',
    severity: 'high',
    pattern: /sybil|fake.*node|node.*spoof(?![\s\S]{0,100}verify|[\s\S]{0,100}detect)/i,
    description: 'Network vulnerable to Sybil attacks with fake nodes.',
    recommendation: 'Implement node verification and Sybil detection.'
  },
  {
    id: 'SOL1776',
    name: 'Synthetify DAO Governance',
    severity: 'critical',
    pattern: /dao.*governance|governance.*dao(?![\s\S]{0,100}timelock|[\s\S]{0,100}delay)/i,
    description: 'DAO governance can be exploited without timelocks.',
    recommendation: 'Add timelocks to all DAO governance actions.'
  },
  {
    id: 'SOL1777',
    name: 'Aurory Game Exploit',
    severity: 'high',
    pattern: /game.*economy|game.*token(?![\s\S]{0,100}rate_limit|[\s\S]{0,100}cap)/i,
    description: 'Game economy can be exploited for tokens.',
    recommendation: 'Rate limit and cap game economy rewards.'
  },
  {
    id: 'SOL1778',
    name: 'Thunder Terminal MongoDB',
    severity: 'critical',
    pattern: /mongodb|database.*expose(?![\s\S]{0,100}encrypt|[\s\S]{0,100}secure)/i,
    description: 'Database exposed leading to key theft. Thunder lost $240K.',
    recommendation: 'Encrypt databases and secure credentials.'
  },
  {
    id: 'SOL1779',
    name: 'Saga DAO Attack',
    severity: 'high',
    pattern: /saga.*dao|dao.*attack(?![\s\S]{0,100}protect|[\s\S]{0,100}verify)/i,
    description: 'DAO vulnerable to governance attacks.',
    recommendation: 'Implement comprehensive governance protections.'
  },
  {
    id: 'SOL1780',
    name: 'Solareum Bot Exploit',
    severity: 'critical',
    pattern: /trading.*bot|bot.*exploit(?![\s\S]{0,100}verify|[\s\S]{0,100}secure)/i,
    description: 'Trading bot was exploited. Solareum collapsed.',
    recommendation: 'Secure trading bot infrastructure.'
  },
  
  // Additional Security Patterns
  {
    id: 'SOL1781',
    name: 'Phantom Wallet DDoS',
    severity: 'high',
    pattern: /phantom|wallet.*ddos(?![\s\S]{0,100}protect|[\s\S]{0,100}rate_limit)/i,
    description: 'Wallet can be DDoSed affecting users.',
    recommendation: 'Implement DDoS protection for wallet services.'
  },
  {
    id: 'SOL1782',
    name: 'Jito DDoS Attack',
    severity: 'high',
    pattern: /jito|mev.*ddos(?![\s\S]{0,100}protect|[\s\S]{0,100}filter)/i,
    description: 'MEV infrastructure vulnerable to DDoS.',
    recommendation: 'Protect MEV infrastructure from DDoS.'
  },
  {
    id: 'SOL1783',
    name: 'Solend Oracle Delay',
    severity: 'high',
    pattern: /solend.*oracle|lending.*oracle(?![\s\S]{0,100}staleness|[\s\S]{0,100}fresh)/i,
    description: 'Lending oracle data can be stale.',
    recommendation: 'Check oracle staleness before using prices.'
  },
  {
    id: 'SOL1784',
    name: 'Validator Set Manipulation',
    severity: 'critical',
    pattern: /validator.*set|stake.*weight(?![\s\S]{0,100}verify|[\s\S]{0,100}threshold)/i,
    description: 'Validator set can be manipulated.',
    recommendation: 'Verify validator set integrity.'
  },
  {
    id: 'SOL1785',
    name: 'Consensus Halt Risk',
    severity: 'critical',
    pattern: /consensus.*halt|network.*stop(?![\s\S]{0,100}recover|[\s\S]{0,100}failsafe)/i,
    description: 'Network can halt due to consensus issues.',
    recommendation: 'Implement consensus recovery mechanisms.'
  },
  {
    id: 'SOL1786',
    name: 'Transaction Replay',
    severity: 'critical',
    pattern: /replay.*transaction|transaction.*replay(?![\s\S]{0,100}prevent|[\s\S]{0,100}nonce)/i,
    description: 'Transactions can be replayed.',
    recommendation: 'Use nonces and blockhash to prevent replay.'
  },
  {
    id: 'SOL1787',
    name: 'Account Data Corruption',
    severity: 'critical',
    pattern: /data.*corrupt|corrupt.*account(?![\s\S]{0,100}validate|[\s\S]{0,100}checksum)/i,
    description: 'Account data can be corrupted.',
    recommendation: 'Validate account data integrity.'
  },
  {
    id: 'SOL1788',
    name: 'Rent Collection Attack',
    severity: 'medium',
    pattern: /rent.*collect|collect.*rent(?![\s\S]{0,100}verify|[\s\S]{0,100}check)/i,
    description: 'Rent collection can be exploited.',
    recommendation: 'Verify rent collection legitimacy.'
  },
  {
    id: 'SOL1789',
    name: 'Account Resurrection',
    severity: 'high',
    pattern: /resurrect.*account|account.*resurrect(?![\s\S]{0,100}prevent|[\s\S]{0,100}check)/i,
    description: 'Closed accounts can be resurrected.',
    recommendation: 'Prevent account resurrection after closure.'
  },
  {
    id: 'SOL1790',
    name: 'Clock Drift Exploitation',
    severity: 'medium',
    pattern: /clock.*drift|timestamp.*manipulat(?![\s\S]{0,100}bounds|[\s\S]{0,100}verify)/i,
    description: 'Clock drift can affect time-sensitive operations.',
    recommendation: 'Use bounded timestamp validation.'
  },
];

export function checkBatch49Patterns(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  
  if (!content) return findings;
  
  const lines = content.split('\n');
  
  for (const pattern of BATCH_49_PATTERNS) {
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
          location: { file: input.path, line: lineNum },
          recommendation: pattern.recommendation,
          code: snippet.substring(0, 200),
        });
      }
    } catch (error) {
      // Skip on regex error
    }
  }
  
  return findings;
}

export { BATCH_49_PATTERNS };
