/**
 * SolShield Batched Patterns - Batch 50
 * Helius Exploit Database 2024-2025 + Advanced Patterns
 * SOL1791-SOL1860 (70 patterns)
 * 
 * Source: Helius "Solana Hacks, Bugs, and Exploits: A Complete History"
 * https://www.helius.dev/blog/solana-hacks
 * Sec3 2025 Solana Security Ecosystem Review
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

const BATCH_50_PATTERNS: BatchedPattern[] = [
  // Pump.fun Exploit (May 2024) - $1.9M
  {
    id: 'SOL1791',
    name: 'Pump.fun Employee Insider Attack',
    severity: 'critical',
    pattern: /employee.*access|insider.*key(?![\s\S]{0,100}audit|[\s\S]{0,100}log)/i,
    description: 'Employee with privileged access stole funds. Pump.fun lost $1.9M.',
    recommendation: 'Implement access logging, rotation, and separation of duties.'
  },
  {
    id: 'SOL1792',
    name: 'Flash Loan Bonding Curve Attack',
    severity: 'critical',
    pattern: /bonding[\s\S]{0,50}flash|flash[\s\S]{0,50}bonding(?![\s\S]{0,100}block|[\s\S]{0,100}prevent)/i,
    description: 'Bonding curve manipulated via flash loan from Raydium.',
    recommendation: 'Block flash loan interactions with bonding curves.'
  },
  {
    id: 'SOL1793',
    name: 'Privileged Wallet Compromise',
    severity: 'critical',
    pattern: /privileged.*wallet|admin.*wallet(?![\s\S]{0,100}hardware|[\s\S]{0,100}multisig)/i,
    description: 'Privileged wallet was compromised by insider.',
    recommendation: 'Use hardware wallets and multisig for privileged accounts.'
  },
  {
    id: 'SOL1794',
    name: 'Launch Token Drain',
    severity: 'critical',
    pattern: /launch.*token|token.*launch(?![\s\S]{0,100}lock|[\s\S]{0,100}vesting)/i,
    description: 'Newly launched tokens drained before lock period.',
    recommendation: 'Implement token locks and vesting schedules.'
  },
  
  // Banana Gun Exploit (Sep 2024) - $1.4M
  {
    id: 'SOL1795',
    name: 'Banana Gun Bot Oracle Attack',
    severity: 'critical',
    pattern: /trading.*bot[\s\S]{0,50}oracle|bot.*price(?![\s\S]{0,100}verify|[\s\S]{0,100}twap)/i,
    description: 'Trading bot oracle exploited. Banana Gun lost $1.4M.',
    recommendation: 'Use TWAP and multiple oracles for bot trading.'
  },
  {
    id: 'SOL1796',
    name: 'Backend Key Exposure',
    severity: 'critical',
    pattern: /backend.*key|server.*private(?![\s\S]{0,100}hsm|[\s\S]{0,100}encrypt)/i,
    description: 'Backend keys exposed enabling fund theft.',
    recommendation: 'Use HSM and encrypt all backend keys.'
  },
  {
    id: 'SOL1797',
    name: 'Telegram Bot Vulnerability',
    severity: 'high',
    pattern: /telegram.*bot|bot.*telegram(?![\s\S]{0,100}verify|[\s\S]{0,100}auth)/i,
    description: 'Telegram trading bot vulnerable to attacks.',
    recommendation: 'Implement strong auth for trading bots.'
  },
  {
    id: 'SOL1798',
    name: 'User Refund Mechanism',
    severity: 'medium',
    pattern: /refund.*user|user.*refund(?![\s\S]{0,100}verify|[\s\S]{0,100}audit)/i,
    description: 'Refund mechanism should be audited for completeness.',
    recommendation: 'Verify and audit all refund mechanisms.'
  },
  
  // DEXX Exploit (Nov 2024) - $30M
  {
    id: 'SOL1799',
    name: 'DEXX Hot Wallet Exposure',
    severity: 'critical',
    pattern: /hot_wallet.*expose|expose.*hot_wallet(?![\s\S]{0,100}limit|[\s\S]{0,100}threshold)/i,
    description: 'Hot wallet private keys were exposed. DEXX lost $30M.',
    recommendation: 'Limit hot wallet holdings, use threshold signatures.'
  },
  {
    id: 'SOL1800',
    name: 'Centralized Custody Failure',
    severity: 'critical',
    pattern: /centralized.*custody|custody.*central(?![\s\S]{0,100}audit|[\s\S]{0,100}insurance)/i,
    description: 'Centralized custody led to massive loss.',
    recommendation: 'Use decentralized custody or insured custodians.'
  },
  {
    id: 'SOL1801',
    name: 'Commingled User Funds',
    severity: 'critical',
    pattern: /commingle|pool.*user.*fund(?![\s\S]{0,100}segregat|[\s\S]{0,100}separate)/i,
    description: 'User funds commingled in single wallet.',
    recommendation: 'Segregate user funds into individual accounts.'
  },
  {
    id: 'SOL1802',
    name: 'Export Private Key Feature',
    severity: 'critical',
    pattern: /export.*private|private.*export(?![\s\S]{0,100}encrypt|[\s\S]{0,100}secure)/i,
    description: 'Private key export feature was exploited.',
    recommendation: 'Disable or heavily secure key export functionality.'
  },
  
  // NoOnes Platform Exploit (Dec 2024) - $4M
  {
    id: 'SOL1803',
    name: 'NoOnes P2P Platform Attack',
    severity: 'critical',
    pattern: /p2p.*platform|platform.*p2p(?![\s\S]{0,100}verify|[\s\S]{0,100}escrow)/i,
    description: 'P2P platform vulnerable to attacks. NoOnes lost $4M.',
    recommendation: 'Use verified escrow and dispute resolution.'
  },
  {
    id: 'SOL1804',
    name: 'ZachXBT Detection Pattern',
    severity: 'high',
    pattern: /suspicious.*transfer|large.*withdrawal(?![\s\S]{0,100}alert|[\s\S]{0,100}notify)/i,
    description: 'Large suspicious transfers should trigger alerts.',
    recommendation: 'Implement real-time suspicious activity alerts.'
  },
  {
    id: 'SOL1805',
    name: 'Platform Fund Drain',
    severity: 'critical',
    pattern: /platform.*drain|drain.*platform(?![\s\S]{0,100}limit|[\s\S]{0,100}rate)/i,
    description: 'Platform funds can be drained rapidly.',
    recommendation: 'Implement withdrawal rate limits.'
  },
  
  // Loopscale/RateX Exploit (Apr 2025) - $5.8M
  {
    id: 'SOL1806',
    name: 'Loopscale RateX Undercollateralization',
    severity: 'critical',
    pattern: /undercollateral|collateral.*ratio(?![\s\S]{0,100}verify|[\s\S]{0,100}enforce)/i,
    description: 'Loans became undercollateralized. Loopscale lost $5.8M (recovered).',
    recommendation: 'Continuously verify collateralization ratios.'
  },
  {
    id: 'SOL1807',
    name: 'Pricing Function Flaw',
    severity: 'critical',
    pattern: /pricing.*function|calculate.*price(?![\s\S]{0,100}audit|[\s\S]{0,100}verify)/i,
    description: 'Pricing function had exploitable flaw.',
    recommendation: 'Audit and formally verify pricing functions.'
  },
  {
    id: 'SOL1808',
    name: 'Vault Quota Manipulation',
    severity: 'critical',
    pattern: /vault.*quota|quota.*vault(?![\s\S]{0,100}limit|[\s\S]{0,100}enforce)/i,
    description: 'Vault quotas can be manipulated.',
    recommendation: 'Enforce strict quota limits.'
  },
  {
    id: 'SOL1809',
    name: 'White Hat Recovery',
    severity: 'info',
    pattern: /white_hat|recovery.*fund(?![\s\S]{0,100}verify|[\s\S]{0,100}audit)/i,
    description: 'White hat recovery pattern - funds returned.',
    recommendation: 'Maintain white hat bounty program.'
  },
  
  // Advanced DeFi Patterns from Sec3 2025 Report
  {
    id: 'SOL1810',
    name: 'Business Logic Vulnerability (43%)',
    severity: 'critical',
    pattern: /logic.*flaw|business.*logic(?![\s\S]{0,100}test|[\s\S]{0,100}verify)/i,
    description: 'Business logic flaws are 43% of Solana vulnerabilities (Sec3 2025).',
    recommendation: 'Extensively test business logic with edge cases.'
  },
  {
    id: 'SOL1811',
    name: 'Input Validation (20%)',
    severity: 'high',
    pattern: /input.*valid|validate.*input(?![\s\S]{0,100}comprehensive|[\s\S]{0,100}all)/i,
    description: 'Input validation issues are 20% of vulnerabilities (Sec3 2025).',
    recommendation: 'Validate all inputs comprehensively.'
  },
  {
    id: 'SOL1812',
    name: 'Access Control (15%)',
    severity: 'critical',
    pattern: /access.*control|control.*access(?![\s\S]{0,100}verify|[\s\S]{0,100}check)/i,
    description: 'Access control issues are 15% of vulnerabilities (Sec3 2025).',
    recommendation: 'Implement comprehensive access control checks.'
  },
  {
    id: 'SOL1813',
    name: 'Data Integrity (12%)',
    severity: 'high',
    pattern: /data.*integrity|integrity.*check(?![\s\S]{0,100}verify|[\s\S]{0,100}hash)/i,
    description: 'Data integrity issues are 12% of vulnerabilities (Sec3 2025).',
    recommendation: 'Verify data integrity with hashes/signatures.'
  },
  {
    id: 'SOL1814',
    name: 'DoS/Liveness (10%)',
    severity: 'high',
    pattern: /dos|denial.*service|liveness(?![\s\S]{0,100}protect|[\s\S]{0,100}prevent)/i,
    description: 'DoS/liveness issues are 10% of vulnerabilities (Sec3 2025).',
    recommendation: 'Protect against denial of service attacks.'
  },
  
  // Certora Lulo Audit Patterns
  {
    id: 'SOL1815',
    name: 'Lulo Oracle Update Failure',
    severity: 'critical',
    pattern: /oracle.*update.*fail|fail.*oracle.*update(?![\s\S]{0,100}fallback|[\s\S]{0,100}retry)/i,
    description: 'Oracle update failures can cause issues (Certora Lulo audit).',
    recommendation: 'Implement fallback oracles and retry logic.'
  },
  {
    id: 'SOL1816',
    name: 'Referral Fee Exploit',
    severity: 'high',
    pattern: /referral.*fee|fee.*referral(?![\s\S]{0,100}cap|[\s\S]{0,100}limit)/i,
    description: 'Referral fees can be exploited (Certora Lulo audit).',
    recommendation: 'Cap and validate referral fee amounts.'
  },
  {
    id: 'SOL1817',
    name: 'Withdrawal Manipulation',
    severity: 'critical',
    pattern: /withdraw.*manipulat|manipulat.*withdraw(?![\s\S]{0,100}verify|[\s\S]{0,100}check)/i,
    description: 'Withdrawal amounts can be manipulated (Certora Lulo audit).',
    recommendation: 'Verify withdrawal calculations independently.'
  },
  {
    id: 'SOL1818',
    name: 'Interest Rate Manipulation',
    severity: 'high',
    pattern: /interest.*rate.*manipulat|rate.*manipulat(?![\s\S]{0,100}bounds|[\s\S]{0,100}cap)/i,
    description: 'Interest rates can be manipulated.',
    recommendation: 'Bound interest rates and prevent rapid changes.'
  },
  
  // Advanced Protocol Patterns
  {
    id: 'SOL1819',
    name: 'TVL Concentration Risk',
    severity: 'high',
    pattern: /tvl.*concentrat|concentrat.*risk(?![\s\S]{0,100}diversif|[\s\S]{0,100}limit)/i,
    description: 'High TVL concentration increases exploit impact.',
    recommendation: 'Diversify TVL across multiple pools/strategies.'
  },
  {
    id: 'SOL1820',
    name: 'Audit Coverage Gap',
    severity: 'medium',
    pattern: /audit.*coverage|coverage.*audit(?![\s\S]{0,100}complete|[\s\S]{0,100}full)/i,
    description: 'Code may have gaps in audit coverage.',
    recommendation: 'Ensure complete audit coverage of all code paths.'
  },
  {
    id: 'SOL1821',
    name: 'Response Time Vulnerability',
    severity: 'high',
    pattern: /response.*time|incident.*response(?![\s\S]{0,100}fast|[\s\S]{0,100}rapid)/i,
    description: 'Slow incident response increases losses.',
    recommendation: 'Implement rapid incident response procedures.'
  },
  {
    id: 'SOL1822',
    name: 'Insurance Fund Depletion',
    severity: 'critical',
    pattern: /insurance.*fund|fund.*insurance(?![\s\S]{0,100}adequate|[\s\S]{0,100}sufficient)/i,
    description: 'Insurance fund may be insufficient for major exploit.',
    recommendation: 'Maintain adequate insurance fund relative to TVL.'
  },
  
  // Validator and Staking Patterns
  {
    id: 'SOL1823',
    name: 'Validator Client Concentration',
    severity: 'high',
    pattern: /jito.*client|client.*concentrat(?![\s\S]{0,100}diversif|[\s\S]{0,100}multiple)/i,
    description: 'Jito client 88% dominance creates systemic risk (Helius).',
    recommendation: 'Diversify validator client implementations.'
  },
  {
    id: 'SOL1824',
    name: 'Hosting Provider Concentration',
    severity: 'high',
    pattern: /teraswitch|latitude.*hosting(?![\s\S]{0,100}diversif|[\s\S]{0,100}multiple)/i,
    description: 'Hosting concentration (43% stake) creates risk.',
    recommendation: 'Diversify validator hosting providers.'
  },
  {
    id: 'SOL1825',
    name: 'Stake Pool Vulnerability',
    severity: 'high',
    pattern: /stake_pool|pool.*stake(?![\s\S]{0,100}verify|[\s\S]{0,100}audit)/i,
    description: 'Stake pools have had multiple vulnerabilities.',
    recommendation: 'Audit stake pool implementations thoroughly.'
  },
  {
    id: 'SOL1826',
    name: 'Validator Commission Exploit',
    severity: 'medium',
    pattern: /commission.*change|validator.*commission(?![\s\S]{0,100}notify|[\s\S]{0,100}delay)/i,
    description: 'Validators can change commission without notice.',
    recommendation: 'Require notice period for commission changes.'
  },
  
  // Cross-Chain and Bridge Patterns
  {
    id: 'SOL1827',
    name: 'Bridge Message Verification',
    severity: 'critical',
    pattern: /bridge.*message|message.*bridge(?![\s\S]{0,100}verify|[\s\S]{0,100}sign)/i,
    description: 'Bridge messages must be cryptographically verified.',
    recommendation: 'Use cryptographic signatures for all bridge messages.'
  },
  {
    id: 'SOL1828',
    name: 'Cross-Chain Replay',
    severity: 'critical',
    pattern: /cross_chain.*replay|replay.*cross(?![\s\S]{0,100}prevent|[\s\S]{0,100}nonce)/i,
    description: 'Cross-chain transactions can be replayed.',
    recommendation: 'Use chain-specific nonces to prevent replay.'
  },
  {
    id: 'SOL1829',
    name: 'Finality Assumption',
    severity: 'critical',
    pattern: /finality.*assumpt|assume.*final(?![\s\S]{0,100}verify|[\s\S]{0,100}wait)/i,
    description: 'Assuming finality too early can cause double-spend.',
    recommendation: 'Wait for sufficient confirmations before finality.'
  },
  {
    id: 'SOL1830',
    name: 'Token Mapping Mismatch',
    severity: 'critical',
    pattern: /token.*map|map.*token(?![\s\S]{0,100}verify|[\s\S]{0,100}canonical)/i,
    description: 'Token mappings between chains can be exploited.',
    recommendation: 'Use canonical token mapping verification.'
  },
  
  // Wallet and User Security Patterns
  {
    id: 'SOL1831',
    name: 'Blind Signing Risk',
    severity: 'high',
    pattern: /blind.*sign|sign.*blind(?![\s\S]{0,100}warn|[\s\S]{0,100}display)/i,
    description: 'Blind signing enables phishing attacks.',
    recommendation: 'Always display transaction details before signing.'
  },
  {
    id: 'SOL1832',
    name: 'Simulation Mismatch',
    severity: 'critical',
    pattern: /simulat.*mismatch|mismatch.*simulat(?![\s\S]{0,100}verify|[\s\S]{0,100}match)/i,
    description: 'Transaction simulation can differ from execution.',
    recommendation: 'Verify simulation matches expected outcome.'
  },
  {
    id: 'SOL1833',
    name: 'Approval Phishing',
    severity: 'critical',
    pattern: /approve.*phish|phish.*approve(?![\s\S]{0,100}limit|[\s\S]{0,100}verify)/i,
    description: 'Token approvals can be exploited for phishing.',
    recommendation: 'Limit approval amounts and verify recipients.'
  },
  {
    id: 'SOL1834',
    name: 'SetAuthority Abuse',
    severity: 'critical',
    pattern: /set_authority|SetAuthority(?![\s\S]{0,100}verify|[\s\S]{0,100}confirm)/i,
    description: 'SetAuthority can transfer account ownership silently.',
    recommendation: 'Require confirmation for authority changes.'
  },
  
  // MEV and Ordering Patterns
  {
    id: 'SOL1835',
    name: 'Sandwich Attack Vector',
    severity: 'high',
    pattern: /sandwich|front.*run(?![\s\S]{0,100}protect|[\s\S]{0,100}slippage)/i,
    description: 'Transactions vulnerable to sandwich attacks.',
    recommendation: 'Use slippage protection and private transactions.'
  },
  {
    id: 'SOL1836',
    name: 'JIT Liquidity Manipulation',
    severity: 'high',
    pattern: /jit.*liquid|just.*in.*time(?![\s\S]{0,100}verify|[\s\S]{0,100}check)/i,
    description: 'JIT liquidity can manipulate prices.',
    recommendation: 'Use TWAP pricing to mitigate JIT manipulation.'
  },
  {
    id: 'SOL1837',
    name: 'Priority Fee Gaming',
    severity: 'medium',
    pattern: /priority.*fee|fee.*priority(?![\s\S]{0,100}cap|[\s\S]{0,100}limit)/i,
    description: 'Priority fees can be gamed for MEV extraction.',
    recommendation: 'Cap priority fees and use fair ordering.'
  },
  {
    id: 'SOL1838',
    name: 'Block Producer Advantage',
    severity: 'high',
    pattern: /block.*producer|leader.*schedule(?![\s\S]{0,100}fair|[\s\S]{0,100}random)/i,
    description: 'Block producers can exploit ordering advantage.',
    recommendation: 'Use commit-reveal or encrypted mempools.'
  },
  
  // Token Security Patterns
  {
    id: 'SOL1839',
    name: 'Token-2022 Transfer Hook Reentrancy',
    severity: 'critical',
    pattern: /transfer_hook|TransferHook(?![\s\S]{0,100}reentrancy|[\s\S]{0,100}guard)/i,
    description: 'Token-2022 transfer hooks enable reentrancy.',
    recommendation: 'Add reentrancy guards to transfer hook handlers.'
  },
  {
    id: 'SOL1840',
    name: 'Confidential Transfer Leak',
    severity: 'high',
    pattern: /confidential.*transfer|transfer.*confidential(?![\s\S]{0,100}verify|[\s\S]{0,100}zk)/i,
    description: 'Confidential transfers can leak information.',
    recommendation: 'Verify zero-knowledge proofs properly.'
  },
  {
    id: 'SOL1841',
    name: 'Interest-Bearing Token Bug',
    severity: 'high',
    pattern: /interest.*bearing|bearing.*interest(?![\s\S]{0,100}compound|[\s\S]{0,100}calculate)/i,
    description: 'Interest-bearing token calculations can have bugs.',
    recommendation: 'Verify interest calculation with multiple tests.'
  },
  {
    id: 'SOL1842',
    name: 'Non-Transferable Token Bypass',
    severity: 'high',
    pattern: /non.*transferable|soulbound(?![\s\S]{0,100}enforce|[\s\S]{0,100}verify)/i,
    description: 'Non-transferable tokens can sometimes be bypassed.',
    recommendation: 'Enforce non-transferability at protocol level.'
  },
  
  // Governance and DAO Patterns
  {
    id: 'SOL1843',
    name: 'Flash Governance Attack',
    severity: 'critical',
    pattern: /flash.*governance|governance.*flash(?![\s\S]{0,100}snapshot|[\s\S]{0,100}lock)/i,
    description: 'Flash loans can be used for governance attacks.',
    recommendation: 'Use snapshot voting or token locking.'
  },
  {
    id: 'SOL1844',
    name: 'Proposal Injection',
    severity: 'critical',
    pattern: /proposal.*inject|inject.*proposal(?![\s\S]{0,100}validate|[\s\S]{0,100}filter)/i,
    description: 'Malicious proposals can be injected.',
    recommendation: 'Validate and filter all governance proposals.'
  },
  {
    id: 'SOL1845',
    name: 'Quorum Manipulation',
    severity: 'high',
    pattern: /quorum.*manipulat|manipulat.*quorum(?![\s\S]{0,100}dynamic|[\s\S]{0,100}adjust)/i,
    description: 'Quorum can be manipulated via stake concentration.',
    recommendation: 'Use dynamic quorum based on participation.'
  },
  {
    id: 'SOL1846',
    name: 'Timelock Bypass',
    severity: 'critical',
    pattern: /timelock.*bypass|bypass.*timelock(?![\s\S]{0,100}enforce|[\s\S]{0,100}verify)/i,
    description: 'Timelocks can be bypassed in some cases.',
    recommendation: 'Enforce timelocks at protocol level.'
  },
  
  // Testing and Deployment Patterns
  {
    id: 'SOL1847',
    name: 'Devnet Address in Mainnet',
    severity: 'critical',
    pattern: /devnet.*address|address.*devnet(?![\s\S]{0,100}check|[\s\S]{0,100}verify)/i,
    description: 'Devnet addresses deployed to mainnet.',
    recommendation: 'Verify all addresses match deployment environment.'
  },
  {
    id: 'SOL1848',
    name: 'Debug Code in Production',
    severity: 'high',
    pattern: /debug.*prod|console\.log|dbg!(?![\s\S]{0,50}test)/i,
    description: 'Debug code left in production.',
    recommendation: 'Remove all debug code before mainnet deployment.'
  },
  {
    id: 'SOL1849',
    name: 'Unverified Program Deployment',
    severity: 'high',
    pattern: /deploy.*unverif|unverif.*deploy(?![\s\S]{0,100}audit|[\s\S]{0,100}verify)/i,
    description: 'Program deployed without verification.',
    recommendation: 'Verify program bytecode matches audited source.'
  },
  {
    id: 'SOL1850',
    name: 'Upgrade Authority Unsecured',
    severity: 'critical',
    pattern: /upgrade_authority|program.*upgrade(?![\s\S]{0,100}multisig|[\s\S]{0,100}timelock)/i,
    description: 'Upgrade authority not properly secured.',
    recommendation: 'Use multisig and timelock for upgrade authority.'
  },
  
  // Miscellaneous Security Patterns
  {
    id: 'SOL1851',
    name: 'Compute Budget Exhaustion',
    severity: 'high',
    pattern: /compute.*budget|budget.*exhaust(?![\s\S]{0,100}check|[\s\S]{0,100}limit)/i,
    description: 'Operations can exhaust compute budget.',
    recommendation: 'Check and limit compute usage per instruction.'
  },
  {
    id: 'SOL1852',
    name: 'Account Size Overflow',
    severity: 'high',
    pattern: /account.*size|size.*overflow(?![\s\S]{0,100}check|[\s\S]{0,100}limit)/i,
    description: 'Account size can overflow causing issues.',
    recommendation: 'Verify account size before allocation.'
  },
  {
    id: 'SOL1853',
    name: 'Rent Exemption Bypass',
    severity: 'medium',
    pattern: /rent.*exempt|exempt.*rent(?![\s\S]{0,100}verify|[\s\S]{0,100}check)/i,
    description: 'Rent exemption can be bypassed.',
    recommendation: 'Always verify rent exemption status.'
  },
  {
    id: 'SOL1854',
    name: 'Lamport Rounding Error',
    severity: 'medium',
    pattern: /lamport.*round|round.*lamport(?![\s\S]{0,100}floor|[\s\S]{0,100}ceil)/i,
    description: 'Lamport rounding can cause errors.',
    recommendation: 'Use explicit rounding direction for lamports.'
  },
  {
    id: 'SOL1855',
    name: 'Slot Number Dependence',
    severity: 'medium',
    pattern: /slot.*number|depend.*slot(?![\s\S]{0,100}verify|[\s\S]{0,100}range)/i,
    description: 'Depending on slot numbers can be manipulated.',
    recommendation: 'Use slot ranges instead of exact slots.'
  },
  {
    id: 'SOL1856',
    name: 'CPI Return Data Spoofing',
    severity: 'high',
    pattern: /return_data|cpi.*return(?![\s\S]{0,100}verify|[\s\S]{0,100}validate)/i,
    description: 'CPI return data can be spoofed.',
    recommendation: 'Validate CPI return data source program.'
  },
  {
    id: 'SOL1857',
    name: 'Account Close Balance Theft',
    severity: 'high',
    pattern: /close.*balance|balance.*close(?![\s\S]{0,100}verify|[\s\S]{0,100}destination)/i,
    description: 'Account close can send balance to wrong destination.',
    recommendation: 'Verify close destination before account closure.'
  },
  {
    id: 'SOL1858',
    name: 'Instruction Introspection Abuse',
    severity: 'high',
    pattern: /instruction.*introspect|sysvar.*instruction(?![\s\S]{0,100}verify|[\s\S]{0,100}validate)/i,
    description: 'Instruction introspection can be abused.',
    recommendation: 'Validate instruction sysvar data thoroughly.'
  },
  {
    id: 'SOL1859',
    name: 'Ed25519 Precompile Misuse',
    severity: 'critical',
    pattern: /ed25519.*precompile|precompile.*signature(?![\s\S]{0,100}verify|[\s\S]{0,100}validate)/i,
    description: 'Ed25519 precompile can be misused for signature bypass.',
    recommendation: 'Properly verify Ed25519 signatures via precompile.'
  },
  {
    id: 'SOL1860',
    name: 'Secp256k1 Signature Malleability',
    severity: 'high',
    pattern: /secp256k1.*malleable|signature.*malleable(?![\s\S]{0,100}normalize|[\s\S]{0,100}check)/i,
    description: 'Secp256k1 signatures can be malleable.',
    recommendation: 'Normalize signatures to prevent malleability.'
  },
];

export function checkBatch50Patterns(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  
  if (!content) return findings;
  
  const lines = content.split('\n');
  
  for (const pattern of BATCH_50_PATTERNS) {
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

export { BATCH_50_PATTERNS };
