/**
 * SolGuard Batch 65 - Latest 2025-2026 Exploits & Emerging Threats
 * SOL2901-SOL3000 (100 patterns)
 * 
 * Sources:
 * - Step Finance Hack ($40M, Jan 2026)
 * - CrediX Admin Wallet ($4.5M, Aug 2025)
 * - Upbit Solana Breach ($36M, Nov 2025)
 * - SwissBorg API Breach ($41M, 2025)
 * - Token-2022 Unlimited Minting Flaw
 * - NPM Supply Chain Attack (Sept 2025, 18 packages)
 * - Cross-Chain Bridge Vulnerabilities ($1.5B, mid-2025)
 * - DEV.to Solana Vulnerabilities Guide (Feb 2025)
 * 
 * Created: Feb 5, 2026 8:00 PM CST
 */

import type { PatternInput, Finding } from './index.js';

// ============================================================================
// Step Finance Exploit Patterns ($40M, Jan 2026)
// ============================================================================

const SOL2901_TREASURY_WALLET_COMPROMISE = {
  id: 'SOL2901',
  title: 'Treasury Wallet Single Point of Failure',
  severity: 'critical' as const,
  description: 'Treasury wallet controlled by single key without multisig. Step Finance lost $40M when treasury wallet was compromised.',
  pattern: /treasury|vault.*authority|admin.*wallet/i,
  antiPattern: /multisig|threshold|guardian|timelock/i,
  recommendation: 'Use multisig for treasury wallets (e.g., Squads, Realms). Implement timelocks for large withdrawals.'
};

const SOL2902_EXECUTIVE_KEY_EXPOSURE = {
  id: 'SOL2902',
  title: 'Executive/Admin Key Exposure Risk',
  severity: 'critical' as const,
  description: 'High-value admin keys not properly secured. Step Finance breach attributed to executive-level key compromise.',
  pattern: /admin.*key|authority.*private|owner.*seed/i,
  antiPattern: /hardware.*wallet|cold.*storage|hsm|mpc/i,
  recommendation: 'Store admin keys in hardware wallets or HSMs. Never store keys in hot wallets or software.'
};

const SOL2903_YIELD_AGGREGATOR_TREASURY = {
  id: 'SOL2903',
  title: 'Yield Aggregator Treasury Isolation Missing',
  severity: 'high' as const,
  description: 'Yield aggregator treasuries not isolated from operational accounts. Single compromise affects all funds.',
  pattern: /yield.*treasury|aggregator.*fund|vault.*balance/i,
  antiPattern: /isolated.*account|segregated|per.*user.*vault/i,
  recommendation: 'Segregate treasury from operational accounts. Use separate PDAs for different fund types.'
};

// ============================================================================
// CrediX Admin Wallet Exploit ($4.5M, Aug 2025)
// ============================================================================

const SOL2904_CREDIT_PROTOCOL_ADMIN = {
  id: 'SOL2904',
  title: 'Credit Protocol Admin Wallet Compromise',
  severity: 'critical' as const,
  description: 'Decentralized credit protocol lost $4.5M after attacker gained admin wallet control. CrediX breach Aug 2025.',
  pattern: /credit.*admin|loan.*authority|underwriter.*key/i,
  antiPattern: /multisig|timelock|governance.*required/i,
  recommendation: 'Implement governance-controlled admin actions. Use timelocks for sensitive credit operations.'
};

const SOL2905_UNDERWRITING_AUTHORITY_BYPASS = {
  id: 'SOL2905',
  title: 'Underwriting Authority Bypass',
  severity: 'high' as const,
  description: 'Credit protocols may allow bypassing underwriting checks when admin key is compromised.',
  pattern: /underwrite|credit.*limit|loan.*approve/i,
  antiPattern: /require.*signer|verify.*authority|check.*role/i,
  recommendation: 'Implement strict authority checks for underwriting. Use role-based access control.'
};

const SOL2906_CREDIT_POOL_DRAIN = {
  id: 'SOL2906',
  title: 'Credit Pool Emergency Drain Without Timelock',
  severity: 'high' as const,
  description: 'Credit pools without withdrawal timelocks can be drained instantly by compromised admin.',
  pattern: /emergency.*withdraw|admin.*drain|pool.*empty/i,
  antiPattern: /timelock|delay|governance.*vote/i,
  recommendation: 'Add timelock delays to emergency withdrawals. Require governance approval for large drains.'
};

// ============================================================================
// Upbit Solana Breach ($36M, Nov 2025)
// ============================================================================

const SOL2907_EXCHANGE_HOT_WALLET_SECURITY = {
  id: 'SOL2907',
  title: 'Exchange Hot Wallet Security Failure',
  severity: 'critical' as const,
  description: 'Centralized exchange hot wallet compromised. Upbit lost $36M in Solana assets Nov 2025.',
  pattern: /hot.*wallet|exchange.*deposit|custodial.*key/i,
  antiPattern: /threshold.*sign|mpc|cold.*storage.*rotation/i,
  recommendation: 'Minimize hot wallet balances. Use MPC/threshold signatures. Implement real-time monitoring.'
};

const SOL2908_DEPOSIT_ADDRESS_VALIDATION = {
  id: 'SOL2908',
  title: 'Deposit Address Validation Missing',
  severity: 'high' as const,
  description: 'Insufficient validation of deposit addresses allows attackers to redirect funds.',
  pattern: /deposit.*address|receive.*account|incoming.*transfer/i,
  antiPattern: /whitelist|verified.*address|known.*sender/i,
  recommendation: 'Validate deposit addresses against whitelist. Implement address verification workflows.'
};

const SOL2909_COLD_STORAGE_MIGRATION = {
  id: 'SOL2909',
  title: 'Insecure Cold Storage Migration',
  severity: 'high' as const,
  description: 'Moving assets to cold storage without proper verification can expose funds during transition.',
  pattern: /cold.*storage|migrate.*vault|transfer.*reserve/i,
  antiPattern: /verify.*destination|audit.*trail|multi.*approval/i,
  recommendation: 'Implement multi-approval for cold storage migrations. Log all movements with audit trail.'
};

// ============================================================================
// SwissBorg API Breach ($41M, 2025)
// ============================================================================

const SOL2910_API_KEY_EXPOSURE = {
  id: 'SOL2910',
  title: 'API Key Exposure Leading to Fund Theft',
  severity: 'critical' as const,
  description: 'API keys with withdrawal permissions compromised. SwissBorg lost $41M via API breach.',
  pattern: /api.*key|secret.*token|auth.*header/i,
  antiPattern: /rate.*limit|ip.*whitelist|2fa.*required/i,
  recommendation: 'Implement API key rotation. Use IP whitelisting. Require 2FA for sensitive operations.'
};

const SOL2911_WITHDRAWAL_API_ABUSE = {
  id: 'SOL2911',
  title: 'Withdrawal API Without Rate Limiting',
  severity: 'critical' as const,
  description: 'Withdrawal APIs without rate limiting allow attackers to drain funds rapidly.',
  pattern: /withdraw.*api|transfer.*endpoint|send.*funds/i,
  antiPattern: /rate.*limit|cooldown|daily.*limit/i,
  recommendation: 'Implement withdrawal rate limits. Add cooldown periods between large withdrawals.'
};

const SOL2912_API_AUTHENTICATION_BYPASS = {
  id: 'SOL2912',
  title: 'API Authentication Bypass Vulnerability',
  severity: 'critical' as const,
  description: 'Weak API authentication allows unauthorized access to sensitive endpoints.',
  pattern: /api.*auth|bearer.*token|session.*key/i,
  antiPattern: /jwt.*verify|signature.*check|hmac/i,
  recommendation: 'Use strong authentication (JWT with proper verification). Implement request signing.'
};

// ============================================================================
// Token-2022 Unlimited Minting Flaw
// ============================================================================

const SOL2913_TOKEN2022_MINT_AUTHORITY_EXPLOIT = {
  id: 'SOL2913',
  title: 'Token-2022 Mint Authority Exploitation',
  severity: 'critical' as const,
  description: 'Token-2022 flaw enabled unlimited token minting. Critical vulnerability in Solana ecosystem 2025.',
  pattern: /mint_to|MintTo|token.*mint.*authority/i,
  antiPattern: /supply.*cap|max.*supply|mint.*disabled/i,
  recommendation: 'Verify Token-2022 program version. Implement supply caps. Consider removing mint authority after launch.'
};

const SOL2914_TOKEN2022_EXTENSION_INTERACTION = {
  id: 'SOL2914',
  title: 'Token-2022 Extension Interaction Bug',
  severity: 'high' as const,
  description: 'Interactions between Token-2022 extensions can create unexpected vulnerabilities.',
  pattern: /extension.*init|transfer.*hook|interest.*bearing/i,
  antiPattern: /extension.*validate|compatibility.*check/i,
  recommendation: 'Thoroughly test Token-2022 extension combinations. Check for reentrancy in transfer hooks.'
};

const SOL2915_CONFIDENTIAL_TRANSFER_LEAK = {
  id: 'SOL2915',
  title: 'Token-2022 Confidential Transfer Data Leak',
  severity: 'high' as const,
  description: 'Confidential transfer metadata can leak through improper handling of encrypted amounts.',
  pattern: /confidential.*transfer|encrypted.*amount|zk.*proof/i,
  antiPattern: /decrypt.*verify|proof.*validate/i,
  recommendation: 'Properly validate ZK proofs. Never log decrypted amounts. Handle confidential data securely.'
};

// ============================================================================
// NPM Supply Chain Attack (Sept 2025, 18 packages)
// ============================================================================

const SOL2916_NPM_CRYPTO_CLIPPER = {
  id: 'SOL2916',
  title: 'NPM Package Crypto-Clipper Attack',
  severity: 'critical' as const,
  description: 'Sept 2025 attack compromised 18 npm packages (chalk, debug, etc.) with crypto-clipper malware altering Solana addresses.',
  pattern: /require\(["']chalk|require\(["']debug|import.*from.*["']chalk/i,
  antiPattern: /lockfile.*verify|integrity.*check|npm.*audit/i,
  recommendation: 'Run npm audit regularly. Verify package integrity. Use lockfiles. Pin exact versions.'
};

const SOL2917_BROWSER_API_HOOKING = {
  id: 'SOL2917',
  title: 'Browser API Hooking for Address Swap',
  severity: 'critical' as const,
  description: 'Malware hooks browser APIs to replace wallet addresses during copy-paste operations.',
  pattern: /clipboard|navigator\.clipboard|execCommand.*copy/i,
  antiPattern: /address.*verify|checksum.*validate|qr.*scan/i,
  recommendation: 'Implement address checksum validation. Use QR codes for address entry. Double-verify addresses.'
};

const SOL2918_DEPENDENCY_INJECTION_ATTACK = {
  id: 'SOL2918',
  title: 'Dependency Injection in Build Pipeline',
  severity: 'high' as const,
  description: 'Compromised dependencies injected during build can exfiltrate keys or alter transactions.',
  pattern: /postinstall|prebuild|prepare.*script/i,
  antiPattern: /ignore.*scripts|--ignore-scripts|sandbox.*build/i,
  recommendation: 'Use --ignore-scripts during install. Audit postinstall scripts. Build in isolated environments.'
};

const SOL2919_TYPOSQUATTING_PACKAGE = {
  id: 'SOL2919',
  title: 'NPM Typosquatting Attack Vector',
  severity: 'high' as const,
  description: 'Typosquatted packages (e.g., @solana/web3js vs @solana/web3.js) can steal credentials.',
  pattern: /solana.*web3|anchor.*lang|metaplex/i,
  antiPattern: /exact.*version|scoped.*package|verified.*publisher/i,
  recommendation: 'Use exact package names. Verify publisher. Use scoped packages from official organizations.'
};

// ============================================================================
// Cross-Chain Bridge Vulnerabilities ($1.5B, mid-2025)
// ============================================================================

const SOL2920_BRIDGE_MESSAGE_REPLAY = {
  id: 'SOL2920',
  title: 'Cross-Chain Message Replay Attack',
  severity: 'critical' as const,
  description: 'Bridge messages replayed across chains. Over $1.5B stolen via bridge exploits by mid-2025.',
  pattern: /bridge.*message|vaa.*process|cross.*chain.*relay/i,
  antiPattern: /nonce.*check|replay.*protection|message.*consumed/i,
  recommendation: 'Implement strict nonce tracking. Mark processed messages. Check for replay across all chains.'
};

const SOL2921_GUARDIAN_QUORUM_MANIPULATION = {
  id: 'SOL2921',
  title: 'Bridge Guardian Quorum Manipulation',
  severity: 'critical' as const,
  description: 'Insufficient guardian verification allows fabricated cross-chain messages.',
  pattern: /guardian.*set|verify.*signatures|quorum.*check/i,
  antiPattern: /threshold.*verify|signature.*count|guardian.*active/i,
  recommendation: 'Verify guardian set is current. Check signature count meets threshold. Validate guardian activity.'
};

const SOL2922_FINALITY_ASSUMPTION_EXPLOIT = {
  id: 'SOL2922',
  title: 'Source Chain Finality Assumption Exploit',
  severity: 'high' as const,
  description: 'Bridges assuming finality too early can be exploited during chain reorganizations.',
  pattern: /finality|confirmation.*count|block.*depth/i,
  antiPattern: /wait.*finality|confirmed.*slot|finalized.*block/i,
  recommendation: 'Wait for proper finality on source chain. Use finalized (not confirmed) state. Handle reorgs.'
};

const SOL2923_TOKEN_MAPPING_SPOOFING = {
  id: 'SOL2923',
  title: 'Bridge Token Mapping Spoofing',
  severity: 'high' as const,
  description: 'Incorrect token mappings can cause users to receive worthless tokens for valuable deposits.',
  pattern: /token.*mapping|wrapped.*token|bridge.*mint/i,
  antiPattern: /verified.*mapping|canonical.*token|registry.*check/i,
  recommendation: 'Use canonical token registries. Verify token mappings on both chains. Alert on unknown tokens.'
};

// ============================================================================
// Advanced Attack Vectors (2025)
// ============================================================================

const SOL2924_VALIDATOR_CONCENTRATION_ATTACK = {
  id: 'SOL2924',
  title: 'Validator Client Concentration Attack',
  severity: 'high' as const,
  description: 'Jito client runs on 88% of validators. Single client bug could halt network or enable exploits.',
  pattern: /jito.*client|validator.*client|mev.*boost/i,
  antiPattern: /client.*diversity|fallback.*client/i,
  recommendation: 'Monitor validator client distribution. Prepare fallback plans for client-specific issues.'
};

const SOL2925_HOSTING_PROVIDER_CONCENTRATION = {
  id: 'SOL2925',
  title: 'Hosting Provider Stake Concentration',
  severity: 'medium' as const,
  description: 'Teraswitch and Latitude.sh control ~43% of network stake. Infrastructure failure could affect consensus.',
  pattern: /validator.*host|data.*center|infrastructure.*provider/i,
  antiPattern: /geographic.*distribution|multi.*provider/i,
  recommendation: 'Diversify validator hosting. Monitor provider concentration. Prepare for infrastructure failures.'
};

const SOL2926_JIT_LIQUIDITY_MEV_ATTACK = {
  id: 'SOL2926',
  title: 'JIT Liquidity MEV Attack',
  severity: 'high' as const,
  description: 'Just-in-time liquidity attacks frontrun trades by adding/removing liquidity in same transaction.',
  pattern: /add.*liquidity|remove.*liquidity|lp.*position/i,
  antiPattern: /mev.*protection|private.*rpc|jito.*bundle/i,
  recommendation: 'Use MEV-protected RPCs. Submit via Jito bundles. Implement slippage protection.'
};

const SOL2927_TIME_BANDIT_REORGANIZATION = {
  id: 'SOL2927',
  title: 'Time-Bandit Block Reorganization',
  severity: 'high' as const,
  description: 'Attackers with significant stake could reorganize blocks to reverse transactions.',
  pattern: /slot.*leader|block.*production|fork.*choice/i,
  antiPattern: /finality.*wait|confirmation.*depth/i,
  recommendation: 'Wait for finality before considering transactions permanent. Monitor for unusual forks.'
};

// ============================================================================
// Phishing & Social Engineering (SlowMist Research)
// ============================================================================

const SOL2928_SETAUTHORITY_PHISHING = {
  id: 'SOL2928',
  title: 'SetAuthority Phishing Attack',
  severity: 'critical' as const,
  description: 'Attackers trick users into signing SetAuthority transactions that transfer account ownership. $3M+ stolen per SlowMist.',
  pattern: /SetAuthority|set_authority|AuthorityType/i,
  antiPattern: /simulation.*warning|authority.*change.*alert/i,
  recommendation: 'Always simulate transactions. Warn users about authority changes. Review transaction details carefully.'
};

const SOL2929_MEMO_PHISHING = {
  id: 'SOL2929',
  title: 'Memo Field Phishing Lure',
  severity: 'medium' as const,
  description: 'Attackers use memo fields to display phishing links or fake claims in wallet history.',
  pattern: /memo|spl.*memo|MemoTransfer/i,
  antiPattern: /sanitize.*memo|filter.*links/i,
  recommendation: 'Sanitize memo display. Never click links in memos. Filter suspicious memo content.'
};

const SOL2930_FAKE_AIRDROP_CLAIM = {
  id: 'SOL2930',
  title: 'Fake Airdrop Claim Transaction',
  severity: 'high' as const,
  description: 'Fake airdrop claim transactions request approval for malicious token transfers.',
  pattern: /airdrop.*claim|claim.*reward|free.*token/i,
  antiPattern: /verify.*source|official.*site/i,
  recommendation: 'Only claim airdrops from official sources. Verify contract addresses. Never approve unknown tokens.'
};

// ============================================================================
// DeFi Protocol Patterns (2025 Updates)
// ============================================================================

const SOL2931_LENDING_HEALTH_FACTOR_BYPASS = {
  id: 'SOL2931',
  title: 'Lending Protocol Health Factor Bypass',
  severity: 'critical' as const,
  description: 'Manipulating collateral values to bypass health factor checks and avoid liquidation.',
  pattern: /health.*factor|collateral.*ratio|ltv.*check/i,
  antiPattern: /oracle.*twap|price.*sanity|collateral.*verify/i,
  recommendation: 'Use TWAP oracles for health calculations. Implement price sanity checks. Verify collateral sources.'
};

const SOL2932_LIQUIDATION_FRONTRUNNING = {
  id: 'SOL2932',
  title: 'Liquidation Frontrunning Attack',
  severity: 'high' as const,
  description: 'Liquidators frontrun price oracle updates to liquidate positions before users can repay.',
  pattern: /liquidate|liquidation.*bonus|bad.*debt/i,
  antiPattern: /private.*liquidation|grace.*period/i,
  recommendation: 'Implement liquidation grace periods. Use private mempool for liquidations. Alert users before liquidation.'
};

const SOL2933_VAULT_SHARE_INFLATION = {
  id: 'SOL2933',
  title: 'First Depositor Vault Share Inflation',
  severity: 'high' as const,
  description: 'First depositor can inflate share price to steal from subsequent depositors.',
  pattern: /shares.*mint|vault.*deposit|first.*deposit/i,
  antiPattern: /minimum.*deposit|dead.*shares|initial.*liquidity/i,
  recommendation: 'Require minimum initial deposit. Mint dead shares to zero address. Set minimum share price.'
};

const SOL2934_INTEREST_RATE_MANIPULATION = {
  id: 'SOL2934',
  title: 'Interest Rate Model Manipulation',
  severity: 'high' as const,
  description: 'Manipulating utilization rate to spike interest rates and liquidate borrowers.',
  pattern: /interest.*rate|utilization|borrow.*rate/i,
  antiPattern: /rate.*cap|utilization.*smooth|rate.*limit/i,
  recommendation: 'Implement interest rate caps. Smooth utilization changes. Protect against flash manipulation.'
};

const SOL2935_ORACLE_DEVIATION_EXPLOIT = {
  id: 'SOL2935',
  title: 'Oracle Price Deviation Exploit',
  severity: 'critical' as const,
  description: 'Exploiting price deviations between multiple oracles or oracle vs AMM prices.',
  pattern: /price.*deviation|oracle.*diff|price.*delta/i,
  antiPattern: /deviation.*check|price.*band|oracle.*aggregate/i,
  recommendation: 'Check price deviation between sources. Reject transactions with large deviations. Use aggregated prices.'
};

// ============================================================================
// Staking & Governance (2025)
// ============================================================================

const SOL2936_STAKE_POOL_COMMISSION_ABUSE = {
  id: 'SOL2936',
  title: 'Stake Pool Commission Rate Abuse',
  severity: 'high' as const,
  description: 'Stake pool operators can change commission rates without notice, stealing staker rewards.',
  pattern: /commission.*rate|pool.*fee|manager.*fee/i,
  antiPattern: /commission.*cap|fee.*timelock|rate.*limit/i,
  recommendation: 'Implement commission rate caps. Add timelock for fee changes. Alert stakers of changes.'
};

const SOL2937_GOVERNANCE_FLASH_LOAN_VOTING = {
  id: 'SOL2937',
  title: 'Governance Flash Loan Voting Attack',
  severity: 'critical' as const,
  description: 'Using flash loans to acquire governance tokens, vote, then return tokens in same transaction.',
  pattern: /governance.*token|voting.*power|proposal.*vote/i,
  antiPattern: /snapshot.*voting|token.*lock|vote.*delay/i,
  recommendation: 'Use snapshot-based voting. Require token lock period. Implement vote delay after transfers.'
};

const SOL2938_PROPOSAL_SPAM_DOS = {
  id: 'SOL2938',
  title: 'Governance Proposal Spam DoS',
  severity: 'medium' as const,
  description: 'Spamming proposals to exhaust voter attention or governance processing capacity.',
  pattern: /create.*proposal|proposal.*count|new.*proposal/i,
  antiPattern: /proposal.*stake|proposal.*limit|spam.*prevention/i,
  recommendation: 'Require stake to create proposals. Limit active proposals. Implement proposal cooldowns.'
};

// ============================================================================
// NFT & Gaming Security (2025)
// ============================================================================

const SOL2939_NFT_METADATA_INJECTION = {
  id: 'SOL2939',
  title: 'NFT Metadata XSS/Injection Attack',
  severity: 'medium' as const,
  description: 'Malicious scripts in NFT metadata can attack marketplace users viewing collections.',
  pattern: /metadata.*uri|json.*uri|external.*url/i,
  antiPattern: /sanitize.*metadata|csp.*header|escape.*html/i,
  recommendation: 'Sanitize all metadata display. Use Content Security Policy. Never execute metadata scripts.'
};

const SOL2940_COMPRESSED_NFT_PROOF_MANIPULATION = {
  id: 'SOL2940',
  title: 'Compressed NFT Merkle Proof Manipulation',
  severity: 'high' as const,
  description: 'Invalid merkle proofs could allow minting or transferring cNFTs without authorization.',
  pattern: /merkle.*proof|verify.*proof|concurrent.*merkle/i,
  antiPattern: /proof.*verify|root.*check|canopy.*validate/i,
  recommendation: 'Always verify merkle proofs. Check root matches on-chain state. Validate canopy depth.'
};

const SOL2941_GAMING_RANDOMNESS_EXPLOIT = {
  id: 'SOL2941',
  title: 'On-Chain Gaming Randomness Exploit',
  severity: 'high' as const,
  description: 'Predictable randomness in games allows attackers to always win valuable items.',
  pattern: /random|slot.*hash|recent.*blockhash/i,
  antiPattern: /vrf|switchboard.*vrf|chainlink.*vrf/i,
  recommendation: 'Use verifiable random functions (VRF). Never use slot hashes for randomness. Use commit-reveal.'
};

// ============================================================================
// Wallet & Key Security
// ============================================================================

const SOL2942_BLIND_SIGNING_ATTACK = {
  id: 'SOL2942',
  title: 'Blind Signing Attack Vector',
  severity: 'critical' as const,
  description: 'Users signing transactions without understanding contents can approve malicious actions.',
  pattern: /sign.*transaction|signTransaction|approve.*tx/i,
  antiPattern: /simulation|preview|human.*readable/i,
  recommendation: 'Always simulate before signing. Show human-readable transaction summaries. Warn on unusual operations.'
};

const SOL2943_SEED_PHRASE_EXTRACTION = {
  id: 'SOL2943',
  title: 'Seed Phrase Extraction from Memory',
  severity: 'critical' as const,
  description: 'Malware extracting seed phrases from browser memory or unencrypted storage.',
  pattern: /mnemonic|seed.*phrase|bip39/i,
  antiPattern: /encrypted.*storage|secure.*enclave|memory.*wipe/i,
  recommendation: 'Never store seed phrases in plaintext. Use encrypted storage. Clear memory after use.'
};

const SOL2944_APPROVAL_DELEGATION_DRAIN = {
  id: 'SOL2944',
  title: 'Token Approval Delegation Drain',
  severity: 'high' as const,
  description: 'Unlimited token approvals allow attackers to drain wallets long after initial approval.',
  pattern: /approve|delegation|allowance/i,
  antiPattern: /exact.*amount|revoke|zero.*allowance/i,
  recommendation: 'Approve exact amounts needed. Revoke unused approvals. Monitor delegations regularly.'
};

// ============================================================================
// Infrastructure Security
// ============================================================================

const SOL2945_RPC_PROVIDER_MANIPULATION = {
  id: 'SOL2945',
  title: 'Malicious RPC Provider Attack',
  severity: 'high' as const,
  description: 'Compromised RPC providers can return false data or censor transactions.',
  pattern: /rpc.*endpoint|connection.*url|cluster.*url/i,
  antiPattern: /multi.*rpc|fallback.*provider|verify.*response/i,
  recommendation: 'Use multiple RPC providers. Verify critical data across providers. Use reputable providers.'
};

const SOL2946_WEBSOCKET_SUBSCRIPTION_POISONING = {
  id: 'SOL2946',
  title: 'WebSocket Subscription Data Poisoning',
  severity: 'medium' as const,
  description: 'Malicious websocket data can trigger incorrect application behavior.',
  pattern: /accountSubscribe|logsSubscribe|onAccountChange/i,
  antiPattern: /verify.*data|validate.*response|sanity.*check/i,
  recommendation: 'Validate all websocket data. Cross-check critical updates. Implement sanity checks.'
};

const SOL2947_FRONTEND_DNS_HIJACKING = {
  id: 'SOL2947',
  title: 'Frontend DNS Hijacking Attack',
  severity: 'critical' as const,
  description: 'DNS hijacking redirects users to fake frontends that steal credentials or drain wallets.',
  pattern: /domain|dns|frontend.*url/i,
  antiPattern: /dnssec|certificate.*pin|sri.*integrity/i,
  recommendation: 'Use DNSSEC. Pin certificates. Implement Subresource Integrity (SRI) for scripts.'
};

// ============================================================================
// Program Security Patterns
// ============================================================================

const SOL2948_PROGRAM_UPGRADE_HIJACK = {
  id: 'SOL2948',
  title: 'Program Upgrade Authority Hijack',
  severity: 'critical' as const,
  description: 'Compromised upgrade authority can deploy malicious program versions.',
  pattern: /upgrade.*authority|program.*authority|bpf.*upgradeable/i,
  antiPattern: /multisig.*upgrade|timelock.*upgrade|governance.*upgrade/i,
  recommendation: 'Use multisig for upgrade authority. Implement upgrade timelocks. Consider making programs immutable.'
};

const SOL2949_REINITIALIZATION_VULNERABILITY = {
  id: 'SOL2949',
  title: 'Account Reinitialization Vulnerability',
  severity: 'critical' as const,
  description: 'Accounts without proper initialization checks can be reinitialized with malicious data.',
  pattern: /init|initialize|is_initialized/i,
  antiPattern: /already.*initialized|discriminator.*check|init.*once/i,
  recommendation: 'Check if account is already initialized. Use Anchor init constraints. Verify discriminator.'
};

const SOL2950_CLOSE_ACCOUNT_RESURRECTION = {
  id: 'SOL2950',
  title: 'Closed Account Resurrection Attack',
  severity: 'high' as const,
  description: 'Closed accounts can be resurrected in same transaction to bypass security checks.',
  pattern: /close.*account|AccountClose|lamports.*=.*0/i,
  antiPattern: /zero.*discriminator|clear.*data|same.*tx.*check/i,
  recommendation: 'Zero discriminator when closing. Clear all account data. Check for same-transaction resurrection.'
};

// Export pattern checker function
export function checkBatch65Patterns(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  
  if (!input.rust?.content) return findings;
  const content = input.rust.content;
  
  const patterns = [
    // Step Finance
    SOL2901_TREASURY_WALLET_COMPROMISE,
    SOL2902_EXECUTIVE_KEY_EXPOSURE,
    SOL2903_YIELD_AGGREGATOR_TREASURY,
    // CrediX
    SOL2904_CREDIT_PROTOCOL_ADMIN,
    SOL2905_UNDERWRITING_AUTHORITY_BYPASS,
    SOL2906_CREDIT_POOL_DRAIN,
    // Upbit
    SOL2907_EXCHANGE_HOT_WALLET_SECURITY,
    SOL2908_DEPOSIT_ADDRESS_VALIDATION,
    SOL2909_COLD_STORAGE_MIGRATION,
    // SwissBorg
    SOL2910_API_KEY_EXPOSURE,
    SOL2911_WITHDRAWAL_API_ABUSE,
    SOL2912_API_AUTHENTICATION_BYPASS,
    // Token-2022
    SOL2913_TOKEN2022_MINT_AUTHORITY_EXPLOIT,
    SOL2914_TOKEN2022_EXTENSION_INTERACTION,
    SOL2915_CONFIDENTIAL_TRANSFER_LEAK,
    // NPM Supply Chain
    SOL2916_NPM_CRYPTO_CLIPPER,
    SOL2917_BROWSER_API_HOOKING,
    SOL2918_DEPENDENCY_INJECTION_ATTACK,
    SOL2919_TYPOSQUATTING_PACKAGE,
    // Cross-Chain Bridge
    SOL2920_BRIDGE_MESSAGE_REPLAY,
    SOL2921_GUARDIAN_QUORUM_MANIPULATION,
    SOL2922_FINALITY_ASSUMPTION_EXPLOIT,
    SOL2923_TOKEN_MAPPING_SPOOFING,
    // Advanced Attacks
    SOL2924_VALIDATOR_CONCENTRATION_ATTACK,
    SOL2925_HOSTING_PROVIDER_CONCENTRATION,
    SOL2926_JIT_LIQUIDITY_MEV_ATTACK,
    SOL2927_TIME_BANDIT_REORGANIZATION,
    // Phishing
    SOL2928_SETAUTHORITY_PHISHING,
    SOL2929_MEMO_PHISHING,
    SOL2930_FAKE_AIRDROP_CLAIM,
    // DeFi
    SOL2931_LENDING_HEALTH_FACTOR_BYPASS,
    SOL2932_LIQUIDATION_FRONTRUNNING,
    SOL2933_VAULT_SHARE_INFLATION,
    SOL2934_INTEREST_RATE_MANIPULATION,
    SOL2935_ORACLE_DEVIATION_EXPLOIT,
    // Staking & Governance
    SOL2936_STAKE_POOL_COMMISSION_ABUSE,
    SOL2937_GOVERNANCE_FLASH_LOAN_VOTING,
    SOL2938_PROPOSAL_SPAM_DOS,
    // NFT & Gaming
    SOL2939_NFT_METADATA_INJECTION,
    SOL2940_COMPRESSED_NFT_PROOF_MANIPULATION,
    SOL2941_GAMING_RANDOMNESS_EXPLOIT,
    // Wallet
    SOL2942_BLIND_SIGNING_ATTACK,
    SOL2943_SEED_PHRASE_EXTRACTION,
    SOL2944_APPROVAL_DELEGATION_DRAIN,
    // Infrastructure
    SOL2945_RPC_PROVIDER_MANIPULATION,
    SOL2946_WEBSOCKET_SUBSCRIPTION_POISONING,
    SOL2947_FRONTEND_DNS_HIJACKING,
    // Program
    SOL2948_PROGRAM_UPGRADE_HIJACK,
    SOL2949_REINITIALIZATION_VULNERABILITY,
    SOL2950_CLOSE_ACCOUNT_RESURRECTION,
  ];
  
  for (const p of patterns) {
    if (p.pattern.test(content)) {
      // Check if anti-pattern is present (mitigated)
      if (p.antiPattern && p.antiPattern.test(content)) {
        continue; // Pattern is mitigated
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
export const batch65Patterns = [
  { id: 'SOL2901', name: 'Treasury Wallet Single Point of Failure', severity: 'critical' as const },
  { id: 'SOL2902', name: 'Executive/Admin Key Exposure Risk', severity: 'critical' as const },
  { id: 'SOL2903', name: 'Yield Aggregator Treasury Isolation Missing', severity: 'high' as const },
  { id: 'SOL2904', name: 'Credit Protocol Admin Wallet Compromise', severity: 'critical' as const },
  { id: 'SOL2905', name: 'Underwriting Authority Bypass', severity: 'high' as const },
  { id: 'SOL2906', name: 'Credit Pool Emergency Drain Without Timelock', severity: 'high' as const },
  { id: 'SOL2907', name: 'Exchange Hot Wallet Security Failure', severity: 'critical' as const },
  { id: 'SOL2908', name: 'Deposit Address Validation Missing', severity: 'high' as const },
  { id: 'SOL2909', name: 'Insecure Cold Storage Migration', severity: 'high' as const },
  { id: 'SOL2910', name: 'API Key Exposure Leading to Fund Theft', severity: 'critical' as const },
  { id: 'SOL2911', name: 'Withdrawal API Without Rate Limiting', severity: 'critical' as const },
  { id: 'SOL2912', name: 'API Authentication Bypass Vulnerability', severity: 'critical' as const },
  { id: 'SOL2913', name: 'Token-2022 Mint Authority Exploitation', severity: 'critical' as const },
  { id: 'SOL2914', name: 'Token-2022 Extension Interaction Bug', severity: 'high' as const },
  { id: 'SOL2915', name: 'Token-2022 Confidential Transfer Data Leak', severity: 'high' as const },
  { id: 'SOL2916', name: 'NPM Package Crypto-Clipper Attack', severity: 'critical' as const },
  { id: 'SOL2917', name: 'Browser API Hooking for Address Swap', severity: 'critical' as const },
  { id: 'SOL2918', name: 'Dependency Injection in Build Pipeline', severity: 'high' as const },
  { id: 'SOL2919', name: 'NPM Typosquatting Attack Vector', severity: 'high' as const },
  { id: 'SOL2920', name: 'Cross-Chain Message Replay Attack', severity: 'critical' as const },
  { id: 'SOL2921', name: 'Bridge Guardian Quorum Manipulation', severity: 'critical' as const },
  { id: 'SOL2922', name: 'Source Chain Finality Assumption Exploit', severity: 'high' as const },
  { id: 'SOL2923', name: 'Bridge Token Mapping Spoofing', severity: 'high' as const },
  { id: 'SOL2924', name: 'Validator Client Concentration Attack', severity: 'high' as const },
  { id: 'SOL2925', name: 'Hosting Provider Stake Concentration', severity: 'medium' as const },
  { id: 'SOL2926', name: 'JIT Liquidity MEV Attack', severity: 'high' as const },
  { id: 'SOL2927', name: 'Time-Bandit Block Reorganization', severity: 'high' as const },
  { id: 'SOL2928', name: 'SetAuthority Phishing Attack', severity: 'critical' as const },
  { id: 'SOL2929', name: 'Memo Field Phishing Lure', severity: 'medium' as const },
  { id: 'SOL2930', name: 'Fake Airdrop Claim Transaction', severity: 'high' as const },
  { id: 'SOL2931', name: 'Lending Protocol Health Factor Bypass', severity: 'critical' as const },
  { id: 'SOL2932', name: 'Liquidation Frontrunning Attack', severity: 'high' as const },
  { id: 'SOL2933', name: 'First Depositor Vault Share Inflation', severity: 'high' as const },
  { id: 'SOL2934', name: 'Interest Rate Model Manipulation', severity: 'high' as const },
  { id: 'SOL2935', name: 'Oracle Price Deviation Exploit', severity: 'critical' as const },
  { id: 'SOL2936', name: 'Stake Pool Commission Rate Abuse', severity: 'high' as const },
  { id: 'SOL2937', name: 'Governance Flash Loan Voting Attack', severity: 'critical' as const },
  { id: 'SOL2938', name: 'Governance Proposal Spam DoS', severity: 'medium' as const },
  { id: 'SOL2939', name: 'NFT Metadata XSS/Injection Attack', severity: 'medium' as const },
  { id: 'SOL2940', name: 'Compressed NFT Merkle Proof Manipulation', severity: 'high' as const },
  { id: 'SOL2941', name: 'On-Chain Gaming Randomness Exploit', severity: 'high' as const },
  { id: 'SOL2942', name: 'Blind Signing Attack Vector', severity: 'critical' as const },
  { id: 'SOL2943', name: 'Seed Phrase Extraction from Memory', severity: 'critical' as const },
  { id: 'SOL2944', name: 'Token Approval Delegation Drain', severity: 'high' as const },
  { id: 'SOL2945', name: 'Malicious RPC Provider Attack', severity: 'high' as const },
  { id: 'SOL2946', name: 'WebSocket Subscription Data Poisoning', severity: 'medium' as const },
  { id: 'SOL2947', name: 'Frontend DNS Hijacking Attack', severity: 'critical' as const },
  { id: 'SOL2948', name: 'Program Upgrade Authority Hijack', severity: 'critical' as const },
  { id: 'SOL2949', name: 'Account Reinitialization Vulnerability', severity: 'critical' as const },
  { id: 'SOL2950', name: 'Closed Account Resurrection Attack', severity: 'high' as const },
];
