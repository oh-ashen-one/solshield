/**
 * SolShield Security Patterns - Batch 93
 * 
 * Feb 6, 2026 6:30 AM - Step Finance $40M Hack + arXiv Research + Sec3 2025 Final
 * Sources:
 * - Step Finance Treasury Breach (Feb 1, 2026) - $30-40M stolen via key compromise
 * - arXiv:2504.07419 "Exploring Vulnerabilities in Solana Smart Contracts" (Apr 2025)
 * - Sec3 2025 Final Report - 163 audits, 1,669 vulnerabilities (38.5% business logic)
 * - Certora Lulo Security Assessment - Oracle failures, referral exploits
 * - GetFailsafe Solana Audit Checklist 2025
 * - Accretion 80% Critical Discovery Research
 * 
 * Patterns: SOL5301-SOL5400
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

const BATCH_93_PATTERNS: PatternDef[] = [
  // ============================================
  // STEP FINANCE $40M TREASURY BREACH (Feb 1, 2026)
  // Pattern: Internal key compromise, single authority control
  // ============================================
  {
    id: 'SOL5301',
    name: 'Step Finance Pattern: Single Authority Treasury Control',
    severity: 'critical',
    pattern: /treasury|vault|fee_wallet[\s\S]{0,300}(?:authority|admin|owner)[\s\S]{0,100}(?!multisig|multi_sig|threshold|squad)/i,
    description: 'Step Finance $40M breach: Single authority controlled 260K+ SOL treasury. No multisig, no timelock. Attacker unstaked and transferred in minutes.',
    recommendation: 'Implement Squads multisig (3/5 minimum). Add 24-48h timelock for large withdrawals. Use hardware wallets for treasury keys.'
  },
  {
    id: 'SOL5302',
    name: 'Step Finance Pattern: No Unstaking Delay for Treasury',
    severity: 'critical',
    pattern: /unstake|undelegate[\s\S]{0,200}treasury[\s\S]{0,100}(?!delay|timelock|cooldown)/i,
    description: 'Step Finance attack: Attacker unstaked SOL immediately without any delay period. Treasury stake could be liquidated in single epoch.',
    recommendation: 'Implement mandatory cooldown period for treasury unstaking. Alert on any unstake initiation.'
  },
  {
    id: 'SOL5303',
    name: 'Step Finance Pattern: Fee Wallet Consolidation Risk',
    severity: 'high',
    pattern: /fee_wallet|fee_account|protocol_fees[\s\S]{0,200}(?:single|one|same)[\s\S]{0,100}(?:authority|key)/i,
    description: 'Step Finance had fee wallets controlled by same authority as treasury. Single key compromise drained everything.',
    recommendation: 'Separate fee collection from treasury management. Use different keys with role separation.'
  },
  {
    id: 'SOL5304',
    name: 'Step Finance Pattern: Missing Transaction Monitoring',
    severity: 'high',
    pattern: /treasury[\s\S]{0,200}(?:transfer|withdraw)[\s\S]{0,100}(?!alert|notify|webhook|monitor)/i,
    description: 'Step Finance attack executed during APAC hours with no automated alerts. Large transfers went undetected until too late.',
    recommendation: 'Implement real-time transaction monitoring via Helius/Shyft webhooks. Set alerts for transfers > 1% of treasury.'
  },
  {
    id: 'SOL5305',
    name: 'Step Finance Pattern: Internal Actor Key Access',
    severity: 'critical',
    pattern: /admin_key|authority_key|owner_key[\s\S]{0,200}(?:team|internal|employee|staff)/i,
    description: 'Step Finance breach likely from internal key exposure. "Well-known Solana attack vector" per official statement.',
    recommendation: 'Hardware wallet requirement for all admin keys. Key rotation every 90 days. Audit key access logs.'
  },

  // ============================================
  // arXiv:2504.07419 - ACADEMIC VULNERABILITY RESEARCH
  // Tab. 1: Major Attacks on Solana Smart Contracts
  // ============================================
  {
    id: 'SOL5306',
    name: 'arXiv Listing 1: Missing Signer Check in Admin Update',
    severity: 'critical',
    pattern: /update_admin|set_admin|change_admin[\s\S]{0,300}(?:pubkey|key)[\s\S]{0,100}(?!is_signer|\.signer|signer\s*==\s*true)/i,
    description: 'arXiv Listing 1 vulnerability: Admin update function checks account pubkey matches but not if account actually signed. Attacker passes admin pubkey as param, sets themselves as new admin.',
    recommendation: 'Always verify is_signer = true for privilege-changing operations. Use Anchor\'s Signer<\'info> constraint.'
  },
  {
    id: 'SOL5307',
    name: 'arXiv: Missing Owner Check for Account Data',
    severity: 'critical',
    pattern: /AccountInfo[\s\S]{0,200}unpack|deserialize[\s\S]{0,150}(?!owner\s*==|\.owner\.eq|check_owner)/i,
    description: 'arXiv 3.1.2: Contract deserializes account data without verifying AccountInfo::owner. Attacker can forge fake config account with arbitrary admin pubkey.',
    recommendation: 'Verify account.owner == program_id before deserializing. Use Anchor\'s Account<T> with owner constraint.'
  },
  {
    id: 'SOL5308',
    name: 'arXiv: Missing Rent-Exemption Check',
    severity: 'medium',
    pattern: /create_account|init[\s\S]{0,200}lamports[\s\S]{0,100}(?!rent\.minimum_balance|rent_exempt|is_exempt)/i,
    description: 'arXiv 3.1.3: Accounts without sufficient SOL for rent-exemption may be garbage collected. Critical account data could be lost.',
    recommendation: 'Use Rent::get()?.minimum_balance(space) to calculate required lamports. Verify is_rent_exempt before operations.'
  },
  {
    id: 'SOL5309',
    name: 'arXiv: Account Type Confusion (Conflation)',
    severity: 'critical',
    pattern: /Account|AccountInfo[\s\S]{0,300}deserialize[\s\S]{0,150}(?!discriminator|type_check|account_type)/i,
    description: 'arXiv 3.2.1: Different account types (User, Config, Vault) share same owner but no type check. Attacker passes wrong account type to exploit logic.',
    recommendation: 'Use 8-byte discriminators for all account types. Anchor provides this automatically with #[account].'
  },
  {
    id: 'SOL5310',
    name: 'arXiv: Cross-Instance Reinitialization Attack',
    severity: 'critical',
    pattern: /init|initialize[\s\S]{0,200}(?:state|config)[\s\S]{0,150}(?!is_initialized|initialized\s*==\s*false)/i,
    description: 'arXiv 3.2.2: Program can be reinitialized, overwriting existing state. Attacker reinitializes with malicious config after legitimate setup.',
    recommendation: 'Check is_initialized flag before any init operation. Use init constraint only once per account.'
  },

  // ============================================
  // arXiv Tab. 1: MAJOR SOLANA EXPLOIT PATTERNS
  // Historical attacks with specific amounts
  // ============================================
  {
    id: 'SOL5311',
    name: 'Solend $1.26M: Oracle Attack Pattern',
    severity: 'critical',
    pattern: /oracle|price_feed[\s\S]{0,200}(?:single|one)[\s\S]{0,100}(?!twap|aggregate|backup|fallback)/i,
    description: 'Solend Nov 2022 $1.26M: Single oracle manipulation crashed collateral prices. Flash loan + oracle attack drained lending pools.',
    recommendation: 'Require multiple oracle sources. Use TWAP with minimum sample period. Implement price band sanity checks.'
  },
  {
    id: 'SOL5312',
    name: 'Mango Markets $100M: Flash Loan Oracle Manipulation',
    severity: 'critical',
    pattern: /flash_loan|flashloan[\s\S]{0,300}(?:price|oracle|value)[\s\S]{0,150}(?!anti_flash|loan_check)/i,
    description: 'Mango Oct 2022 $100M: Flash loan manipulated MNGO price, borrowed against inflated collateral. Exploiter profit = protocol loss.',
    recommendation: 'Block price updates in same transaction as borrowing. Require time-delay between price change and leverage.'
  },
  {
    id: 'SOL5313',
    name: 'Tulip/UXD $22.5M: Mango Attack Cascade',
    severity: 'high',
    pattern: /mango|tulip|uxd[\s\S]{0,200}dependency[\s\S]{0,100}(?!isolation|independent)/i,
    description: 'Oct 2022: Tulip $2.5M and UXD $20M were Mango-dependent. When Mango exploited, dependent protocols crashed.',
    recommendation: 'Avoid single-protocol dependencies. Implement circuit breakers for external protocol failures.'
  },
  {
    id: 'SOL5314',
    name: 'OptiFi $661K: Accidental Program Close',
    severity: 'critical',
    pattern: /close|close_program|close_account[\s\S]{0,200}(?:admin|authority)[\s\S]{0,100}(?!confirm|require.*yes)/i,
    description: 'OptiFi Aug 2022: Accidental close_program called by admin locked $661K permanently. No confirmation step.',
    recommendation: 'Two-step confirmation for destructive operations. 24h timelock for program modifications. Backup deploy authority.'
  },
  {
    id: 'SOL5315',
    name: 'Nirvana $3.5M: Flash Loan Bonding Curve Attack',
    severity: 'critical',
    pattern: /bonding_curve|bond_curve[\s\S]{0,200}(?:price|rate)[\s\S]{0,100}(?!flash_guard|same_slot)/i,
    description: 'Nirvana Jul 2022: Flash loan manipulated bonding curve, minted tokens at manipulated rate, drained treasury.',
    recommendation: 'Implement flash loan guards on bonding curves. Block curve manipulation in same slot as minting.'
  },
  {
    id: 'SOL5316',
    name: 'Crema $1.68M: Flash Loan CLMM Attack',
    severity: 'high',
    pattern: /clmm|concentrated_liquidity[\s\S]{0,200}flash[\s\S]{0,100}(?!atomic_check|loan_guard)/i,
    description: 'Crema Jul 2022: Flash loan attack on concentrated liquidity pools. Fake tick account allowed fee extraction.',
    recommendation: 'Validate tick accounts against Merkle tree. Prevent flash loan operations across ticks.'
  },
  {
    id: 'SOL5317',
    name: 'Jet Protocol: Unknown Vulnerability Pattern',
    severity: 'high',
    pattern: /jet|lending_market[\s\S]{0,200}(?:borrow|withdraw)[\s\S]{0,100}(?!rate_limit|max_borrow)/i,
    description: 'Jet Protocol Mar 2022: Unspecified vulnerability in lending logic. Pattern: unlimited borrow without proper collateral checks.',
    recommendation: 'Strict collateral-to-debt ratio enforcement. Real-time position monitoring with automatic liquidation.'
  },
  {
    id: 'SOL5318',
    name: 'Cashio $52M: Unverified Account Bypass',
    severity: 'critical',
    pattern: /mint|token_mint[\s\S]{0,200}(?:collateral|backing)[\s\S]{0,100}(?!verify|validate|whitelist)/i,
    description: 'Cashio Mar 2022 $52M: Attacker bypassed account verification to mint unlimited stablecoin with fake collateral.',
    recommendation: 'Whitelist valid collateral mints. Verify full account chain before minting. Use PDAs for collateral accounts.'
  },
  {
    id: 'SOL5319',
    name: 'Wormhole $320M: Deprecated Function Signature Forge',
    severity: 'critical',
    pattern: /verify_signatures|guardian[\s\S]{0,300}(?:deprecated|old_version)[\s\S]{0,100}/i,
    description: 'Wormhole Feb 2022 $120K ETH: Deprecated solana_program function allowed forged guardian signatures. Largest Solana exploit.',
    recommendation: 'Remove deprecated function calls immediately. Pin SDK versions. Audit all cross-program invocations.'
  },

  // ============================================
  // SEC3 2025 FINAL REPORT - 163 AUDITS, 1,669 VULNS
  // Top vulnerability categories with real percentages
  // ============================================
  {
    id: 'SOL5320',
    name: 'Sec3 2025: Business Logic Invariant Violation (38.5%)',
    severity: 'high',
    pattern: /(?:state|status|phase)[\s\S]{0,200}(?:transition|change|update)[\s\S]{0,100}(?!invariant|assert_eq|check_state)/i,
    description: 'Sec3 2025: 38.5% of vulnerabilities were business logic flaws. State transitions without invariant verification.',
    recommendation: 'Document and enforce all state machine invariants. Use assert! macros for critical state assumptions.'
  },
  {
    id: 'SOL5321',
    name: 'Sec3 2025: Input Validation Missing (25%)',
    severity: 'high',
    pattern: /fn\s+\w+[\s\S]{0,100}\([\s\S]{0,200}(?:amount|value|rate|price)[\s\S]{0,100}(?!require!|assert!|validate)/i,
    description: 'Sec3 2025: 25% of findings were input validation failures. User input passed directly to critical operations.',
    recommendation: 'Validate all numeric inputs for bounds (min/max). Reject zero amounts. Sanitize string inputs.'
  },
  {
    id: 'SOL5322',
    name: 'Sec3 2025: Access Control Failure (19%)',
    severity: 'critical',
    pattern: /(?:admin|owner|authority)[\s\S]{0,200}(?:instruction|fn)[\s\S]{0,100}(?!has_one|constraint.*=|require.*signer)/i,
    description: 'Sec3 2025: 19% were access control failures. Privilege escalation via missing authority checks.',
    recommendation: 'Use Anchor\'s has_one constraint for all authority checks. Implement role-based access control.'
  },
  {
    id: 'SOL5323',
    name: 'Sec3 2025: Data Integrity Arithmetic (8.9%)',
    severity: 'high',
    pattern: /[\+\-\*\/]\s*(?:amount|balance|supply)[\s\S]{0,50}(?!checked_|saturating_|safe_)/i,
    description: 'Sec3 2025: 8.9% were arithmetic/data integrity issues. Overflow, underflow, precision loss.',
    recommendation: 'Use checked_* or saturating_* math operations. Never use raw arithmetic on financial values.'
  },
  {
    id: 'SOL5324',
    name: 'Sec3 2025: DoS/Liveness Attack (8.5%)',
    severity: 'medium',
    pattern: /for\s*.*\s*in\s*\d+\.\.[\s\S]{0,100}(?:accounts|items|users)[\s\S]{0,50}(?!\.len\(\)\s*<|max_iter)/i,
    description: 'Sec3 2025: 8.5% were DoS/liveness risks. Unbounded loops, compute budget exhaustion.',
    recommendation: 'Bound all loops with maximum iterations. Paginate large operations. Monitor compute unit usage.'
  },
  {
    id: 'SOL5325',
    name: 'Sec3 2025: 76% of Audits Had Medium+ Issues',
    severity: 'info',
    pattern: /audit|security_review[\s\S]{0,100}(?:passed|clean|no_issues)/i,
    description: 'Sec3 2025: 76% of 163 audits found medium-or-higher vulnerabilities. 51% had high+, 23% had critical.',
    recommendation: 'Multiple audit rounds recommended. Use automated tools (Soteria, Trident) before manual audit.'
  },

  // ============================================
  // CERTORA LULO SECURITY ASSESSMENT PATTERNS
  // Real audit findings from formal verification
  // ============================================
  {
    id: 'SOL5326',
    name: 'Certora Lulo: Oracle Update Failure Handling',
    severity: 'critical',
    pattern: /oracle[\s\S]{0,200}(?:get_price|fetch)[\s\S]{0,100}(?!fallback|stale_check|try.*catch)/i,
    description: 'Certora Lulo audit: Protocol failed to handle oracle update failures gracefully. Stale prices used for critical operations.',
    recommendation: 'Implement staleness checks on all oracle reads. Define fallback pricing mechanisms. Pause on oracle failure.'
  },
  {
    id: 'SOL5327',
    name: 'Certora Lulo: Referral Fee Exploit',
    severity: 'high',
    pattern: /referral_fee|ref_fee|affiliate[\s\S]{0,200}(?!cap|max|limit|\%\s*<)/i,
    description: 'Certora Lulo audit: Uncapped referral fees could drain protocol treasury. Self-referral loop extracted value.',
    recommendation: 'Cap referral fees at reasonable percentage (1-5%). Prevent self-referral patterns. Time-delay large payouts.'
  },
  {
    id: 'SOL5328',
    name: 'Certora Lulo: Withdrawal Rate Manipulation',
    severity: 'critical',
    pattern: /withdraw[\s\S]{0,200}(?:rate|ratio|exchange)[\s\S]{0,100}(?!snapshot|block|same_slot)/i,
    description: 'Certora Lulo audit: Withdrawal exchange rate could be manipulated within same transaction.',
    recommendation: 'Snapshot exchange rates at start of epoch/block. Prevent rate updates and withdrawals in same transaction.'
  },

  // ============================================
  // GETFAILSAFE SOLANA AUDIT CHECKLIST 2025
  // Common vulnerability patterns from audit experience
  // ============================================
  {
    id: 'SOL5329',
    name: 'GetFailsafe: Improper Account Type Validation',
    severity: 'critical',
    pattern: /Account<[\s\S]{0,50}>[\s\S]{0,100}(?!constraint\s*=|#\[account\(.*check)/i,
    description: 'GetFailsafe 2025: Improper validation of account types leads to type confusion attacks.',
    recommendation: 'Use Anchor\'s Account<T> with explicit constraints. Add discriminator checks for all custom types.'
  },
  {
    id: 'SOL5330',
    name: 'GetFailsafe: PDA Seed Collision Risk',
    severity: 'high',
    pattern: /Pubkey::find_program_address[\s\S]{0,100}(?:seeds|seed)[\s\S]{0,50}(?!.*unique|.*user_|.*mint_)/i,
    description: 'GetFailsafe 2025: Non-unique PDA seeds allow cross-user account manipulation.',
    recommendation: 'Include unique identifiers (user pubkey, mint, timestamp) in PDA seeds. Use canonical bump.'
  },
  {
    id: 'SOL5331',
    name: 'GetFailsafe: CPI Privilege Escalation',
    severity: 'critical',
    pattern: /invoke_signed|invoke[\s\S]{0,200}(?:program_id|target)[\s\S]{0,100}(?!whitelist|allowed_programs)/i,
    description: 'GetFailsafe 2025: Unrestricted CPI targets allow privilege escalation via malicious programs.',
    recommendation: 'Whitelist allowed CPI targets. Validate program_id before any invoke. Use CPI guards.'
  },

  // ============================================
  // ACCRETION SECURITY RESEARCH (80% CRITICAL)
  // Patterns from their 80% critical discovery rate
  // ============================================
  {
    id: 'SOL5332',
    name: 'Accretion: Authority Transfer Without Timelock',
    severity: 'critical',
    pattern: /(?:set|change|update)_authority[\s\S]{0,200}(?!timelock|delay|pending_)/i,
    description: 'Accretion research: Immediate authority transfers enable instant protocol takeover. No time for community response.',
    recommendation: 'Implement 24-72h timelock for authority changes. Emit events on transfer initiation. Allow cancellation.'
  },
  {
    id: 'SOL5333',
    name: 'Accretion: Missing Emergency Pause Mechanism',
    severity: 'high',
    pattern: /(?:swap|transfer|withdraw|deposit)[\s\S]{0,300}(?!paused|is_paused|emergency_stop)/i,
    description: 'Accretion research: Protocols without pause mechanisms cannot stop exploits in progress.',
    recommendation: 'Implement pausable pattern for all critical operations. Guardian role for emergency pause.'
  },
  {
    id: 'SOL5334',
    name: 'Accretion: Precision Loss in Financial Calculations',
    severity: 'high',
    pattern: /(?:div|\/)\s*[\d_]+[\s\S]{0,50}(?:mul|\*)[\s\S]{0,30}(?!scale|precision|decimal)/i,
    description: 'Accretion research: Division before multiplication loses precision. Rounding errors compound over time.',
    recommendation: 'Multiply before divide. Use scaled integers (1e18). Apply rounding in favor of protocol.'
  },

  // ============================================
  // ADVANCED DEFI PATTERNS 2026
  // New attack vectors emerging in current ecosystem
  // ============================================
  {
    id: 'SOL5335',
    name: 'JIT Liquidity Sandwich Attack',
    severity: 'high',
    pattern: /add_liquidity[\s\S]{0,200}(?:same_slot|atomic)[\s\S]{0,100}(?!time_weighted|min_duration)/i,
    description: 'JIT liquidity providers add/remove in same slot, sandwiching regular traders. MEV extraction at user expense.',
    recommendation: 'Implement minimum liquidity duration. Use time-weighted LP rewards. Block single-slot LP cycles.'
  },
  {
    id: 'SOL5336',
    name: 'Perpetual Funding Rate Manipulation',
    severity: 'high',
    pattern: /funding_rate|perp_rate[\s\S]{0,200}(?:calculate|compute)[\s\S]{0,100}(?!cap|max|clamp)/i,
    description: 'Uncapped funding rates can drain one side of perpetual positions. Whales manipulate rates for extraction.',
    recommendation: 'Cap funding rates at reasonable levels (0.1%/8h max). Use TWAP for rate calculation.'
  },
  {
    id: 'SOL5337',
    name: 'Cross-Margin Cascade Liquidation',
    severity: 'critical',
    pattern: /cross_margin|portfolio_margin[\s\S]{0,200}liquidat[\s\S]{0,100}(?!circuit_breaker|cascade_limit)/i,
    description: 'Cross-margin liquidations cascade across positions. Single price spike can wipe entire portfolio.',
    recommendation: 'Implement per-position isolation limits. Circuit breakers on rapid liquidation cascades.'
  },
  {
    id: 'SOL5338',
    name: 'Vault First Depositor Share Inflation',
    severity: 'critical',
    pattern: /deposit[\s\S]{0,100}total_supply\s*==\s*0[\s\S]{0,100}(?!initial_shares|dead_shares|minimum)/i,
    description: 'First depositor can manipulate share price by depositing dust then donating tokens. Later depositors get minimal shares.',
    recommendation: 'Mint dead shares on vault creation. Require minimum first deposit. Use virtual offset.'
  },
  {
    id: 'SOL5339',
    name: 'Token-2022 Transfer Hook Reentrancy',
    severity: 'critical',
    pattern: /transfer_hook|TransferHook[\s\S]{0,200}(?:invoke|call)[\s\S]{0,100}(?!reentrancy_guard|nonreentrant)/i,
    description: 'Token-2022 transfer hooks can trigger reentrancy via malicious hook programs. Classic reentrancy in new form.',
    recommendation: 'Implement reentrancy guards on all hook-triggering operations. Validate hook program IDs.'
  },
  {
    id: 'SOL5340',
    name: 'Compressed NFT Merkle Proof Verification',
    severity: 'high',
    pattern: /verify_proof|merkle_proof[\s\S]{0,200}(?:leaf|hash)[\s\S]{0,100}(?!canonical|root_check)/i,
    description: 'cNFT proofs can be forged without proper verification. Malicious leaf data accepted with valid proof.',
    recommendation: 'Verify proof against canonical tree root. Check leaf data hash matches expected. Use Bubblegum standards.'
  },

  // ============================================
  // TOKEN-2022 EXTENSION SECURITY
  // New extension-specific vulnerabilities
  // ============================================
  {
    id: 'SOL5341',
    name: 'Token-2022: Permanent Delegate Abuse',
    severity: 'critical',
    pattern: /permanent_delegate|PermanentDelegate[\s\S]{0,100}(?!user_consent|warning|opt_in)/i,
    description: 'Permanent delegate extension allows token issuer to transfer user tokens forever. Hidden rug pull mechanism.',
    recommendation: 'Warn users about permanent delegate before accepting tokens. Check extension on token receive.'
  },
  {
    id: 'SOL5342',
    name: 'Token-2022: Interest-Bearing Manipulation',
    severity: 'high',
    pattern: /interest_bearing|InterestBearing[\s\S]{0,200}(?:rate|update)[\s\S]{0,100}(?!cap|max_rate|governance)/i,
    description: 'Interest-bearing token rate can be manipulated by issuer. Sudden rate changes affect holder value.',
    recommendation: 'Cap maximum interest rate changes. Require governance for rate updates. Time-delay large changes.'
  },
  {
    id: 'SOL5343',
    name: 'Token-2022: Confidential Transfer Privacy Leak',
    severity: 'medium',
    pattern: /confidential_transfer|ConfidentialTransfer[\s\S]{0,200}(?!zk_verify|proof_check)/i,
    description: 'Confidential transfers with improper ZK proof verification leak transaction details.',
    recommendation: 'Use official Confidential Transfer SDK. Verify all ZK proofs before accepting. Audit proof circuits.'
  },
  {
    id: 'SOL5344',
    name: 'Token-2022: Transfer Fee Misconfiguration',
    severity: 'high',
    pattern: /transfer_fee|TransferFeeConfig[\s\S]{0,200}(?:maximum_fee|basis_points)[\s\S]{0,100}(?!cap|limit)/i,
    description: 'Transfer fees can be set extremely high, effectively freezing tokens. Hidden fee trap.',
    recommendation: 'Check transfer fee configuration before accepting tokens. Reject tokens with >5% fees. Display fee warnings.'
  },
  {
    id: 'SOL5345',
    name: 'Token-2022: Non-Transferable Token Logic Bypass',
    severity: 'high',
    pattern: /non_transferable|NonTransferable[\s\S]{0,200}(?:burn|close)[\s\S]{0,100}(?!restrict|prevent)/i,
    description: 'Non-transferable tokens can still be burned and value extracted via wrapping mechanisms.',
    recommendation: 'Implement burn restrictions on non-transferable tokens. Prevent wrapping into transferable form.'
  },

  // ============================================
  // GOVERNANCE & DAO SECURITY
  // Patterns from 2025-2026 governance attacks
  // ============================================
  {
    id: 'SOL5346',
    name: 'Flash Loan Governance Attack',
    severity: 'critical',
    pattern: /vote|proposal[\s\S]{0,200}(?:token|power)[\s\S]{0,100}(?!snapshot|checkpoint|lock_period)/i,
    description: 'Flash loan tokens to gain voting power, pass proposal in same transaction. Audius-style governance takeover.',
    recommendation: 'Require token lock period before voting. Snapshot voting power at proposal creation. Block same-slot votes.'
  },
  {
    id: 'SOL5347',
    name: 'Low Quorum DAO Drain',
    severity: 'high',
    pattern: /quorum[\s\S]{0,100}(?:\d{1,2}|percentage)[\s\S]{0,100}(?!minimum_tokens|require)/i,
    description: 'Low quorum thresholds enable minority treasury drain. Saga DAO lost $1.5M to low-quorum attack.',
    recommendation: 'Set minimum quorum at 10%+ of circulating supply. Require higher quorum for treasury actions.'
  },
  {
    id: 'SOL5348',
    name: 'Proposal Timelock Bypass',
    severity: 'critical',
    pattern: /execute_proposal|run_proposal[\s\S]{0,200}(?!timelock|delay|wait_period)/i,
    description: 'Proposals executed immediately without timelock. No time for community to detect malicious proposals.',
    recommendation: 'Minimum 48-72h timelock on all proposals. Allow proposal cancellation during timelock period.'
  },
  {
    id: 'SOL5349',
    name: 'Vote Buying via Delegation',
    severity: 'medium',
    pattern: /delegate|delegation[\s\S]{0,200}(?:vote|voting)[\s\S]{0,100}(?!restrict|whitelist|verify)/i,
    description: 'Unrestricted delegation enables vote buying markets. Centralization of governance power.',
    recommendation: 'Implement delegation limits. Require identity verification for large delegations. Track delegation chains.'
  },
  {
    id: 'SOL5350',
    name: 'Emergency Proposal Abuse',
    severity: 'high',
    pattern: /emergency|urgent[\s\S]{0,100}proposal[\s\S]{0,100}(?!multisig|guardian|threshold)/i,
    description: 'Emergency proposal mechanisms bypassed normal governance. Used for illegitimate fast-track.',
    recommendation: 'Require guardian multisig for emergency actions. Limit scope of emergency powers. Audit all uses.'
  },

  // ============================================
  // BRIDGE & CROSS-CHAIN SECURITY
  // Patterns from Wormhole and other bridge attacks
  // ============================================
  {
    id: 'SOL5351',
    name: 'Guardian Signature Quorum Insufficient',
    severity: 'critical',
    pattern: /guardian|validator[\s\S]{0,200}(?:signature|sig)[\s\S]{0,100}(?!threshold|quorum|minimum.*\d+\/\d+)/i,
    description: 'Wormhole $326M: Insufficient guardian quorum validation allowed forged messages. Single point of failure.',
    recommendation: 'Require 2/3+ guardian signatures. Verify each signature individually. Reject duplicate guardian sigs.'
  },
  {
    id: 'SOL5352',
    name: 'VAA Message Replay Attack',
    severity: 'critical',
    pattern: /vaa|message[\s\S]{0,200}(?:verify|validate)[\s\S]{0,100}(?!nonce|sequence|replay_check)/i,
    description: 'Bridge messages replayed multiple times for duplicate minting. No sequence/nonce checking.',
    recommendation: 'Track message sequences. Reject already-processed messages. Use unique nonces per bridge operation.'
  },
  {
    id: 'SOL5353',
    name: 'Cross-Chain Decimal Mismatch',
    severity: 'high',
    pattern: /(?:eth|ethereum|polygon|bsc)[\s\S]{0,100}(?:decimals?|precision)[\s\S]{0,100}(?!convert|normalize)/i,
    description: 'Token decimals differ across chains (18 on ETH, 9 on Solana). Mismatch causes value errors.',
    recommendation: 'Normalize all token amounts to common precision. Store original decimals. Validate on bridge both sides.'
  },
  {
    id: 'SOL5354',
    name: 'Finality Assumption Violation',
    severity: 'high',
    pattern: /block|transaction[\s\S]{0,100}(?:confirm|final)[\s\S]{0,100}(?!wait|minimum_confirmations)/i,
    description: 'Bridging before source chain finality allows double-spend. Reorgs can reverse source transaction.',
    recommendation: 'Wait for source chain finality (31 blocks Solana, 12 blocks ETH 2.0). Never bridge on unconfirmed tx.'
  },
  {
    id: 'SOL5355',
    name: 'Wrapped Token Backing Mismatch',
    severity: 'critical',
    pattern: /wrapped|bridged[\s\S]{0,200}(?:mint|supply)[\s\S]{0,100}(?!backing_check|reserve_match)/i,
    description: 'Wrapped token supply exceeds backing on source chain. Unbacked tokens cause insolvency on redemption.',
    recommendation: 'Verify 1:1 backing before minting wrapped tokens. Implement reserve audits. Pause on backing gap.'
  },

  // ============================================
  // NFT & GAMING SECURITY
  // Metaplex and gaming-specific patterns
  // ============================================
  {
    id: 'SOL5356',
    name: 'Metadata URI Mutability Attack',
    severity: 'high',
    pattern: /metadata[\s\S]{0,100}(?:uri|url)[\s\S]{0,100}(?:mut|update)[\s\S]{0,50}(?!immutable|freeze)/i,
    description: 'Mutable metadata URI allows rug pull. Issuer changes image/attributes after sale.',
    recommendation: 'Freeze metadata after mint. Use on-chain metadata or IPFS (immutable). Display mutability warnings.'
  },
  {
    id: 'SOL5357',
    name: 'Creator Royalty Bypass',
    severity: 'medium',
    pattern: /royalt(?:y|ies)[\s\S]{0,200}(?:pay|fee)[\s\S]{0,100}(?!enforce|require|standard)/i,
    description: 'Royalties can be bypassed via OTC transfers or royalty-free marketplaces. Creator revenue lost.',
    recommendation: 'Use Token-2022 transfer hooks for enforced royalties. Implement allowlist for royalty-respecting platforms.'
  },
  {
    id: 'SOL5358',
    name: 'Collection Verification Bypass',
    severity: 'high',
    pattern: /collection[\s\S]{0,100}(?:verify|verified)[\s\S]{0,100}(?!check|require|assert)/i,
    description: 'Fake NFTs claiming verified collection membership. Buyers deceived by false collection association.',
    recommendation: 'Verify collection on-chain via Metaplex certified collections. Check creator signatures. Display verification status.'
  },
  {
    id: 'SOL5359',
    name: 'On-Chain Randomness for Gaming',
    severity: 'high',
    pattern: /random|rng[\s\S]{0,100}(?:slot|block|hash)[\s\S]{0,100}(?!vrf|switchboard|pyth)/i,
    description: 'On-chain randomness from slots/hashes is predictable. Validators can manipulate outcomes.',
    recommendation: 'Use Switchboard VRF or Pyth Entropy for verifiable randomness. Commit-reveal for time-delayed outcomes.'
  },
  {
    id: 'SOL5360',
    name: 'Game Asset Duplication Exploit',
    severity: 'critical',
    pattern: /game_item|asset[\s\S]{0,200}(?:mint|create)[\s\S]{0,100}(?!unique_check|exists)/i,
    description: 'Duplicate game assets minted via race condition or validation gap. Economy inflation.',
    recommendation: 'Use PDAs with unique seeds per asset. Verify non-existence before creation. Atomic mint operations.'
  },

  // ============================================
  // LENDING PROTOCOL SECURITY
  // DeFi lending-specific patterns
  // ============================================
  {
    id: 'SOL5361',
    name: 'First Depositor Share Inflation Attack',
    severity: 'critical',
    pattern: /deposit[\s\S]{0,200}(?:shares|tokens)[\s\S]{0,100}(?:total\s*==\s*0|first_deposit)[\s\S]{0,50}(?!virtual|offset|min_deposit)/i,
    description: 'First depositor deposits 1 wei, donates tokens, inflates share price. Later depositors get dust shares.',
    recommendation: 'Mint virtual shares to dead address on pool creation. Require minimum first deposit. Use share offset.'
  },
  {
    id: 'SOL5362',
    name: 'Bad Debt Socialization Risk',
    severity: 'high',
    pattern: /liquidat[\s\S]{0,200}(?:debt|loss)[\s\S]{0,100}(?!insurance|reserve|backstop)/i,
    description: 'Underwater positions create bad debt socialized to depositors. No insurance fund protection.',
    recommendation: 'Maintain insurance fund for bad debt. Aggressive liquidation thresholds. Reserve fund from protocol fees.'
  },
  {
    id: 'SOL5363',
    name: 'Interest Rate Model Manipulation',
    severity: 'high',
    pattern: /interest_rate|borrow_rate[\s\S]{0,200}(?:calculate|compute)[\s\S]{0,100}(?!cap|max|clamp)/i,
    description: 'Extreme utilization manipulation causes rate spikes. Depositors or borrowers griefed via rate manipulation.',
    recommendation: 'Cap maximum interest rates. Use smooth rate curves. Implement rate change limits per epoch.'
  },
  {
    id: 'SOL5364',
    name: 'Collateral Factor Misconfiguration',
    severity: 'high',
    pattern: /collateral_factor|ltv[\s\S]{0,200}(?:set|update)[\s\S]{0,100}(?!governance|timelock)/i,
    description: 'Collateral factor changed without timelock. Existing positions suddenly underwater and liquidated.',
    recommendation: 'Timelock all parameter changes. Grandfather existing positions. Provide exit window on parameter changes.'
  },
  {
    id: 'SOL5365',
    name: 'Borrow Cap Exhaustion Attack',
    severity: 'medium',
    pattern: /borrow[\s\S]{0,100}(?:limit|cap|max)[\s\S]{0,100}(?!per_user|rate_limit)/i,
    description: 'Global borrow caps exhausted by single user. Legitimate borrowers locked out.',
    recommendation: 'Implement per-user borrow limits. Reserve portion of cap for diverse borrowers. Anti-monopoly mechanisms.'
  },

  // ============================================
  // AMM & DEX SECURITY
  // Orca, Raydium, and AMM-specific patterns
  // ============================================
  {
    id: 'SOL5366',
    name: 'AMM K-Invariant Violation',
    severity: 'critical',
    pattern: /(?:x|reserve_a)[\s\S]{0,20}\*[\s\S]{0,20}(?:y|reserve_b)[\s\S]{0,100}(?!invariant_check|k_check)/i,
    description: 'x*y=k invariant not verified after operations. Pool drained via invariant-breaking trades.',
    recommendation: 'Verify k-invariant before and after every swap. Reject transactions that decrease k.'
  },
  {
    id: 'SOL5367',
    name: 'CLMM Tick Crossing Exploitation',
    severity: 'high',
    pattern: /tick[\s\S]{0,100}(?:cross|transition)[\s\S]{0,100}(?!verify|range_check)/i,
    description: 'Concentrated liquidity tick crossing manipulated. Crema-style fee extraction via fake ticks.',
    recommendation: 'Verify tick accounts against pool state. Use Merkle proofs for tick validation. Check tick spacing.'
  },
  {
    id: 'SOL5368',
    name: 'LP Share Price Manipulation',
    severity: 'high',
    pattern: /lp_price|share_price[\s\S]{0,200}(?:reserve|balance)[\s\S]{0,100}(?!twap|time_weighted)/i,
    description: 'LP share price calculated from spot reserves is manipulable. Flash loan attacks on LP pricing.',
    recommendation: 'Use TWAP for LP pricing. Implement manipulation resistance. Check price deviation from oracle.'
  },
  {
    id: 'SOL5369',
    name: 'Fee Tier Arbitrage',
    severity: 'medium',
    pattern: /fee_tier|pool_fee[\s\S]{0,200}(?:swap|route)[\s\S]{0,100}(?!optimal_path)/i,
    description: 'Multiple fee tiers exploited for arbitrage at LPs expense. Toxic flow routed to wrong tier.',
    recommendation: 'Dynamic fee adjustment based on volatility. JIT liquidity detection. Flow toxicity analysis.'
  },
  {
    id: 'SOL5370',
    name: 'Virtual Reserve Manipulation',
    severity: 'high',
    pattern: /virtual|amplified[\s\S]{0,100}(?:reserve|liquidity)[\s\S]{0,100}(?!concentration_check)/i,
    description: 'Virtual reserves in stableswap pools manipulated. Amplification factor exploitation.',
    recommendation: 'Validate virtual reserve calculations. Limit A-factor changes. Ramp A slowly with timelock.'
  },

  // ============================================
  // STAKING PROTOCOL SECURITY
  // LST and staking-specific patterns
  // ============================================
  {
    id: 'SOL5371',
    name: 'Stake Pool Commission Manipulation',
    severity: 'high',
    pattern: /commission|fee[\s\S]{0,100}stake_pool[\s\S]{0,100}(?!cap|max|governance)/i,
    description: 'Stake pool operator raises commission suddenly. Stakers receive reduced yield without warning.',
    recommendation: 'Cap maximum commission. Require advance notice for changes. Implement commission ramp.'
  },
  {
    id: 'SOL5372',
    name: 'Instant Unstake Exploitation',
    severity: 'high',
    pattern: /instant_unstake|immediate_withdraw[\s\S]{0,200}(?!fee_check|penalty|rate_limit)/i,
    description: 'Instant unstake at favorable rate during market stress. Pool drained of liquid SOL.',
    recommendation: 'Dynamic instant unstake fees based on pool liquidity. Rate limit unstakes. Maintain liquid buffer.'
  },
  {
    id: 'SOL5373',
    name: 'Stake Reward Rate Manipulation',
    severity: 'medium',
    pattern: /stake_reward|reward_rate[\s\S]{0,200}(?:update|set)[\s\S]{0,100}(?!epoch_boundary|sync)/i,
    description: 'Reward rate manipulated between epochs. Front-running reward distribution.',
    recommendation: 'Sync reward updates to epoch boundaries. Snapshot stake balances for rewards. Time-lock rate changes.'
  },
  {
    id: 'SOL5374',
    name: 'Validator Slashing Cascade',
    severity: 'high',
    pattern: /slash|penalty[\s\S]{0,200}validator[\s\S]{0,100}(?!distribute|cap|limit)/i,
    description: 'Slashing events cascade through stake pools. Undercollateralized LST causes panic.',
    recommendation: 'Maintain slashing insurance fund. Diversify validator set. Cap per-validator stake.'
  },
  {
    id: 'SOL5375',
    name: 'Epoch Boundary Race Condition',
    severity: 'medium',
    pattern: /epoch[\s\S]{0,100}(?:transition|boundary)[\s\S]{0,100}(?!sync|atomic)/i,
    description: 'Operations straddling epoch boundary cause accounting errors. Double-counting or missing rewards.',
    recommendation: 'Atomic epoch transition handling. Queue operations across boundaries. Verify epoch before operations.'
  },

  // ============================================
  // INFRASTRUCTURE & RPC SECURITY
  // Network and infrastructure patterns
  // ============================================
  {
    id: 'SOL5376',
    name: 'RPC Endpoint Trust Issue',
    severity: 'high',
    pattern: /rpc|endpoint[\s\S]{0,100}(?:url|host)[\s\S]{0,100}(?!verify|signature|trusted)/i,
    description: 'Untrusted RPC can return false data. Simulation responses manipulated to deceive users.',
    recommendation: 'Use multiple RPC sources. Verify critical data on-chain. Cross-reference transaction results.'
  },
  {
    id: 'SOL5377',
    name: 'Blockhash Expiry Exploitation',
    severity: 'medium',
    pattern: /recent_blockhash|blockhash[\s\S]{0,100}(?!valid|fresh|check_expiry)/i,
    description: 'Expired blockhash causes transaction failure. Attacker griefs users by delaying transaction submission.',
    recommendation: 'Use durable nonces for critical transactions. Refresh blockhash before signing. Set appropriate expiry.'
  },
  {
    id: 'SOL5378',
    name: 'Lookup Table Poisoning',
    severity: 'high',
    pattern: /address_lookup|lookup_table[\s\S]{0,200}(?!verify_owner|trusted_tables)/i,
    description: 'Malicious lookup tables substitute program addresses. User signs transaction calling wrong program.',
    recommendation: 'Verify lookup table ownership. Use trusted table addresses only. Display resolved addresses before signing.'
  },
  {
    id: 'SOL5379',
    name: 'Priority Fee Griefing',
    severity: 'medium',
    pattern: /priority_fee|compute_unit_price[\s\S]{0,100}(?!dynamic|adjust)/i,
    description: 'Spam transactions with high priority fees to price out legitimate users. Network congestion attack.',
    recommendation: 'Use dynamic priority fees based on recent network conditions. Implement fee caps. Retry logic with backoff.'
  },
  {
    id: 'SOL5380',
    name: 'Program Upgrade Without Notice',
    severity: 'high',
    pattern: /upgrade|deploy[\s\S]{0,100}(?:program|buffer)[\s\S]{0,100}(?!timelock|announce|governance)/i,
    description: 'Program upgraded without user notice. Malicious upgrade changes behavior mid-operation.',
    recommendation: 'Timelock program upgrades. Announce upgrades in advance. Consider immutable deployments for critical logic.'
  },

  // ============================================
  // WALLET & KEY SECURITY
  // Key management patterns from DEXX, Slope exploits
  // ============================================
  {
    id: 'SOL5381',
    name: 'DEXX Pattern: Centralized Key Storage',
    severity: 'critical',
    pattern: /private_key|secret_key[\s\S]{0,100}(?:store|save|database)[\s\S]{0,100}(?!encrypt|hardware|hsm)/i,
    description: 'DEXX $30M: Centralized storage of user private keys. Database breach exposed all keys.',
    recommendation: 'Never store user private keys. Use MPC or threshold signatures. Hardware wallet integration.'
  },
  {
    id: 'SOL5382',
    name: 'Slope Wallet Pattern: Seed Phrase Logging',
    severity: 'critical',
    pattern: /seed|mnemonic[\s\S]{0,100}(?:log|print|send|transmit)[\s\S]{0,100}(?!redact|mask)/i,
    description: 'Slope $8M: Seed phrases logged to Sentry telemetry. Attackers accessed logging service.',
    recommendation: 'Never log sensitive data. Redact all key material. Audit all telemetry endpoints.'
  },
  {
    id: 'SOL5383',
    name: 'Hot Wallet Excessive Balance',
    severity: 'high',
    pattern: /hot_wallet|operational_wallet[\s\S]{0,200}(?:balance|amount)[\s\S]{0,100}(?!limit|threshold|sweep)/i,
    description: 'Hot wallets holding more than needed for operations. Single compromise exposes all funds.',
    recommendation: 'Minimum operational balance in hot wallets. Auto-sweep to cold storage. Define balance limits.'
  },
  {
    id: 'SOL5384',
    name: 'Key Rotation Not Implemented',
    severity: 'medium',
    pattern: /authority|admin_key[\s\S]{0,200}(?!rotate|rotation|expire|refresh)/i,
    description: 'Static keys never rotated. Compromised key remains valid indefinitely.',
    recommendation: 'Implement key rotation schedules (90 days). Support multiple valid keys during transition. Log all key usage.'
  },
  {
    id: 'SOL5385',
    name: 'Transaction Signing Without Display',
    severity: 'high',
    pattern: /sign|signature[\s\S]{0,100}(?:transaction|tx)[\s\S]{0,100}(?!display|show|human_readable)/i,
    description: 'Transactions signed without human-readable display. Users sign malicious transactions unknowingly.',
    recommendation: 'Display all transaction details before signing. Parse instructions to human-readable form. Warn on unusual operations.'
  },

  // ============================================
  // AI AGENT SECURITY (2026 EMERGING)
  // Patterns for AI-controlled wallets
  // ============================================
  {
    id: 'SOL5386',
    name: 'AI Agent Wallet: Unlimited Spending',
    severity: 'critical',
    pattern: /(?:ai_|agent_|bot_)[\s\S]{0,50}(?:wallet|account)[\s\S]{0,100}(?!limit|allowance|cap)/i,
    description: 'AI agents with unlimited wallet access. Compromised or malfunctioning AI drains all funds.',
    recommendation: 'Implement per-transaction and daily spending limits for AI wallets. Require human approval above threshold.'
  },
  {
    id: 'SOL5387',
    name: 'AI Agent: Prompt Injection via Transaction',
    severity: 'high',
    pattern: /(?:llm|gpt|claude|ai)[\s\S]{0,100}(?:parse|read|interpret)[\s\S]{0,100}memo|instruction/i,
    description: 'Malicious memos or metadata contain prompt injection attacks. AI agents manipulated via on-chain data.',
    recommendation: 'Sanitize all on-chain data before LLM processing. Separate data parsing from action execution.'
  },
  {
    id: 'SOL5388',
    name: 'AI Agent: Autonomous Trading Without Limits',
    severity: 'high',
    pattern: /(?:trade|swap|execute)[\s\S]{0,100}(?:ai|agent|auto)[\s\S]{0,100}(?!cooldown|rate_limit)/i,
    description: 'AI agents executing unlimited trades. Malfunctioning AI creates infinite trading loop.',
    recommendation: 'Rate limit AI trading operations. Implement cooldowns between trades. Human approval for large trades.'
  },
  {
    id: 'SOL5389',
    name: 'AI Agent: MPC Key Share Exposure',
    severity: 'critical',
    pattern: /mpc|threshold[\s\S]{0,100}(?:share|key_part)[\s\S]{0,100}(?:ai|agent|llm)[\s\S]{0,50}(?!isolated|enclave)/i,
    description: 'AI agent has access to MPC key share. Compromised AI can participate in signing.',
    recommendation: 'Isolate MPC key shares from AI context. Use hardware enclaves for key operations. Human-only key custody.'
  },
  {
    id: 'SOL5390',
    name: 'AI Agent: Social Engineering via Agent-to-Agent',
    severity: 'medium',
    pattern: /(?:agent|ai)[\s\S]{0,50}(?:message|communicate)[\s\S]{0,100}(?:other_agent|peer)/i,
    description: 'Malicious AI agents socially engineer other agents. Agent-to-agent protocols exploited.',
    recommendation: 'Authenticate agent communications. Verify agent identities cryptographically. Rate limit inter-agent messages.'
  },

  // ============================================
  // SUPPLY CHAIN SECURITY
  // NPM, CDN, dependency patterns
  // ============================================
  {
    id: 'SOL5391',
    name: 'Web3.js Supply Chain: Postinstall Script',
    severity: 'critical',
    pattern: /postinstall|preinstall[\s\S]{0,100}(?:script|hook)[\s\S]{0,100}(?:web3|solana)/i,
    description: 'Web3.js Dec 2024: Malicious postinstall script in npm package. Private keys exfiltrated on install.',
    recommendation: 'Pin exact dependency versions. Audit npm scripts before install. Use npm ci with lockfile.'
  },
  {
    id: 'SOL5392',
    name: 'CDN Frontend Injection',
    severity: 'critical',
    pattern: /cdn|script.*src[\s\S]{0,100}(?!integrity|sri_hash|subresource)/i,
    description: 'Parcl frontend compromise: CDN assets replaced with wallet drainer. No SRI verification.',
    recommendation: 'Use Subresource Integrity (SRI) for all CDN assets. Host critical JS locally. CSP headers.'
  },
  {
    id: 'SOL5393',
    name: 'Dependency Typosquatting',
    severity: 'high',
    pattern: /(?:require|import)[\s\S]{0,50}(?:solona|sol-web3|solana_js|web-3)[\s\S]{0,30}/i,
    description: 'Typosquatted package names near legitimate Solana packages. Malicious code in similarly-named packages.',
    recommendation: 'Verify package names exactly. Use package-lock.json. Audit new dependencies before adding.'
  },
  {
    id: 'SOL5394',
    name: 'Build Reproducibility Missing',
    severity: 'medium',
    pattern: /build|compile[\s\S]{0,100}(?:program|contract)[\s\S]{0,100}(?!verifiable|reproducible|deterministic)/i,
    description: 'Deployed bytecode doesn\'t match published source. Hidden malicious code in compiled program.',
    recommendation: 'Use Anchor verify or similar for reproducible builds. Publish build commands. Independent verification.'
  },
  {
    id: 'SOL5395',
    name: 'SDK Version Drift',
    severity: 'medium',
    pattern: /(?:solana|anchor|spl).*\^|~|>=[\s\S]{0,50}(?!exact|pinned)/i,
    description: 'Floating dependency versions allow unexpected updates. Breaking changes or vulnerabilities introduced.',
    recommendation: 'Pin exact SDK versions. Update deliberately with testing. Monitor security advisories.'
  },

  // ============================================
  // MONITORING & INCIDENT RESPONSE
  // Operational security patterns
  // ============================================
  {
    id: 'SOL5396',
    name: 'Missing Event Emission for Critical Operations',
    severity: 'medium',
    pattern: /(?:transfer|mint|burn|update)[\s\S]{0,300}(?!emit!|event!|log_event|msg!)/i,
    description: 'Critical operations without events. Exploit detection delayed due to missing logs.',
    recommendation: 'Emit events for all state-changing operations. Include relevant parameters. Enable real-time monitoring.'
  },
  {
    id: 'SOL5397',
    name: 'No Circuit Breaker Implementation',
    severity: 'high',
    pattern: /(?:protocol|pool|vault)[\s\S]{0,300}(?!circuit_breaker|emergency_stop|pause|kill_switch)/i,
    description: 'No mechanism to stop protocol during active exploit. Losses continue until manual intervention.',
    recommendation: 'Implement pause mechanisms. Define circuit breaker triggers (unusual volume, price deviation). Test pause regularly.'
  },
  {
    id: 'SOL5398',
    name: 'Insufficient Invariant Assertions',
    severity: 'medium',
    pattern: /(?:fn|pub fn)[\s\S]{0,500}(?!assert!|require!|invariant)/i,
    description: 'Functions lack invariant assertions. Logic errors go undetected until exploited.',
    recommendation: 'Assert invariants at function entry and exit. Document expected invariants. Use formal verification for critical paths.'
  },
  {
    id: 'SOL5399',
    name: 'Incident Response Plan Missing',
    severity: 'info',
    pattern: /security|vulnerability[\s\S]{0,200}(?!response_plan|incident|runbook)/i,
    description: 'No documented incident response plan. Chaotic response during actual incidents.',
    recommendation: 'Document incident response procedures. Assign roles. Practice incident drills. Prepare communication templates.'
  },
  {
    id: 'SOL5400',
    name: 'Bug Bounty Program Absent',
    severity: 'info',
    pattern: /security[\s\S]{0,200}(?!bounty|immunefi|hackerone|reward)/i,
    description: 'No bug bounty program. White hat researchers have no incentive to report vulnerabilities.',
    recommendation: 'Launch bug bounty program on Immunefi or similar. Offer competitive rewards. Fast response to reports.'
  }
];

// Export patterns with matching logic
export function scanBatch93(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.content;

  for (const pattern of BATCH_93_PATTERNS) {
    if (pattern.pattern.test(content)) {
      // Find the actual match for location info
      const match = content.match(pattern.pattern);
      let line = 1;
      let column = 0;

      if (match && match.index !== undefined) {
        const beforeMatch = content.slice(0, match.index);
        line = (beforeMatch.match(/\n/g) || []).length + 1;
        const lastNewline = beforeMatch.lastIndexOf('\n');
        column = match.index - (lastNewline === -1 ? 0 : lastNewline + 1);
      }

      findings.push({
        id: pattern.id,
        name: pattern.name,
        severity: pattern.severity,
        description: pattern.description,
        recommendation: pattern.recommendation,
        location: {
          file: input.file,
          line,
          column,
          snippet: match ? match[0].slice(0, 100) : ''
        }
      });
    }
  }

  return findings;
}

// Export pattern definitions for documentation
export const BATCH_93_PATTERN_DEFS = BATCH_93_PATTERNS;
export const BATCH_93_COUNT = BATCH_93_PATTERNS.length;
