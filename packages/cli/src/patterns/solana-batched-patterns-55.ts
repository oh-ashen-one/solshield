/**
 * SolShield Security Patterns - Batch 55
 * 
 * 70 Patterns (SOL2141-SOL2210)
 * Sources: 
 * - arXiv:2504.07419 "Exploring Vulnerabilities in Solana Smart Contracts"
 * - Sec3 2025 Security Ecosystem Review (163 audits, 1,669 vulns)
 * - sannykim/solsec GitHub Resource Collection
 * - OtterSec, Neodyme, Kudelski, Zellic Research
 * 
 * Categories:
 * - arXiv Academic Findings (SOL2141-SOL2160)
 * - Sealevel Attack Patterns (SOL2161-SOL2175)
 * - Audit-Derived Patterns (SOL2176-SOL2195)
 * - 2025 Emerging Attack Vectors (SOL2196-SOL2210)
 */

import type { PatternInput, Finding } from './index.js';

/** Batch 55 Patterns: Academic + Audit Research */
export const BATCH_55_PATTERNS = [
  // ========== arXiv Academic Findings (SOL2141-SOL2160) ==========
  {
    id: 'SOL2141',
    name: 'arXiv: Deprecated Library Usage',
    severity: 'medium' as const,
    pattern: /solana_program\s*=\s*"1\.[0-8]\./i,
    description: 'Using deprecated solana_program version. arXiv:2504.07419 identifies outdated dependencies as common vulnerability source.',
    recommendation: 'Upgrade to solana_program >= 1.14 for latest security fixes.'
  },
  {
    id: 'SOL2142',
    name: 'arXiv: Soteria-Detectable Missing Signer',
    severity: 'critical' as const,
    pattern: /pub\s+authority\s*:\s*AccountInfo(?![\s\S]{0,30}Signer|[\s\S]{0,30}is_signer)/i,
    description: 'Authority account without signer check. Soteria (SEC) tool from arXiv paper detects this pattern.',
    recommendation: 'Use Signer<\'info> type or manually verify is_signer.'
  },
  {
    id: 'SOL2143',
    name: 'arXiv: Radar-Detectable Type Confusion',
    severity: 'high' as const,
    pattern: /try_from_slice[\s\S]{0,50}(?!discriminator|match|if\s+\w+\[\d+\])/i,
    description: 'Deserializing account data without discriminator check. Radar tool from arXiv detects type confusion.',
    recommendation: 'Verify 8-byte discriminator before deserialization.'
  },
  {
    id: 'SOL2144',
    name: 'arXiv: Anchor Privilege Escalation',
    severity: 'critical' as const,
    pattern: /#\[account\([\s\S]{0,100}mut[\s\S]{0,100}\)\][\s\S]{0,200}(?!has_one|constraint)/i,
    description: 'Mutable account in Anchor without relationship constraints. arXiv identifies privilege escalation risk.',
    recommendation: 'Add has_one or constraint checks for mutable accounts.'
  },
  {
    id: 'SOL2145',
    name: 'arXiv: Laminar Static Analysis Gap',
    severity: 'high' as const,
    pattern: /invoke(?:_signed)?[\s\S]{0,100}accounts[\s\S]{0,50}\[/i,
    description: 'Dynamic account indexing in CPI calls bypasses static analysis tools like Laminar.',
    recommendation: 'Use named account references instead of array indexing.'
  },
  {
    id: 'SOL2146',
    name: 'arXiv: Solana eBPF Syscall Abuse',
    severity: 'critical' as const,
    pattern: /sol_invoke_signed_c|syscall|sol_log_|sol_sha256/i,
    description: 'Direct syscall usage bypasses Anchor safety. arXiv notes syscall abuse in native programs.',
    recommendation: 'Use high-level Anchor abstractions when possible.'
  },
  {
    id: 'SOL2147',
    name: 'arXiv: Insufficient Program Verification',
    severity: 'critical' as const,
    pattern: /UncheckedAccount[\s\S]{0,100}invoke(?![\s\S]{0,50}program\.key\(\)\s*==)/i,
    description: 'CPI with unchecked account and no program ID verification. arXiv Table 3 lists this.',
    recommendation: 'Verify target program ID before CPI calls.'
  },
  {
    id: 'SOL2148',
    name: 'arXiv: Arithmetic Wrapping in Release',
    severity: 'high' as const,
    pattern: /\+|\-|\*(?![\s\S]{0,20}checked_|saturating_|wrapping_)[\s\S]{0,50}(?:balance|amount|supply)/i,
    description: 'Arithmetic on financial values. Rust release mode wraps on overflow (arXiv Section 3.1.4).',
    recommendation: 'Use checked_add/sub/mul for all financial calculations.'
  },
  {
    id: 'SOL2149',
    name: 'arXiv: SEC Tool False Negative Area',
    severity: 'medium' as const,
    pattern: /AccountInfo<'info>[\s\S]{0,200}(?:if|match|require!)[\s\S]{0,100}owner/i,
    description: 'Complex ownership check that static analyzers may miss. arXiv notes SEC tool gaps.',
    recommendation: 'Ensure ownership checks are explicit and early in function.'
  },
  {
    id: 'SOL2150',
    name: 'arXiv: Cross-Contract Vulnerability',
    severity: 'critical' as const,
    pattern: /invoke[\s\S]{0,200}state[\s\S]{0,50}=[\s\S]{0,50}(?!reload|refresh)/i,
    description: 'State mutation after CPI without reload. arXiv identifies cross-contract vulnerabilities.',
    recommendation: 'Reload account state after any CPI call.'
  },
  {
    id: 'SOL2151',
    name: 'arXiv: Missing Bump Canonicalization',
    severity: 'high' as const,
    pattern: /bump\s*:\s*u8[\s\S]{0,100}(?!find_program_address|canonical)/i,
    description: 'Bump stored without canonicalization. arXiv Section 3.2.2 PDA vulnerabilities.',
    recommendation: 'Always use canonical bump from find_program_address.'
  },
  {
    id: 'SOL2152',
    name: 'arXiv: Rent Exemption Bypass',
    severity: 'medium' as const,
    pattern: /lamports[\s\S]{0,50}(?:transfer|sub)[\s\S]{0,100}(?!minimum_balance|rent_exempt)/i,
    description: 'Lamport transfer without rent check. arXiv notes account eviction vulnerability.',
    recommendation: 'Verify account remains rent-exempt after transfers.'
  },
  {
    id: 'SOL2153',
    name: 'arXiv: Reinitialization Attack Vector',
    severity: 'critical' as const,
    pattern: /is_initialized\s*=\s*true[\s\S]{0,200}(?!require!.*is_initialized\s*==\s*false)/i,
    description: 'Setting initialized without checking prior state. arXiv cross-instance reinit attack.',
    recommendation: 'Check is_initialized == false before initialization.'
  },
  {
    id: 'SOL2154',
    name: 'arXiv: Tool Detection Comparison Gap',
    severity: 'medium' as const,
    pattern: /#\[program\][\s\S]{0,500}(?:anchor_lang|solana_program)/i,
    description: 'Program using both Anchor and native. arXiv shows tool coverage gaps at boundaries.',
    recommendation: 'Use consistent framework throughout program.'
  },
  {
    id: 'SOL2155',
    name: 'arXiv: EVM vs Solana Reentrancy Difference',
    severity: 'high' as const,
    pattern: /invoke[\s\S]{0,100}(?:transfer|send)[\s\S]{0,200}state[\s\S]{0,50}=/i,
    description: 'Solana reentrancy differs from EVM. arXiv notes developers assume EVM patterns apply.',
    recommendation: 'Update state before CPI, even though Solana prevents recursive calls.'
  },
  {
    id: 'SOL2156',
    name: 'arXiv: Security Tool Coverage Gap',
    severity: 'low' as const,
    pattern: /#\[cfg\(test\)\][\s\S]{0,500}(?!fuzzing|property)/i,
    description: 'Tests without fuzzing. arXiv Table 4 shows limited tool coverage for complex vulns.',
    recommendation: 'Add property-based testing and fuzzing with Trident.'
  },
  {
    id: 'SOL2157',
    name: 'arXiv: Solana vs Ethereum Account Model',
    severity: 'medium' as const,
    pattern: /msg\.sender|tx\.origin/i,
    description: 'EVM patterns in Solana code. arXiv emphasizes account model differences.',
    recommendation: 'Use Solana account model: explicit signers and PDAs.'
  },
  {
    id: 'SOL2158',
    name: 'arXiv: Instruction Data Validation',
    severity: 'high' as const,
    pattern: /instruction_data[\s\S]{0,50}try_from_slice[\s\S]{0,100}(?!validate|check|require)/i,
    description: 'Deserializing instruction data without validation. arXiv input validation category.',
    recommendation: 'Validate all instruction data fields after deserialization.'
  },
  {
    id: 'SOL2159',
    name: 'arXiv: Compute Budget Vulnerability',
    severity: 'medium' as const,
    pattern: /for[\s\S]{0,30}in[\s\S]{0,50}\.iter\(\)[\s\S]{0,200}(?!\.take\(|\.limit|MAX_)/i,
    description: 'Unbounded iteration. arXiv notes compute budget exhaustion attacks.',
    recommendation: 'Add iteration limits to prevent DoS attacks.'
  },
  {
    id: 'SOL2160',
    name: 'arXiv: Tool Ecosystem Maturity Gap',
    severity: 'low' as const,
    pattern: /\/\/\s*(?:TODO|FIXME|HACK|XXX)[\s\S]{0,50}security/i,
    description: 'Security-related TODO comments. arXiv notes Solana tooling less mature than Ethereum.',
    recommendation: 'Address all security TODOs before deployment.'
  },

  // ========== Sealevel Attack Patterns (SOL2161-SOL2175) ==========
  {
    id: 'SOL2161',
    name: 'Sealevel: Duplicate Mutable Accounts',
    severity: 'critical' as const,
    pattern: /#\[account\(mut\)\][\s\S]{0,300}#\[account\(mut\)\][\s\S]{0,100}(?!constraint\s*=.*!=)/i,
    description: 'Two mutable accounts of same type without inequality constraint. Armani Sealevel attack #2.',
    recommendation: 'Add constraint: constraint = account_a.key() != account_b.key()'
  },
  {
    id: 'SOL2162',
    name: 'Sealevel: Account Type Confusion',
    severity: 'critical' as const,
    pattern: /Account<[\s\S]{0,30}>[\s\S]{0,100}try_from[\s\S]{0,50}(?!discriminator)/i,
    description: 'Account deserialization without type verification. Sealevel attack #3.',
    recommendation: 'Use Anchor Account<T> type or verify discriminator manually.'
  },
  {
    id: 'SOL2163',
    name: 'Sealevel: Sysvar Address Spoofing',
    severity: 'critical' as const,
    pattern: /(?:rent|clock|slot_hashes)[\s\S]{0,50}AccountInfo[\s\S]{0,100}(?!Sysvar::id\(\)|check_id)/i,
    description: 'Sysvar passed as AccountInfo without address verification. Sealevel attack #4.',
    recommendation: 'Use Sysvar<Rent> type or verify sysvar.key() == Sysvar::id()'
  },
  {
    id: 'SOL2164',
    name: 'Sealevel: Arbitrary Program CPI',
    severity: 'critical' as const,
    pattern: /invoke[\s\S]{0,100}program[\s\S]{0,50}\.key\(\)[\s\S]{0,100}(?!==|require!|assert!)/i,
    description: 'CPI to program without address verification. Sealevel attack #5.',
    recommendation: 'Hardcode expected program ID or verify against allowlist.'
  },
  {
    id: 'SOL2165',
    name: 'Sealevel: PDA Not Verified',
    severity: 'high' as const,
    pattern: /seeds\s*=[\s\S]{0,100}(?!bump|find_program_address)/i,
    description: 'PDA seeds without bump verification. Sealevel attack #6.',
    recommendation: 'Store and verify canonical bump seed.'
  },
  {
    id: 'SOL2166',
    name: 'Sealevel: Bump Seed Canonicalization',
    severity: 'high' as const,
    pattern: /bump\s*:\s*\d+|bump\s*=\s*(?!ctx\.bumps|bump_seed)/i,
    description: 'Hardcoded bump seed instead of canonical. Sealevel attack #7.',
    recommendation: 'Use find_program_address to get canonical bump.'
  },
  {
    id: 'SOL2167',
    name: 'Sealevel: Close Account Resurrection',
    severity: 'critical' as const,
    pattern: /close\s*=[\s\S]{0,100}(?!zero_copy|memset|\.fill\(0\))/i,
    description: 'Account closure without zeroing data. Sealevel attack #8.',
    recommendation: 'Zero account data before closing to prevent resurrection.'
  },
  {
    id: 'SOL2168',
    name: 'Sealevel: Missing Owner Check',
    severity: 'critical' as const,
    pattern: /AccountInfo[\s\S]{0,200}data[\s\S]{0,100}(?!owner\s*==|check_owner)/i,
    description: 'Reading account data without owner verification. Sealevel attack #1.',
    recommendation: 'Verify account.owner == expected_program before reading data.'
  },
  {
    id: 'SOL2169',
    name: 'Sealevel: Token Account Verification',
    severity: 'high' as const,
    pattern: /TokenAccount[\s\S]{0,100}(?!token::mint\s*=|token::authority\s*=)/i,
    description: 'Token account without mint/authority constraints. Armani tip.',
    recommendation: 'Add token::mint and token::authority constraints.'
  },
  {
    id: 'SOL2170',
    name: 'Sealevel: Associated Token Account',
    severity: 'high' as const,
    pattern: /associated_token_account|ata[\s\S]{0,100}(?!associated_token::)/i,
    description: 'ATA without proper Anchor constraint. Creates confusion with other PDAs.',
    recommendation: 'Use associated_token::mint and associated_token::authority.'
  },
  {
    id: 'SOL2171',
    name: 'Sealevel: Init If Needed Race',
    severity: 'high' as const,
    pattern: /init_if_needed[\s\S]{0,200}(?!realloc::zero\s*=\s*true)/i,
    description: 'init_if_needed without zero initialization. Race condition vulnerability.',
    recommendation: 'Avoid init_if_needed or ensure proper initialization.'
  },
  {
    id: 'SOL2172',
    name: 'Sealevel: Realloc Vulnerability',
    severity: 'high' as const,
    pattern: /realloc\s*=[\s\S]{0,100}(?!realloc::zero\s*=\s*true)/i,
    description: 'Account realloc without zeroing new space. Data leak vulnerability.',
    recommendation: 'Add realloc::zero = true to zero new space.'
  },
  {
    id: 'SOL2173',
    name: 'Sealevel: Constraint Ordering',
    severity: 'medium' as const,
    pattern: /#\[account\([\s\S]{0,100}constraint[\s\S]{0,100}init/i,
    description: 'Constraint before init. Anchor processes attributes in order.',
    recommendation: 'Place init before constraint in account attributes.'
  },
  {
    id: 'SOL2174',
    name: 'Sealevel: Seeds Constraint Missing',
    severity: 'high' as const,
    pattern: /seeds\s*=[\s\S]{0,100}(?!seeds::program)/i,
    description: 'PDA seeds without program specification. Cross-program PDA confusion.',
    recommendation: 'Add seeds::program = program_id for clarity.'
  },
  {
    id: 'SOL2175',
    name: 'Sealevel: Account Constraint Error',
    severity: 'medium' as const,
    pattern: /constraint\s*=[\s\S]{0,100}(?!@\s*\w+Error)/i,
    description: 'Constraint without custom error message. Debugging difficulty.',
    recommendation: 'Add custom error: constraint = condition @ CustomError::Name'
  },

  // ========== Audit-Derived Patterns (SOL2176-SOL2195) ==========
  {
    id: 'SOL2176',
    name: 'Kudelski: Unvalidated Reference Accounts',
    severity: 'high' as const,
    pattern: /\/\/\/\s*CHECK[\s\S]{0,50}(?:reference|read|info)/i,
    description: 'Reference-only account without validation. Kudelski Solana Program Security.',
    recommendation: 'Verify reference accounts even if read-only.'
  },
  {
    id: 'SOL2177',
    name: 'Neodyme: Rounding Direction Attack',
    severity: 'critical' as const,
    pattern: /(?:div|\/)\s*\d+[\s\S]{0,50}(?:mint|transfer|withdraw)/i,
    description: 'Division before token operation. Neodyme $2.6B rounding vulnerability.',
    recommendation: 'Use explicit floor/ceil and favor protocol in rounding.'
  },
  {
    id: 'SOL2178',
    name: 'OtterSec: LP Oracle Manipulation',
    severity: 'critical' as const,
    pattern: /lp_token|liquidity_pool[\s\S]{0,100}price[\s\S]{0,100}(?!fair|twap|virtual)/i,
    description: 'LP token price without fair pricing. OtterSec $200M oracle manipulation.',
    recommendation: 'Use virtual reserves for LP token valuation.'
  },
  {
    id: 'SOL2179',
    name: 'Sec3: Business Logic State Machine',
    severity: 'high' as const,
    pattern: /status|state[\s\S]{0,50}=[\s\S]{0,50}(?:active|pending|complete)(?![\s\S]{0,100}match|require)/i,
    description: 'State transition without validation. Sec3 2025: 38.5% are business logic bugs.',
    recommendation: 'Implement explicit state machine with valid transitions.'
  },
  {
    id: 'SOL2180',
    name: 'Sec3: Economic Invariant Violation',
    severity: 'critical' as const,
    pattern: /(?:supply|balance|reserve)[\s\S]{0,100}(?:\+|\-|=)[\s\S]{0,100}(?!invariant|assert)/i,
    description: 'Economic value change without invariant check. Sec3 business logic category.',
    recommendation: 'Assert economic invariants after every value change.'
  },
  {
    id: 'SOL2181',
    name: 'Zellic: Anchor Vulnerability Patterns',
    severity: 'high' as const,
    pattern: /#\[account\][\s\S]{0,100}pub[\s\S]{0,50}:[\s\S]{0,50}Account<[\s\S]{0,50}>(?![\s\S]{0,100}constraint|has_one)/i,
    description: 'Anchor account without additional constraints. Zellic vulnerability research.',
    recommendation: 'Add has_one, constraint, or other validation.'
  },
  {
    id: 'SOL2182',
    name: 'Trail of Bits: DeFi Composability Risk',
    severity: 'high' as const,
    pattern: /invoke[\s\S]{0,200}invoke[\s\S]{0,200}invoke/i,
    description: 'Multiple nested CPI calls. Trail of Bits DeFi composability concerns.',
    recommendation: 'Limit CPI depth and verify all intermediate states.'
  },
  {
    id: 'SOL2183',
    name: 'Halborn: Admin Key Compromise',
    severity: 'critical' as const,
    pattern: /admin|owner|authority[\s\S]{0,50}(?:transfer|set|update)[\s\S]{0,100}(?!multisig|timelock|governance)/i,
    description: 'Single admin key can change critical parameters. Halborn audit finding.',
    recommendation: 'Use multisig or timelock for admin operations.'
  },
  {
    id: 'SOL2184',
    name: 'Bramah: Stable Swap Invariant',
    severity: 'high' as const,
    pattern: /stable_swap|curve[\s\S]{0,100}(?:swap|exchange)[\s\S]{0,100}(?!invariant|amplification)/i,
    description: 'Stable swap without invariant verification. Bramah Saber audit.',
    recommendation: 'Verify StableSwap invariant after every operation.'
  },
  {
    id: 'SOL2185',
    name: 'Quantstamp: Reward Distribution Drift',
    severity: 'medium' as const,
    pattern: /reward[\s\S]{0,50}(?:per_token|rate|index)[\s\S]{0,100}(?!update|refresh|sync)/i,
    description: 'Reward calculation without update. Quantstamp Quarry audit.',
    recommendation: 'Update reward index before any staking operation.'
  },
  {
    id: 'SOL2186',
    name: 'SlowMist: Oracle Freshness',
    severity: 'high' as const,
    pattern: /oracle|price[\s\S]{0,50}(?:get|fetch|read)[\s\S]{0,100}(?!staleness|age|timestamp)/i,
    description: 'Oracle data without freshness check. SlowMist Larix audit.',
    recommendation: 'Verify oracle data is within acceptable staleness window.'
  },
  {
    id: 'SOL2187',
    name: 'HashCloak: ZK Proof Verification',
    severity: 'critical' as const,
    pattern: /zk|zero_knowledge|proof[\s\S]{0,100}(?:verify|check)[\s\S]{0,100}(?!require!|assert!)/i,
    description: 'ZK proof verification without failure handling. HashCloak Light audit.',
    recommendation: 'Always assert ZK proof verification succeeds.'
  },
  {
    id: 'SOL2188',
    name: 'Certik: Reentrancy Guard Missing',
    severity: 'high' as const,
    pattern: /pub\s+fn\s+\w+[\s\S]{0,300}invoke[\s\S]{0,200}self[\s\S]{0,50}(?:state|data|balance)/i,
    description: 'State modification after CPI without guard. Certik Francium audit.',
    recommendation: 'Use reentrancy guard or update state before CPI.'
  },
  {
    id: 'SOL2189',
    name: 'Opcodes: Vesting Cliff Bypass',
    severity: 'high' as const,
    pattern: /vesting|cliff[\s\S]{0,100}(?:withdraw|claim)[\s\S]{0,100}(?!timestamp|block|slot)/i,
    description: 'Vesting withdrawal without time verification. Opcodes Streamflow audit.',
    recommendation: 'Check cliff and vesting schedule before allowing withdrawals.'
  },
  {
    id: 'SOL2190',
    name: 'MadShield: NFT Staking Duration',
    severity: 'medium' as const,
    pattern: /nft[\s\S]{0,50}(?:stake|lock)[\s\S]{0,100}(?:unstake|unlock)[\s\S]{0,100}(?!duration|period|cooldown)/i,
    description: 'NFT unstaking without lockup period. MadShield Genopets audit.',
    recommendation: 'Enforce minimum staking duration for NFTs.'
  },
  {
    id: 'SOL2191',
    name: 'Ackee: Fuzzing Discovery Gap',
    severity: 'medium' as const,
    pattern: /#\[cfg\(test\)\][\s\S]{0,1000}#\[test\][\s\S]{0,500}(?!proptest|arbitrary|fuzz)/i,
    description: 'Unit tests without property-based testing. Ackee audit methodology.',
    recommendation: 'Add Trident fuzzing or proptest for comprehensive testing.'
  },
  {
    id: 'SOL2192',
    name: 'Audit: Emergency Pause Missing',
    severity: 'high' as const,
    pattern: /pub\s+fn\s+(?:swap|transfer|withdraw|deposit)[\s\S]{0,200}(?!paused|emergency|frozen)/i,
    description: 'Critical function without pause check. Common audit finding.',
    recommendation: 'Add emergency pause capability to all critical functions.'
  },
  {
    id: 'SOL2193',
    name: 'Audit: Fee Precision Loss',
    severity: 'medium' as const,
    pattern: /fee[\s\S]{0,50}(?:\*|\/)\s*\d+[\s\S]{0,50}(?!\d{4,}|1e|10000)/i,
    description: 'Fee calculation with low precision. Audit precision loss finding.',
    recommendation: 'Use basis points (10000) or higher precision for fees.'
  },
  {
    id: 'SOL2194',
    name: 'Audit: Liquidation Threshold',
    severity: 'high' as const,
    pattern: /liquidat[\s\S]{0,50}(?:threshold|factor|ratio)[\s\S]{0,50}(?:=|:)[\s\S]{0,30}(?!require|assert|check)/i,
    description: 'Liquidation threshold without bounds validation. Common lending audit.',
    recommendation: 'Validate threshold is within safe bounds (e.g., 50-90%).'
  },
  {
    id: 'SOL2195',
    name: 'Audit: Collateral Factor Timelock',
    severity: 'high' as const,
    pattern: /collateral_factor|ltv[\s\S]{0,50}(?:set|update)[\s\S]{0,100}(?!timelock|delay|governance)/i,
    description: 'Collateral factor change without timelock. Lending audit finding.',
    recommendation: 'Add timelock for collateral factor changes.'
  },

  // ========== 2025 Emerging Attack Vectors (SOL2196-SOL2210) ==========
  {
    id: 'SOL2196',
    name: '2025: Jito Client Concentration Risk',
    severity: 'medium' as const,
    pattern: /validator|stake[\s\S]{0,100}(?:jito|mev)[\s\S]{0,100}(?!diversif|multiple)/i,
    description: 'Jito client has 88% validator dominance. Sec3 2025 concentration risk.',
    recommendation: 'Consider MEV client diversity for protocol resilience.'
  },
  {
    id: 'SOL2197',
    name: '2025: Hosting Provider Concentration',
    severity: 'medium' as const,
    pattern: /teraswitch|latitude[\s\S]{0,50}|hosting[\s\S]{0,50}provider/i,
    description: '43% stake on two hosting providers. Sec3 2025 infrastructure risk.',
    recommendation: 'Diversify infrastructure providers for network resilience.'
  },
  {
    id: 'SOL2198',
    name: '2025: Token-2022 Confidential Leaks',
    severity: 'high' as const,
    pattern: /confidential_transfer|ElGamalCiphertext[\s\S]{0,100}(?!decrypt|verify_range)/i,
    description: 'Token-2022 confidential transfers require proper range proofs.',
    recommendation: 'Verify all range proofs in confidential transfer handling.'
  },
  {
    id: 'SOL2199',
    name: '2025: Transfer Hook Reentrancy',
    severity: 'critical' as const,
    pattern: /transfer_hook|TransferHook[\s\S]{0,200}(?:invoke|call)[\s\S]{0,100}(?!guard|lock)/i,
    description: 'Token-2022 transfer hooks can enable reentrancy.',
    recommendation: 'Add reentrancy guard when handling transfer hooks.'
  },
  {
    id: 'SOL2200',
    name: '2025: cNFT Merkle Proof Manipulation',
    severity: 'high' as const,
    pattern: /merkle_proof|compressed_nft[\s\S]{0,100}(?:verify|validate)[\s\S]{0,100}(?!canopy|root)/i,
    description: 'Compressed NFT proof verification without canopy.',
    recommendation: 'Verify merkle proofs against on-chain canopy or root.'
  },
  {
    id: 'SOL2201',
    name: '2025: Blink Action URL Injection',
    severity: 'high' as const,
    pattern: /blink|action_url|solana:[\s\S]{0,100}(?!sanitize|validate|whitelist)/i,
    description: 'Solana Blink action URLs without validation.',
    recommendation: 'Sanitize and whitelist Blink action URLs.'
  },
  {
    id: 'SOL2202',
    name: '2025: Lookup Table Poisoning',
    severity: 'critical' as const,
    pattern: /address_lookup_table|alt[\s\S]{0,100}(?:extend|create)[\s\S]{0,100}(?!authority)/i,
    description: 'Address lookup table modification without authority check.',
    recommendation: 'Verify ALT authority before extension operations.'
  },
  {
    id: 'SOL2203',
    name: '2025: Priority Fee Manipulation',
    severity: 'medium' as const,
    pattern: /priority_fee|compute_budget[\s\S]{0,100}set[\s\S]{0,100}(?!cap|max|limit)/i,
    description: 'Priority fee setting without caps enables griefing.',
    recommendation: 'Cap priority fees to prevent economic attacks.'
  },
  {
    id: 'SOL2204',
    name: '2025: Durable Nonce Replay',
    severity: 'high' as const,
    pattern: /durable_nonce|nonce_account[\s\S]{0,100}(?:advance|use)[\s\S]{0,100}(?!authority)/i,
    description: 'Durable nonce without authority verification.',
    recommendation: 'Verify nonce authority before advancing.'
  },
  {
    id: 'SOL2205',
    name: '2025: Versioned Transaction Confusion',
    severity: 'medium' as const,
    pattern: /VersionedTransaction|legacy[\s\S]{0,100}(?:convert|handle)[\s\S]{0,100}(?!version|check)/i,
    description: 'Mixed legacy and versioned transaction handling.',
    recommendation: 'Explicitly handle transaction versioning.'
  },
  {
    id: 'SOL2206',
    name: '2025: Restaking Slashing Cascade',
    severity: 'high' as const,
    pattern: /restake|liquid_staking[\s\S]{0,100}(?:slash|penalty)[\s\S]{0,100}(?!isolation|cap)/i,
    description: 'Restaking protocols can cascade slashing events.',
    recommendation: 'Isolate slashing risk and cap per-validator exposure.'
  },
  {
    id: 'SOL2207',
    name: '2025: AI Agent Wallet Security',
    severity: 'critical' as const,
    pattern: /agent|bot[\s\S]{0,50}(?:wallet|keypair)[\s\S]{0,100}(?!hardware|multisig|threshold)/i,
    description: 'AI agent wallets without hardware security.',
    recommendation: 'Use hardware wallets or MPC for agent key management.'
  },
  {
    id: 'SOL2208',
    name: '2025: Meme Coin Rug Detection',
    severity: 'high' as const,
    pattern: /pump\.fun|bonding_curve[\s\S]{0,100}(?:migration|graduate)[\s\S]{0,100}(?!lock|timelock)/i,
    description: 'Meme coin launch without migration protection.',
    recommendation: 'Add timelock or multisig for liquidity migration.'
  },
  {
    id: 'SOL2209',
    name: '2025: Flash Loan Oracle Window',
    severity: 'critical' as const,
    pattern: /flash_loan[\s\S]{0,200}(?:price|oracle)[\s\S]{0,100}(?!twap|window|delay)/i,
    description: 'Flash loans can manipulate single-block prices.',
    recommendation: 'Use TWAP oracles spanning multiple slots.'
  },
  {
    id: 'SOL2210',
    name: '2025: Cross-Program Invocation Depth',
    severity: 'medium' as const,
    pattern: /invoke[\s\S]{0,100}invoke[\s\S]{0,100}invoke[\s\S]{0,100}invoke/i,
    description: 'Deep CPI nesting increases attack surface.',
    recommendation: 'Limit CPI depth to 4 or fewer for security and compute.'
  },
];

/**
 * Run Batch 55 patterns against input
 */
export function checkBatch55Patterns(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  const fileName = input.path || input.rust?.filePath || 'unknown';

  if (!content) return findings;

  const lines = content.split('\n');

  for (const pattern of BATCH_55_PATTERNS) {
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

export const BATCH_55_COUNT = BATCH_55_PATTERNS.length; // 70 patterns
