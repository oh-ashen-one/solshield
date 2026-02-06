/**
 * SolGuard Security Patterns - Batch 92
 * 
 * Feb 6, 2026 6:00 AM - Solsec Deep Dive + PoC Exploits
 * Sources:
 * - Solsec GitHub (sannykim/solsec) - Curated Auditing Resources
 * - Cope Roulette Exploit (Arrowana) - Reverting Transaction Attack
 * - Jet Protocol Break Bug (Jayne) - Logic Flow Vulnerability
 * - Port Finance Max Withdraw Bug - State Validation
 * - Neodyme Lending Disclosure - $2.6B Rounding Attack
 * - Incinerator SPL Token Program Attack - Exploit Chaining
 * - Schrodinger's NFT - Royal Flush Attack Pattern
 * - Opcodes Simulation Detection Research
 * - SPL Token Approve/Revoke Security (Hana/2501babe)
 * 
 * Patterns: SOL5201-SOL5300
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

const BATCH_92_PATTERNS: PatternDef[] = [
  // ============================================
  // Cope Roulette - Reverting Transaction Exploit
  // Source: github.com/Arrowana/cope-roulette-pro
  // ============================================
  {
    id: 'SOL5201',
    name: 'Cope Roulette: Reverting Transaction Gambling Exploit',
    severity: 'critical',
    pattern: /random|rng|lottery|gamble[\s\S]{0,200}(?:seed|slot|hash)(?![\s\S]{0,100}commit_reveal|[\s\S]{0,100}vrf)/i,
    description: 'Cope Roulette exploit: Attacker can bundle bets with winning condition checks, reverting losing transactions atomically. On-chain randomness is vulnerable to bet-then-check attacks.',
    recommendation: 'Use VRF (Switchboard/Pyth) for verifiable randomness. Implement commit-reveal schemes with time delays.'
  },
  {
    id: 'SOL5202',
    name: 'Cope Roulette: Atomic Bet Reversal Pattern',
    severity: 'high',
    pattern: /assert!|require![\s\S]{0,50}(?:win|prize|payout)[\s\S]{0,100}(?:revert|err|fail)/i,
    description: 'Gambling logic that can be exploited by bundling bet + assertion in same transaction. Attacker only pays for winning bets.',
    recommendation: 'Separate bet placement from outcome resolution. Use blockhash-based delays between bet and reveal.'
  },
  {
    id: 'SOL5203',
    name: 'Cope Roulette: Same-Slot Randomness Exploitation',
    severity: 'critical',
    pattern: /Clock::get\(\)[\s\S]{0,50}(?:slot|unix_timestamp)[\s\S]{0,100}random|seed/i,
    description: 'Using slot or timestamp as randomness source enables same-slot manipulation. Attackers can retry until winning.',
    recommendation: 'Never use Clock for randomness. Use VRF with callback or commit-reveal with multi-block delays.'
  },
  
  // ============================================
  // Jet Protocol Break Bug
  // Source: medium.com/@0xjayne/jet-protocol-vulnerability
  // ============================================
  {
    id: 'SOL5204',
    name: 'Jet Protocol: Unintended Break Statement Bug',
    severity: 'critical',
    pattern: /for\s*\([\s\S]*?\)\s*\{[\s\S]*?break[\s\S]*?\}[\s\S]{0,100}(?:borrow|withdraw|tvl)/i,
    description: 'Jet Protocol bug: An unintended break statement allowed unlimited borrowing by exiting validation loop early. Logic flow vulnerability.',
    recommendation: 'Review all break/continue/return statements in validation loops. Add comprehensive unit tests for loop edge cases.'
  },
  {
    id: 'SOL5205',
    name: 'Jet Protocol: Validation Loop Early Exit',
    severity: 'high',
    pattern: /while|for[\s\S]{0,50}(?:validate|check|verify)[\s\S]{0,100}break(?![\s\S]{0,30}error|[\s\S]{0,30}fail)/i,
    description: 'Break statement in validation loop without error condition. May skip critical checks for remaining items.',
    recommendation: 'Use continue instead of break for skipping items. Ensure break only occurs on explicit failures.'
  },
  {
    id: 'SOL5206',
    name: 'Jet Protocol: All TVL Borrowable Pattern',
    severity: 'critical',
    pattern: /max_borrow|borrow_limit[\s\S]{0,100}(?:tvl|total_supply|available)(?![\s\S]{0,100}utilization|[\s\S]{0,100}cap)/i,
    description: 'Lending protocol without proper borrow limits relative to TVL. Bug could allow draining entire protocol.',
    recommendation: 'Implement utilization caps. Never allow borrowing more than X% of available liquidity (typically 80-90%).'
  },

  // ============================================
  // Port Finance Max Withdraw Bug
  // Source: github.com/port-finance/variable-rate-lending PoC
  // ============================================
  {
    id: 'SOL5207',
    name: 'Port Finance: Max Withdraw Calculation Bug',
    severity: 'high',
    pattern: /max_withdraw|available_amount[\s\S]{0,100}(?:reserve|liquidity)(?![\s\S]{0,100}accrue|[\s\S]{0,100}refresh)/i,
    description: 'Port Finance bug: Max withdraw calculated without refreshing accrued interest. Stale state leads to incorrect withdrawal limits.',
    recommendation: 'Always refresh/accrue interest before calculating max withdraw. Update reserve state atomically.'
  },
  {
    id: 'SOL5208',
    name: 'Port Finance: Stale Interest State Exploit',
    severity: 'high',
    pattern: /interest_rate|accrued_interest[\s\S]{0,100}(?:last_update|timestamp)[\s\S]{0,100}(?!refresh|sync)/i,
    description: 'Interest calculations using stale last_update timestamp. Can be exploited for profit timing attacks.',
    recommendation: 'Sync interest accrual at start of every instruction. Use slot-based rather than timestamp-based updates.'
  },

  // ============================================
  // Neodyme Lending Disclosure - $2.6B Rounding Attack
  // Source: blog.neodyme.io/posts/lending_disclosure
  // ============================================
  {
    id: 'SOL5209',
    name: 'Neodyme: SPL-Lending Rounding Attack ($2.6B at Risk)',
    severity: 'critical',
    pattern: /(?:deposit|mint|share)[\s\S]{0,100}(?:\/|div)[\s\S]{0,50}(?!floor|ceil|round_down|round_up)/i,
    description: 'Neodyme disclosure: Innocent rounding errors in SPL-lending put $2.6B at risk. Division without explicit rounding direction.',
    recommendation: 'Use floor for user-favorable ops (withdrawals), ceil for protocol-favorable (deposits). Never use default rounding.'
  },
  {
    id: 'SOL5210',
    name: 'Neodyme: Share Calculation Rounding Exploit',
    severity: 'high',
    pattern: /shares?\s*=[\s\S]{0,50}(?:amount|tokens?)[\s\S]{0,30}(?:\/|div)[\s\S]{0,30}(?:rate|price|exchange)/i,
    description: 'Share calculation from amount division vulnerable to rounding manipulation. Small deposits can steal fractions.',
    recommendation: 'Add minimum deposit requirements. Use checked_div with explicit rounding direction (floor for minting shares).'
  },
  {
    id: 'SOL5211',
    name: 'Neodyme: Dust Attack via Rounding',
    severity: 'medium',
    pattern: /\.(?:round|div)\(\)[\s\S]{0,100}(?:token|mint|transfer)(?![\s\S]{0,50}min_amount)/i,
    description: 'Generic rounding without minimum amounts enables dust accumulation attacks over many transactions.',
    recommendation: 'Enforce minimum transaction sizes. Round in protocol-favorable direction for all external transfers.'
  },

  // ============================================
  // Incinerator Attack + Schrodinger's NFT
  // Source: medium.com/@solens_io/schrodingers-nft
  // ============================================
  {
    id: 'SOL5212',
    name: 'Incinerator: SPL Token Program Attack Chain',
    severity: 'critical',
    pattern: /incinerator|burn.*destination[\s\S]{0,100}(?!verify|check|constraint)/i,
    description: "Schrodinger's NFT attack: Chaining incinerator program with SPL token creates exploit. Token burn destination not properly validated.",
    recommendation: 'Verify all token destinations. Never trust user-provided burn/incinerator addresses.'
  },
  {
    id: 'SOL5213',
    name: 'Schrodinger NFT: Royal Flush Attack Pattern',
    severity: 'critical',
    pattern: /(?:transfer|burn|mint)[\s\S]{0,100}(?:nft|token)[\s\S]{0,100}(?:combine|chain|sequence)/i,
    description: 'Royal Flush attack: Chaining small exploits to create significant damage. NFT state manipulation via exploit sequence.',
    recommendation: 'Audit instruction sequences as chains, not individual operations. Test multi-instruction attack scenarios.'
  },
  {
    id: 'SOL5214',
    name: 'Schrodinger NFT: State Superposition Exploit',
    severity: 'high',
    pattern: /nft[\s\S]{0,50}(?:state|status)[\s\S]{0,100}(?:burned|alive|valid)(?![\s\S]{0,50}atomic)/i,
    description: "Schrodinger state: NFT can appear both burned and alive due to non-atomic state updates across accounts.",
    recommendation: 'Use atomic state transitions. Verify all related accounts in single instruction.'
  },

  // ============================================
  // Candy Machine Exploit
  // Source: medium.com/@solens_io/smashing-the-candy-machine
  // ============================================
  {
    id: 'SOL5215',
    name: 'Candy Machine: UncheckedAccount Exploit',
    severity: 'critical',
    pattern: /UncheckedAccount[\s\S]{0,100}(?:candy|mint|nft)(?![\s\S]{0,50}\/\/\/\s*CHECK)/i,
    description: 'Candy Machine exploit: UncheckedAccount without proper validation. Anchor requires /// CHECK documentation for reason.',
    recommendation: 'Add /// CHECK documentation. Better: use proper account type or add explicit constraints.'
  },
  {
    id: 'SOL5216',
    name: 'Candy Machine: Init vs Zero Account Confusion',
    severity: 'high',
    pattern: /#\[account\(zero\)\][\s\S]{0,200}(?:init|initialize)/i,
    description: 'Candy Machine fix was 1 line: #[account(zero)] vs #[account(init)]. Using zero when init is needed allows reinitialization.',
    recommendation: 'Use #[account(init)] for new account creation. Use #[account(zero)] only when account is pre-allocated.'
  },

  // ============================================
  // Opcodes Simulation Detection
  // Source: opcodes.fr/en/publications/detecting-transaction-simulation
  // ============================================
  {
    id: 'SOL5217',
    name: 'Opcodes: Simulation Detection Bypass',
    severity: 'high',
    pattern: /simulate|preflight|simulation[\s\S]{0,100}(?:detect|check|block)/i,
    description: 'Programs attempting to detect simulation mode can be bypassed. Simulation uses Bank module differently than runtime.',
    recommendation: 'Do not rely on simulation detection for security. Assume all transactions could be simulated first.'
  },
  {
    id: 'SOL5218',
    name: 'Opcodes: Bank Module State Differences',
    severity: 'medium',
    pattern: /bank[\s\S]{0,50}(?:state|slot|hash)[\s\S]{0,100}(?:simulation|preflight)/i,
    description: 'Bank module processes simulations differently. State accessed during simulation may differ from execution state.',
    recommendation: 'Design logic to work identically in simulation and execution. Avoid timing-dependent operations.'
  },

  // ============================================
  // SPL Token Approve/Revoke Security (Hana/2501babe)
  // Source: 2501babe.github.io/tools/revoken.html
  // ============================================
  {
    id: 'SOL5219',
    name: 'SPL Token: Sneaky Approval Attack',
    severity: 'high',
    pattern: /approve[\s\S]{0,100}(?:token|spl)[\s\S]{0,100}(?!revoke|check_approval|approval_limit)/i,
    description: 'SPL Token approve instruction can be used sneakily. Users may not realize they granted spending permission.',
    recommendation: 'Implement approval limits. Show clear UI for approval amounts. Support revoke workflows.'
  },
  {
    id: 'SOL5220',
    name: 'SPL Token: Missing Revoke After Transfer',
    severity: 'medium',
    pattern: /transfer[\s\S]{0,100}(?:delegate|approval)(?![\s\S]{0,100}revoke)/i,
    description: 'Token transferred without revoking prior approvals. Old delegates may still have access rights.',
    recommendation: 'Revoke approvals when transferring tokens between owners. Check delegated_amount before operations.'
  },

  // ============================================
  // OtterSec LP Token Oracle Manipulation ($200M)
  // Source: osec.io/blog/reports/2022-02-16-lp-token-oracle-manipulation
  // ============================================
  {
    id: 'SOL5221',
    name: 'OtterSec: AMM Price Oracle Manipulation ($200M Bluff)',
    severity: 'critical',
    pattern: /lp_token[\s\S]{0,50}(?:price|value|oracle)[\s\S]{0,100}(?:reserve|balance)/i,
    description: 'OtterSec $200M bluff: LP token price derived from reserves can be manipulated via flash loans. Move AMM price to exploit lending.',
    recommendation: 'Use fair pricing for LP tokens (geometric mean). Never derive LP value directly from reserve balances.'
  },
  {
    id: 'SOL5222',
    name: 'OtterSec: Reserve-Based LP Valuation Attack',
    severity: 'critical',
    pattern: /(?:reserve_a|reserve_b|pool_balance)[\s\S]{0,100}(?:lp_price|token_value)/i,
    description: 'LP token value calculated from reserves is manipulable. Flash loan can skew reserves to inflate collateral.',
    recommendation: 'Use TWAP for LP valuation. Apply Drift-style oracle guardrails for lending protocols.'
  },
  {
    id: 'SOL5223',
    name: 'Drift Oracle Guardrails Pattern',
    severity: 'info',
    pattern: /oracle[\s\S]{0,100}(?:guardrail|guard|limit|bound)/i,
    description: 'Reference: Drift Protocol oracle guardrails prevent price manipulation attacks. Good security pattern.',
    recommendation: 'Implement oracle guardrails: max price deviation per slot, staleness checks, confidence intervals.'
  },

  // ============================================
  // Wormhole Attack Deep Patterns
  // Sources: samczsun, Halborn, Kudelski, Entropy analyses
  // ============================================
  {
    id: 'SOL5224',
    name: 'Wormhole: Signature Set Spoofing',
    severity: 'critical',
    pattern: /SignatureSet|guardian.*signature[\s\S]{0,100}(?:verify|check)(?![\s\S]{0,100}owner_check)/i,
    description: 'Wormhole $326M: Attacker spoofed SignatureSet by analyzing input accounts. Fake guardian signatures accepted.',
    recommendation: 'Verify SignatureSet account ownership. Validate guardian set membership cryptographically.'
  },
  {
    id: 'SOL5225',
    name: 'Wormhole: Delegation Chain Verification Gap',
    severity: 'critical',
    pattern: /delegate[\s\S]{0,50}(?:verify|sign)[\s\S]{0,100}(?:chain|forward)(?![\s\S]{0,100}root_verify)/i,
    description: 'Wormhole attack: Delegation of signature verification without proper chain validation. Must trace to root verifier.',
    recommendation: 'When chaining verification delegations, ensure complete path to trusted root. Never trust intermediate delegators.'
  },
  {
    id: 'SOL5226',
    name: 'Wormhole: Unmodified Reference Account Exploit',
    severity: 'high',
    pattern: /AccountInfo[\s\S]{0,50}(?:readonly|reference)[\s\S]{0,100}(?!verify|check|constraint)/i,
    description: 'Kudelski analysis: Reference-only accounts still need validation. Attacker passed malicious account as "reference".',
    recommendation: 'Validate unmodified reference accounts. Check owner, discriminator, and expected state.'
  },

  // ============================================
  // Cashio Root of Trust Attack ($52M)
  // Source: samczsun thread
  // ============================================
  {
    id: 'SOL5227',
    name: 'Cashio: Root of Trust Chain Failure',
    severity: 'critical',
    pattern: /(?:collateral|backing|reserve)[\s\S]{0,100}(?:verify|validate)[\s\S]{0,100}(?!root|origin|source)/i,
    description: 'Cashio $52M: Failed to trace validation to root of trust. Attacker created fake collateral chain that passed intermediate checks.',
    recommendation: 'Trace validation chains to immutable root (program ID, hardcoded keys). Never trust intermediate validators alone.'
  },
  {
    id: 'SOL5228',
    name: 'Cashio: Infinite Mint via Fake Collateral',
    severity: 'critical',
    pattern: /mint[\s\S]{0,50}(?:collateral|backing)[\s\S]{0,100}(?!whitelist|known_mints|verified_mints)/i,
    description: 'Cashio attack: Minting against unverified collateral. Created worthless tokens, minted infinite CASH.',
    recommendation: 'Whitelist valid collateral mints. Check mint address against known good list, not just structure.'
  },

  // ============================================
  // Audit Methodology Patterns (Sec3/OtterSec)
  // ============================================
  {
    id: 'SOL5229',
    name: 'Sec3 Audit: Owner Check Methodology',
    severity: 'high',
    pattern: /AccountInfo[\s\S]{0,200}(?!owner\s*==|owner\.eq|\.owner\.key\(\))/i,
    description: 'Sec3 audit methodology: Every AccountInfo should have owner verification unless explicitly trusted (system accounts).',
    recommendation: 'Audit checklist: For each AccountInfo, verify owner == expected_program. Use Anchor constraints.'
  },
  {
    id: 'SOL5230',
    name: 'Sec3 Audit: Signer Check Methodology',
    severity: 'high',
    pattern: /(?:admin|authority|owner|operator)[\s\S]{0,50}AccountInfo(?![\s\S]{0,100}is_signer|[\s\S]{0,100}Signer)/i,
    description: 'Sec3 audit methodology: Privileged operations require signer verification. Authority without is_signer check.',
    recommendation: 'Use #[account(signer)] or manually check account.is_signer for all authority operations.'
  },

  // ============================================
  // Advanced Audit Patterns from Solsec Collection
  // ============================================
  {
    id: 'SOL5231',
    name: 'Kudelski: Ownership Validation Gap',
    severity: 'high',
    pattern: /(?:try_borrow|borrow_mut|try_borrow_mut)[\s\S]{0,100}(?!owner|check_owner)/i,
    description: 'Kudelski audit pattern: Account data borrowed without ownership validation. Attacker-controlled accounts may be passed.',
    recommendation: 'Verify account ownership before borrowing data. Use Anchor Account<> types with constraints.'
  },
  {
    id: 'SOL5232',
    name: 'Neodyme: Common Pitfall - Missing Account Data Check',
    severity: 'high',
    pattern: /deserialize|try_from_slice[\s\S]{0,100}(?!is_initialized|discriminator|magic)/i,
    description: 'Neodyme pitfall: Deserializing account data without checking initialization or type discriminator.',
    recommendation: 'Check is_initialized and discriminator before deserializing. Use Anchor for automatic discriminator checks.'
  },
  {
    id: 'SOL5233',
    name: 'Armani Sealevel: Invoke Signed Verification',
    severity: 'high',
    pattern: /invoke_signed[\s\S]{0,100}(?!program_id|expected_program)/i,
    description: 'Armani tip: invoke_signed should verify target program_id. Attacker may redirect CPI to malicious program.',
    recommendation: 'Always verify: require!(cpi_program.key() == expected_program_id, ErrorCode::InvalidProgram);'
  },

  // ============================================
  // Trail of Bits DeFi Patterns
  // ============================================
  {
    id: 'SOL5234',
    name: 'ToB: DeFi Composability Attack Surface',
    severity: 'medium',
    pattern: /(?:external|cpi|invoke)[\s\S]{0,100}(?:defi|lending|swap)(?![\s\S]{0,100}reentrancy_guard)/i,
    description: 'Trail of Bits: DeFi composability creates attack surface. Each external integration adds risk.',
    recommendation: 'Audit all external integrations. Add reentrancy guards for multi-protocol interactions.'
  },
  {
    id: 'SOL5235',
    name: 'ToB: System Risk in DeFi Stacks',
    severity: 'medium',
    pattern: /(?:yield|aggregator|vault)[\s\S]{0,100}(?:deposit|withdraw)[\s\S]{0,100}(?:external|upstream)/i,
    description: 'Trail of Bits: Yield aggregators inherit all downstream protocol risks. System risk compounds.',
    recommendation: 'Document dependency graph. Implement circuit breakers. Monitor upstream protocol health.'
  },

  // ============================================
  // Zellic Anchor Vulnerabilities
  // Source: zellic.io/blog/the-vulnerabilities-youll-write-with-anchor
  // ============================================
  {
    id: 'SOL5236',
    name: 'Zellic: Anchor Init If Needed Race',
    severity: 'high',
    pattern: /init_if_needed[\s\S]{0,100}(?:payer|space)(?![\s\S]{0,100}realloc_guard)/i,
    description: 'Zellic: init_if_needed can race between initialization check and execution. Front-runner may initialize first.',
    recommendation: 'Avoid init_if_needed for sensitive accounts. Use explicit initialization with ownership verification.'
  },
  {
    id: 'SOL5237',
    name: 'Zellic: Anchor Account Realloc Vulnerability',
    severity: 'high',
    pattern: /realloc[\s\S]{0,50}(?:mut|zero_copy)(?![\s\S]{0,100}constraint)/i,
    description: 'Zellic: Account reallocation without proper constraints. Attacker may manipulate account size.',
    recommendation: 'Add realloc constraints: #[account(realloc = NEW_SIZE, realloc::payer = payer, realloc::zero = false)]'
  },
  {
    id: 'SOL5238',
    name: 'Zellic: Anchor Close Destination Attack',
    severity: 'critical',
    pattern: /close\s*=[\s\S]{0,50}(?!sol_destination|authority|admin)/i,
    description: 'Zellic: Account closure destination not restricted. Attacker may close to their own account.',
    recommendation: 'Restrict close destination: #[account(close = authority)] where authority is verified.'
  },

  // ============================================
  // DeFi MOOC samczsun Patterns
  // ============================================
  {
    id: 'SOL5239',
    name: 'samczsun: Cross-Chain Bridge Invariant',
    severity: 'critical',
    pattern: /bridge[\s\S]{0,100}(?:lock|unlock|mint|burn)[\s\S]{0,100}(?!invariant|balance_check)/i,
    description: 'samczsun MOOC: Cross-chain bridges must maintain invariant: locked = minted. Any gap enables infinite mint.',
    recommendation: 'Verify bridge invariant atomically. Sum of locked must equal sum of minted across all chains.'
  },
  {
    id: 'SOL5240',
    name: 'samczsun: Smart Contract Security Mindset',
    severity: 'info',
    pattern: /(?:security|audit|review)[\s\S]{0,100}(?:checklist|methodology)/i,
    description: 'samczsun MOOC pattern: Security mindset - assume all inputs are adversarial. Test with attacker mentality.',
    recommendation: 'Think like an attacker. For each function, ask: How can this be exploited?'
  },

  // ============================================
  // CMichel Audit Methodology
  // ============================================
  {
    id: 'SOL5241',
    name: 'CMichel: Smart Contract Auditor Pattern',
    severity: 'info',
    pattern: /audit[\s\S]{0,100}(?:finding|vulnerability|issue)/i,
    description: 'CMichel methodology: Systematic approach to auditing - map attack surface, identify trust boundaries, test edge cases.',
    recommendation: 'Follow structured audit methodology: 1) Understand system 2) Map trust boundaries 3) Test assumptions.'
  },

  // ============================================
  // Solana Stake Pool Vulnerabilities (Multiple Audits)
  // ============================================
  {
    id: 'SOL5242',
    name: 'Stake Pool: Semantic Inconsistency Attack',
    severity: 'high',
    pattern: /stake_pool[\s\S]{0,100}(?:deposit|withdraw)[\s\S]{0,100}(?:validator|vote)/i,
    description: 'Sec3 stake pool finding: Semantic inconsistency between expected and actual validator behavior. Audited code still vulnerable.',
    recommendation: 'Test semantic expectations, not just code correctness. Verify validator behavior matches documentation.'
  },
  {
    id: 'SOL5243',
    name: 'Stake Pool: Prior Audit False Confidence',
    severity: 'medium',
    pattern: /audit(?:ed)?[\s\S]{0,50}(?:kudelski|neodyme|quantstamp)[\s\S]{0,100}(?:secure|safe)/i,
    description: 'Stake Pool had 3 audits (Kudelski, Neodyme, Quantstamp) yet still contained vulnerabilities. Audits reduce but do not eliminate risk.',
    recommendation: 'Do not assume audited = secure. Continuous security monitoring required post-audit.'
  },

  // ============================================
  // Solend Malicious Lending Market
  // Source: Rooter incident report + Kudelski analysis
  // ============================================
  {
    id: 'SOL5244',
    name: 'Solend: Malicious Market Creation',
    severity: 'critical',
    pattern: /create_market|lending_market[\s\S]{0,100}(?:permissionless|anyone)(?![\s\S]{0,100}whitelist)/i,
    description: 'Solend incident: Malicious lending market created permissionlessly. Users deposited into attacker-controlled market.',
    recommendation: 'Whitelist valid markets in protocol. Warn users about non-official markets with clear UI indicators.'
  },
  {
    id: 'SOL5245',
    name: 'Solend: Reserve Configuration Bypass',
    severity: 'high',
    pattern: /reserve[\s\S]{0,50}(?:config|settings)[\s\S]{0,100}(?:update|modify)(?![\s\S]{0,100}timelock)/i,
    description: 'Lending reserve configurations can be modified to enable attacks. Oracle, LTV changes without delay.',
    recommendation: 'Add timelock to reserve configuration changes. Emit events for all config modifications.'
  },

  // ============================================
  // Jet Governance PoC (OtterSec)
  // ============================================
  {
    id: 'SOL5246',
    name: 'Jet Governance: Vote Manipulation',
    severity: 'high',
    pattern: /(?:vote|ballot|proposal)[\s\S]{0,100}(?:weight|power)[\s\S]{0,100}(?!snapshot|checkpoint)/i,
    description: 'Jet Governance PoC: Vote weight can be manipulated between snapshot and execution. Flash loan votes.',
    recommendation: 'Use vote escrow with snapshots. Weight determined at proposal creation, not execution.'
  },
  {
    id: 'SOL5247',
    name: 'Jet Governance: Proposal Timing Attack',
    severity: 'medium',
    pattern: /proposal[\s\S]{0,50}(?:execute|finalize)[\s\S]{0,100}(?:delay|timelock)/i,
    description: 'Governance proposals with short delays enable surprise attacks. Community has no time to respond.',
    recommendation: 'Minimum 3-day delay between proposal passing and execution. Allow emergency cancellation.'
  },

  // ============================================
  // Cashio Exploit PoC (PNM Workshop)
  // ============================================
  {
    id: 'SOL5248',
    name: 'Cashio PoC: Account Validation Hierarchy',
    severity: 'critical',
    pattern: /(?:bank|crate_token|collateral)[\s\S]{0,100}(?:validate|verify)(?![\s\S]{0,100}crate_mint)/i,
    description: 'Cashio PoC pattern: Validation checked intermediate accounts but not root crate_mint. Full hierarchy validation required.',
    recommendation: 'Validate entire account hierarchy from root to leaf. Each level must reference its parent correctly.'
  },
  {
    id: 'SOL5249',
    name: 'Cashio PoC: Input Account Trust Chain',
    severity: 'critical',
    pattern: /input[\s\S]{0,50}account[\s\S]{0,100}(?:pass|provide|supply)[\s\S]{0,100}(?!trace_trust|verify_chain)/i,
    description: 'All input accounts form trust chains. Each must be traced to trusted root (program ID, known key).',
    recommendation: 'Map trust chains for all input accounts. Document and verify each trust relationship.'
  },

  // ============================================
  // Additional Patterns from Audit Reports
  // ============================================
  {
    id: 'SOL5250',
    name: 'Halborn: Integer Truncation in Fee Calculation',
    severity: 'high',
    pattern: /fee[\s\S]{0,50}(?:as\s+u32|as\s+u16|truncate)(?![\s\S]{0,50}check_overflow)/i,
    description: 'Halborn pattern: Fee calculations truncated to smaller integers can underflow or lose precision.',
    recommendation: 'Use u64/u128 for all fee calculations. Check for truncation before downcasting.'
  },
  {
    id: 'SOL5251',
    name: 'Bramah: Cross-Program State Inconsistency',
    severity: 'high',
    pattern: /(?:maple|crema)[\s\S]{0,100}(?:state|position)[\s\S]{0,100}(?:sync|update)(?![\s\S]{0,100}atomic)/i,
    description: 'Bramah audit pattern: State updated across programs non-atomically. Inconsistent state enables exploits.',
    recommendation: 'Make cross-program state updates atomic. Use single transaction or implement rollback.'
  },
  {
    id: 'SOL5252',
    name: 'Quantstamp: Quarry Reward Distribution',
    severity: 'medium',
    pattern: /reward[\s\S]{0,50}(?:distribute|claim)[\s\S]{0,100}(?:rate|per_second)/i,
    description: 'Quantstamp Quarry pattern: Reward distribution rate changes can be exploited with timing attacks.',
    recommendation: 'Checkpoint rewards before rate changes. Calculate owed rewards with previous rate.'
  },
  {
    id: 'SOL5253',
    name: 'HashCloak: Light Protocol Proof Verification',
    severity: 'critical',
    pattern: /proof[\s\S]{0,50}(?:verify|validate)[\s\S]{0,100}(?:merkle|zk)/i,
    description: 'HashCloak Light Protocol pattern: Zero-knowledge proof verification must be complete. Partial verification exploitable.',
    recommendation: 'Verify all proof components. Do not skip verification steps even for optimization.'
  },
  {
    id: 'SOL5254',
    name: 'SlowMist: Larix Price Feed Delay',
    severity: 'high',
    pattern: /price[\s\S]{0,50}(?:feed|oracle)[\s\S]{0,100}(?:delay|latency|lag)/i,
    description: 'SlowMist Larix pattern: Price feed delays enable front-running. Oracle update visible before transaction execution.',
    recommendation: 'Use on-chain price averaging. Implement slippage protection for price-sensitive operations.'
  },
  {
    id: 'SOL5255',
    name: 'Opcodes: Streamflow Time-Based Vesting',
    severity: 'medium',
    pattern: /(?:vesting|stream|unlock)[\s\S]{0,100}(?:time|timestamp|slot)/i,
    description: 'Opcodes Streamflow pattern: Time-based vesting with slot dependency. Validator can influence unlock timing.',
    recommendation: 'Use monotonic slot-based timing. Add small buffer for timing-sensitive operations.'
  },
  
  // ============================================
  // Infrastructure and Operational Patterns
  // ============================================
  {
    id: 'SOL5256',
    name: 'Multisig Operational Security',
    severity: 'high',
    pattern: /multisig[\s\S]{0,100}(?:threshold|signers)[\s\S]{0,100}(?:2|two|single)/i,
    description: 'Multisig with low threshold (2/n) for critical operations. Single compromise enables attack.',
    recommendation: 'Use 3/5 or higher for critical operations. Geographically distribute signers.'
  },
  {
    id: 'SOL5257',
    name: 'Upgrade Authority Centralization',
    severity: 'high',
    pattern: /upgrade[\s\S]{0,50}authority[\s\S]{0,100}(?:single|one|solo)/i,
    description: 'Single upgrade authority creates central point of failure. Compromise enables malicious upgrade.',
    recommendation: 'Use multisig for upgrade authority. Consider making program immutable after stabilization.'
  },
  {
    id: 'SOL5258',
    name: 'Emergency Pause Mechanism',
    severity: 'medium',
    pattern: /(?:pause|emergency|shutdown)[\s\S]{0,100}(?:mechanism|function|feature)(?![\s\S]{0,100}implemented)/i,
    description: 'Protocol lacks emergency pause mechanism. Cannot respond quickly to attacks.',
    recommendation: 'Implement guardian-controlled pause. Test pause/unpause flow regularly.'
  },
  {
    id: 'SOL5259',
    name: 'Key Rotation Procedure',
    severity: 'medium',
    pattern: /(?:key|authority)[\s\S]{0,50}(?:rotate|change|update)[\s\S]{0,100}(?!procedure|documented)/i,
    description: 'No documented key rotation procedure. Compromised keys cannot be replaced safely.',
    recommendation: 'Document and test key rotation. Implement timelock for authority changes.'
  },
  {
    id: 'SOL5260',
    name: 'Deployment Safety Check',
    severity: 'high',
    pattern: /(?:deploy|upgrade)[\s\S]{0,100}(?:mainnet|production)[\s\S]{0,100}(?!peer_review|multi_sig)/i,
    description: 'Production deployment without multi-party verification. Single point of failure for critical action.',
    recommendation: 'Require 3+ team members for production deployments. Use deployment ceremony with verification.'
  },

  // ============================================
  // Emerging 2026 Patterns from Research
  // ============================================
  {
    id: 'SOL5261',
    name: 'AI-Assisted Code Generation Vulnerabilities',
    severity: 'medium',
    pattern: /(?:copilot|gpt|claude|ai)[\s\S]{0,50}(?:generated|assisted|suggested)(?![\s\S]{0,100}reviewed)/i,
    description: 'AI-generated code may contain subtle vulnerabilities. Copilot/GPT suggestions need human security review.',
    recommendation: 'Always review AI-generated code for security. AI optimizes for correctness, not security.'
  },
  {
    id: 'SOL5262',
    name: 'Firedancer Validator Compatibility',
    severity: 'medium',
    pattern: /(?:firedancer|jump|validator)[\s\S]{0,100}(?:compat|different|behavior)/i,
    description: 'Firedancer (Jump) validator implementation may have different behavior than Solana Labs client.',
    recommendation: 'Test with both validator implementations. Document any behavior differences.'
  },
  {
    id: 'SOL5263',
    name: 'Token-2022 Extension Interaction Bugs',
    severity: 'high',
    pattern: /token.2022|spl_token_2022[\s\S]{0,100}(?:extension|hook|transfer_fee)/i,
    description: 'Token-2022 extensions create new attack surfaces. Transfer hooks, fees, and metadata extensions need audit.',
    recommendation: 'Audit all Token-2022 extension interactions. Test with various extension combinations.'
  },
  {
    id: 'SOL5264',
    name: 'Compressed NFT State Sync',
    severity: 'high',
    pattern: /(?:cnft|compressed)[\s\S]{0,100}(?:merkle|state)[\s\S]{0,100}(?:sync|update)/i,
    description: 'Compressed NFT state relies on merkle proofs. Outdated proofs can cause sync issues or exploits.',
    recommendation: 'Use fresh merkle proofs for each transaction. Implement proof freshness validation.'
  },
  {
    id: 'SOL5265',
    name: 'Blinks Security Assessment',
    severity: 'medium',
    pattern: /blink|action[\s\S]{0,50}(?:url|link)[\s\S]{0,100}(?:execute|sign)/i,
    description: 'Solana Blinks (actions) can execute transactions from URLs. Malicious blinks may trick users.',
    recommendation: 'Validate action sources. Show clear transaction preview before signing.'
  },
  
  // ============================================
  // Additional Refinement Patterns
  // ============================================
  {
    id: 'SOL5266',
    name: 'Anchor PDA Seeds Order Sensitivity',
    severity: 'medium',
    pattern: /seeds\s*=\s*\[[\s\S]*?,[\s\S]*?\][\s\S]{0,100}(?!order_check|canonical)/i,
    description: 'PDA seeds order matters for derivation. Inconsistent ordering between derive and verify causes failures.',
    recommendation: 'Document and enforce consistent seed ordering. Use constants for seed strings.'
  },
  {
    id: 'SOL5267',
    name: 'Account Data Borrowing Lifetime',
    severity: 'high',
    pattern: /borrow(?:_mut)?[\s\S]{0,50}data[\s\S]{0,100}(?:drop|release|scope)/i,
    description: 'Holding account data borrow across CPI prevents other instructions from accessing account.',
    recommendation: 'Drop data borrows before CPI calls. Reborrow after CPI if needed.'
  },
  {
    id: 'SOL5268',
    name: 'Zero-Copy Account Alignment',
    severity: 'medium',
    pattern: /zero_copy|#\[zero_copy\][\s\S]{0,100}(?:align|repr)/i,
    description: 'Zero-copy accounts require proper memory alignment. Misalignment causes deserialization failures.',
    recommendation: 'Use #[repr(C)] for zero-copy structs. Verify 8-byte alignment for all fields.'
  },
  {
    id: 'SOL5269',
    name: 'Event Ordering Dependency',
    severity: 'low',
    pattern: /emit!|log[\s\S]{0,50}(?:event|msg)[\s\S]{0,100}(?:before|after|order)/i,
    description: 'Event emission ordering may be inconsistent across network. Do not depend on event order for logic.',
    recommendation: 'Include sequence numbers in events. Do not rely on event ordering for state reconstruction.'
  },
  {
    id: 'SOL5270',
    name: 'Compute Budget Exhaustion Attack',
    severity: 'high',
    pattern: /compute[\s\S]{0,50}(?:budget|units)[\s\S]{0,100}(?:loop|iterate|recursive)/i,
    description: 'Unbounded loops can exhaust compute budget, causing transaction failure. DoS vector.',
    recommendation: 'Add iteration limits. Process in batches with pagination across multiple transactions.'
  },

  // ============================================
  // Latest 2025-2026 Exploit Patterns
  // ============================================
  {
    id: 'SOL5271',
    name: 'Whale Liquidation Cascade ($258M)',
    severity: 'critical',
    pattern: /liquidat[\s\S]{0,100}(?:cascade|chain|domino)(?![\s\S]{0,100}circuit_breaker)/i,
    description: '$258M whale liquidation cascade (Nov 2025). Single large liquidation triggered systemic failures.',
    recommendation: 'Implement liquidation caps per block. Add circuit breakers for cascade detection.'
  },
  {
    id: 'SOL5272',
    name: 'MEV Validator Concentration Risk',
    severity: 'medium',
    pattern: /(?:jito|mev)[\s\S]{0,100}(?:validator|client)[\s\S]{0,100}(?:dominance|concentration)/i,
    description: 'Jito client 88% dominance creates concentrated MEV attack surface. Single bug affects most validators.',
    recommendation: 'Monitor client diversity. Support multiple MEV solutions for redundancy.'
  },
  {
    id: 'SOL5273',
    name: 'Hosting Provider Concentration',
    severity: 'medium',
    pattern: /(?:hosting|provider|datacenter)[\s\S]{0,100}(?:teraswitch|latitude)[\s\S]{0,100}stake/i,
    description: 'Teraswitch + Latitude.sh control 43% of network stake. Infrastructure concentration risk.',
    recommendation: 'Diversify validator hosting. Monitor stake distribution by infrastructure provider.'
  },
  {
    id: 'SOL5274',
    name: 'DeFi $3.1B Breach Pattern',
    severity: 'critical',
    pattern: /(?:reentrancy|access.control|oracle.manipulation|account.validation)/i,
    description: 'DeFi security breaches exceeded $3.1B in 2025. Main causes: reentrancy, access control, oracle manipulation, account validation.',
    recommendation: 'Focus security efforts on the big four: reentrancy guards, access control, oracle safety, account validation.'
  },
  {
    id: 'SOL5275',
    name: 'Loopscale Admin Exploit ($5.8M)',
    severity: 'critical',
    pattern: /admin[\s\S]{0,50}(?:withdraw|drain)[\s\S]{0,100}(?!timelock|multisig|governance)/i,
    description: 'Loopscale $5.8M (Apr 2025): Admin function allowed unrestricted withdrawal. ThreeSigma analysis.',
    recommendation: 'Add timelock to admin withdrawals. Use governance for large value transfers.'
  },

  // ============================================
  // Final Pattern Set - Security Best Practices
  // ============================================
  {
    id: 'SOL5276',
    name: 'Security Pattern: Defense in Depth',
    severity: 'info',
    pattern: /(?:single|only.one)[\s\S]{0,50}(?:check|validation|guard)/i,
    description: 'Security best practice: Single point of validation is insufficient. Layer multiple checks.',
    recommendation: 'Implement defense in depth: multiple independent checks that each catch different attack vectors.'
  },
  {
    id: 'SOL5277',
    name: 'Security Pattern: Fail Secure',
    severity: 'info',
    pattern: /(?:default|fallback)[\s\S]{0,50}(?:allow|permit|success)/i,
    description: 'Security best practice: Fail secure - default to deny. Success requires explicit validation.',
    recommendation: 'Design for fail-secure: if any check is uncertain, deny. Never default to allowing action.'
  },
  {
    id: 'SOL5278',
    name: 'Security Pattern: Least Privilege',
    severity: 'info',
    pattern: /(?:admin|authority)[\s\S]{0,100}(?:can|able|permitted)[\s\S]{0,100}(?:all|any|everything)/i,
    description: 'Security best practice: Least privilege - grant minimum permissions needed. Reduce blast radius.',
    recommendation: 'Split admin roles by function. Each authority should only have permissions it strictly needs.'
  },
  {
    id: 'SOL5279',
    name: 'Security Pattern: Secure by Default',
    severity: 'info',
    pattern: /(?:config|setting|option)[\s\S]{0,50}(?:default|initial)[\s\S]{0,100}(?:insecure|open|permissive)/i,
    description: 'Security best practice: Secure by default - initial configuration should be restrictive.',
    recommendation: 'Default to maximum security. Users must explicitly enable riskier features.'
  },
  {
    id: 'SOL5280',
    name: 'Security Pattern: Audit Trail',
    severity: 'info',
    pattern: /(?:admin|critical|sensitive)[\s\S]{0,100}(?:action|operation)(?![\s\S]{0,100}emit|[\s\S]{0,100}event|[\s\S]{0,100}log)/i,
    description: 'Security best practice: All sensitive operations should emit events for audit trail.',
    recommendation: 'Emit events for all state-changing operations. Include relevant context for forensics.'
  }
];

export function checkBatch92Patterns(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  
  if (!input.rust?.content) return findings;
  const content = input.rust.content;

  for (const pattern of BATCH_92_PATTERNS) {
    if (pattern.pattern.test(content)) {
      findings.push({
        id: pattern.id,
        title: pattern.name,
        severity: pattern.severity,
        description: pattern.description,
        location: { file: input.path },
        recommendation: pattern.recommendation
      });
    }
  }

  return findings;
}
