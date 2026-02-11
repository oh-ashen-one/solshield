/**
 * Batch 114: Feb 2026 — Account Revival, Address Pre-funding DoS, Rent Epoch Drain,
 *                        Validator Gossip Manipulation, ZK Compression Exploits
 * 
 * Sources:
 * - dev.to/4k_mira: "Solana Vulnerabilities Every Developer Should Know" (Jan 2026)
 * - SoluLab: Smart Contract Audit Readiness 2026 findings
 * - Nadcab: 2026 Audit Checklist — $1.8B lost in 2025 from preventable vulns
 * - Solana validator network gossip protocol analysis
 * - ZK Compression (Light Protocol) security considerations
 * 
 * Patterns: SOL7696-SOL7726 (31 patterns)
 * Focus: Account revival attacks, deterministic address pre-funding DoS,
 *        rent epoch drainage, validator-level exploits, ZK compression safety
 */

import type { PatternInput, Finding } from './index.js';

const BATCH_114_PATTERNS: {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  pattern: RegExp;
  description: string;
  recommendation: string;
}[] = [
  // === ACCOUNT REVIVAL ATTACKS ===
  {
    id: 'SOL7696',
    title: 'Account Revival After Close — Lamport Re-funding',
    severity: 'critical',
    pattern: /close\s*=|close_account|AccountInfo.*lamports.*=\s*0/,
    description: 'After closing an account by zeroing lamports, an attacker can re-fund the address with lamports in the same transaction, reviving the account with stale data. The runtime only garbage-collects zero-lamport accounts at slot boundaries.',
    recommendation: 'Zero out all account data AND lamports when closing. Use a discriminator/is_initialized flag checked on every instruction. Consider using Anchor close constraint which handles data zeroing.'
  },
  {
    id: 'SOL7697',
    title: 'Account Revival — Missing Data Zeroing on Close',
    severity: 'critical',
    pattern: /\.to_account_info\(\)\.lamports\.borrow_mut\(\)|sub_lamports/,
    description: 'Draining lamports without zeroing account data leaves the data intact if the account is revived. An attacker re-funding the account gets access to the previous state, potentially re-using spent tokens or replaying completed operations.',
    recommendation: 'Always zero all account data bytes before draining lamports: account.data.borrow_mut().fill(0). Set discriminator to a "closed" sentinel value.'
  },
  {
    id: 'SOL7698',
    title: 'Deterministic Address Pre-funding DoS',
    severity: 'high',
    pattern: /create_account|CreateAccount|find_program_address.*create/,
    description: 'When a program creates accounts at deterministic (PDA) addresses, an attacker can pre-fund that address with 1 lamport before the program runs. The create_account instruction fails because the account already exists, causing denial of service.',
    recommendation: 'Use init_if_needed with proper discriminator checks, or use try_create patterns that handle pre-existing accounts. Alternatively, derive addresses with user-controlled seeds to prevent prediction.'
  },
  {
    id: 'SOL7699',
    title: 'Rent Epoch Drainage — Sub-Exempt Balance Decay',
    severity: 'medium',
    pattern: /lamports.*<.*rent|minimum_balance|rent_exempt|is_rent_exempt/,
    description: 'Accounts with lamport balances below the rent-exempt minimum lose lamports each epoch. An attacker who drains an account to just below rent-exemption threshold causes slow balance decay, eventually zeroing and garbage-collecting the account.',
    recommendation: 'Always ensure accounts maintain rent-exempt minimum balance after any lamport transfer. Use Rent::get()?.minimum_balance(data_len) to calculate and enforce the floor.'
  },
  {
    id: 'SOL7700',
    title: 'Rent Exemption Check Bypass via Data Reallocation',
    severity: 'high',
    pattern: /realloc|set_len|AccountInfo.*data_len/,
    description: 'Increasing account data size via realloc increases the rent-exempt minimum. If the lamport balance is not topped up accordingly, the account falls below rent exemption and begins decaying, potentially causing unexpected account deletion.',
    recommendation: 'After any realloc, recalculate and enforce the new rent-exempt minimum. Transfer additional lamports from the payer to cover the increased data size.'
  },
  // === VALIDATOR GOSSIP / NETWORK LEVEL ===
  {
    id: 'SOL7701',
    title: 'Gossip Protocol — Fake Vote Injection',
    severity: 'critical',
    pattern: /vote_account|VoteInstruction|process_vote|vote_state/,
    description: 'Validators gossip votes to reach consensus. A malicious validator can inject fake votes referencing non-existent slots to confuse fork choice in other validators, potentially causing temporary chain splits or delayed finality.',
    recommendation: 'Implement strict vote validation: verify slot exists, bank hash matches, and vote account authority. Rate-limit gossip messages per validator identity.'
  },
  {
    id: 'SOL7702',
    title: 'Turbine Block Propagation — Shred Withholding',
    severity: 'high',
    pattern: /shred|turbine|block_production|leader_schedule/,
    description: 'A leader producing a block can selectively withhold shreds from specific validators via Turbine tree manipulation, creating an information asymmetry that can be exploited for MEV or to cause missed votes.',
    recommendation: 'Implement redundant shred repair paths. Monitor for systematic shred loss patterns from specific leaders. Use erasure coding recovery aggressively.'
  },
  {
    id: 'SOL7703',
    title: 'Gossip Protocol — Eclipse Attack via Peer Table Poisoning',
    severity: 'high',
    pattern: /gossip|contact_info|cluster_info|peer|node_pubkey/,
    description: 'Attacker floods the gossip network with fake ContactInfo entries pointing to attacker-controlled IPs. This can eclipse a validator from legitimate peers, feeding it a false view of the chain.',
    recommendation: 'Implement stake-weighted peer selection. Validate ContactInfo signatures against known validator identities. Maintain minimum connections to high-stake validators.'
  },
  // === ZK COMPRESSION EXPLOITS ===
  {
    id: 'SOL7704',
    title: 'ZK Compressed Account — Merkle Proof Manipulation',
    severity: 'critical',
    pattern: /compressed|merkle_tree|state_tree|CompressedAccount|light_protocol/,
    description: 'ZK compressed accounts store state in Merkle trees. If proof verification is incomplete or the nullifier set is not checked, an attacker can provide valid-looking proofs for already-spent compressed accounts, enabling double-spend.',
    recommendation: 'Always verify the full Merkle proof path AND check the nullifier/sequence number to prevent replay. Use Light Protocol SDK which handles proof verification correctly.'
  },
  {
    id: 'SOL7705',
    title: 'ZK Compression — Concurrent Merkle Tree Race Condition',
    severity: 'high',
    pattern: /ConcurrentMerkleTree|concurrent.*merkle|changelog|canopy/,
    description: 'Concurrent Merkle trees allow parallel updates but have a bounded changelog. If more updates occur than the changelog depth allows between a proof generation and verification, the proof becomes invalid, causing transaction failures or requiring expensive retries.',
    recommendation: 'Set adequate maxDepth and maxBufferSize for expected throughput. Implement retry logic with proof refresh. Monitor changelog utilization.'
  },
  {
    id: 'SOL7706',
    title: 'ZK Compression — Forester Manipulation',
    severity: 'high',
    pattern: /forester|nullifier_queue|address_queue|rollover/,
    description: 'Foresters (off-chain indexers) process nullifier queues and roll over state trees. A malicious forester could selectively delay or reorder nullifier processing, temporarily allowing double-spend windows for compressed accounts.',
    recommendation: 'Use multiple independent foresters. Implement on-chain verification of forester actions. Set maximum queue age limits with automatic fallback foresters.'
  },
  // === ECONOMIC / DeFi LOGIC ===
  {
    id: 'SOL7707',
    title: 'Token-2022 Transfer Hook — Reentrancy via CPI',
    severity: 'critical',
    pattern: /transfer_hook|TransferHook|execute.*hook|ExtraAccountMetaList/,
    description: 'Token-2022 transfer hooks execute arbitrary program logic during transfers via CPI. A malicious hook program can call back into the invoking program, creating a reentrancy vector. The hook runs with the caller\'s context.',
    recommendation: 'Implement reentrancy guards (mutex/lock flags) in any program that triggers Token-2022 transfers with hooks. Validate the hook program ID matches expected. Use check-effects-interactions pattern.'
  },
  {
    id: 'SOL7708',
    title: 'Confidential Transfer — Balance Encryption Mismatch',
    severity: 'critical',
    pattern: /confidential_transfer|ElGamal|Pedersen|decrypt.*balance|ConfidentialTransferMint/,
    description: 'Token-2022 confidential transfers use ElGamal encryption for balances. If the decryption key is compromised or the encryption proof is not verified, an attacker can forge encrypted balance proofs to mint tokens or transfer more than their actual balance.',
    recommendation: 'Verify all zero-knowledge proofs on-chain. Never trust client-provided decrypted balances. Ensure auditor keys are properly configured for compliance monitoring.'
  },
  {
    id: 'SOL7709',
    title: 'Permanent Delegate — Unauthorized Token Seizure',
    severity: 'high',
    pattern: /permanent_delegate|PermanentDelegate|set_authority.*delegate/,
    description: 'Token-2022 permanent delegate extension allows a designated authority to transfer or burn any holder\'s tokens without consent. If the delegate authority private key is compromised, all token holders are at risk.',
    recommendation: 'Use multisig for permanent delegate authority. Implement time-locked delegate actions. Clearly disclose permanent delegate to token holders. Consider governance-controlled delegate.'
  },
  {
    id: 'SOL7710',
    title: 'Non-Transferable Token — Bypass via Delegate Burn and Re-mint',
    severity: 'medium',
    pattern: /non_transferable|NonTransferable|soulbound/,
    description: 'Non-transferable (soulbound) tokens on Token-2022 can potentially be circumvented if the mint authority can burn from any holder and re-mint to a new address. This defeats the non-transferability guarantee.',
    recommendation: 'If using non-transferable tokens, ensure mint authority is revoked or controlled by immutable governance. Implement burn restrictions alongside non-transferability.'
  },
  // === INSTRUCTION INTROSPECTION & SIMULATION ===
  {
    id: 'SOL7711',
    title: 'Transaction Simulation Divergence — Conditional Logic Based on Cluster',
    severity: 'high',
    pattern: /simulation|simulate|SanitizedMessage|is_simulation|cluster.*type/,
    description: 'Programs that behave differently based on whether they detect simulation (via cluster type, slot number heuristics, or instruction introspection) can show benign behavior during wallet preview but execute malicious logic on-chain.',
    recommendation: 'Wallets should use recent blockhashes and realistic fee payers for simulation. Programs should never branch on simulation detection. Users should verify on-chain results independently.'
  },
  {
    id: 'SOL7712',
    title: 'Instruction Introspection — Sysvar Manipulation for Authorization',
    severity: 'high',
    pattern: /instructions_sysvar|load_instruction_at|get_instruction_relative|Sysvar.*Instructions/,
    description: 'Programs using instruction introspection (checking adjacent instructions in the transaction) for authorization can be fooled. An attacker can construct transactions that include the expected adjacent instructions alongside malicious ones.',
    recommendation: 'Do not rely solely on instruction introspection for authorization. Use proper signer checks and PDA authority. If introspection is needed, verify the entire transaction instruction set, not just adjacent instructions.'
  },
  {
    id: 'SOL7713',
    title: 'Versioned Transaction — Address Lookup Table Swap',
    severity: 'high',
    pattern: /AddressLookupTable|lookup_table|v0.*transaction|VersionedTransaction/,
    description: 'Versioned transactions (v0) use Address Lookup Tables (ALTs) to compress account lists. If an ALT is modified between transaction construction and execution, the resolved addresses may differ from what the user intended, leading to interactions with wrong accounts.',
    recommendation: 'Freeze critical ALTs after initialization. Wallets should resolve ALT entries at simulation time and verify they match expected accounts. Use deactivation slots to prevent mid-flight ALT modifications.'
  },
  // === ACCESS CONTROL EDGE CASES ===
  {
    id: 'SOL7714',
    title: 'Authority Transfer Race — Concurrent Update Authority Change',
    severity: 'high',
    pattern: /set_authority|update_authority|transfer_authority|AuthorityType/,
    description: 'If two authority transfer transactions are submitted concurrently (e.g., admin rotation), the second may fail or succeed depending on ordering, potentially locking out the intended new authority or leaving authority with an unintended party.',
    recommendation: 'Implement nonce-based authority transfers where the new authority must acknowledge acceptance. Use two-phase authority transfer: propose then accept.'
  },
  {
    id: 'SOL7715',
    title: 'PDA Authority — Seeds Containing User-Controlled Data',
    severity: 'high',
    pattern: /find_program_address|create_program_address|seeds.*\[.*user|seeds.*\[.*input/,
    description: 'When PDA seeds include user-controlled data (strings, pubkeys), an attacker can craft inputs that collide with other legitimate PDAs or create PDAs that mimic authority accounts, bypassing signer checks.',
    recommendation: 'Prefix all user-controlled seeds with fixed discriminator bytes. Validate seed lengths. Use canonical bump (the one returned by find_program_address). Hash long or variable-length user inputs before using as seeds.'
  },
  {
    id: 'SOL7716',
    title: 'Multi-Instruction Atomic Exploit — Split Authorization',
    severity: 'high',
    pattern: /invoke_signed|invoke\s*\(|instruction.*\[.*instruction/,
    description: 'Attackers can split exploit logic across multiple instructions in a single atomic transaction. Instruction 1 sets up state, instruction 2 exploits it, instruction 3 cleans up — all atomically. This evades per-instruction monitoring.',
    recommendation: 'Implement invariant checks that verify global state consistency at the end of each instruction, not just at transaction boundaries. Use post-instruction assertion patterns.'
  },
  // === CROSS-PROGRAM / COMPOSABILITY ===
  {
    id: 'SOL7717',
    title: 'CPI to Unverified Program — Dynamic Program ID from Account Data',
    severity: 'critical',
    pattern: /invoke\s*\(&|invoke_signed\s*\(&|program_id.*from.*data|Pubkey::new_from_array/,
    description: 'Loading a program ID from on-chain account data to make a CPI call is dangerous. An attacker who controls that account can redirect the CPI to a malicious program that mimics the expected interface.',
    recommendation: 'Hardcode expected program IDs or verify them against known constants. Never load target program IDs from mutable account data. Use Anchor program type checks.'
  },
  {
    id: 'SOL7718',
    title: 'Return Data Spoofing via CPI Chain',
    severity: 'high',
    pattern: /set_return_data|get_return_data|sol_set_return_data|return_data/,
    description: 'When program A calls B which calls C, the return data is set by the last CPI that called set_return_data. Program A reading return data may get C\'s data instead of B\'s expected response, enabling spoofing.',
    recommendation: 'Always verify the program_id returned alongside return data matches the expected callee. Do not trust return data without program identity verification.'
  },
  // === MEV / ORDERING ===
  {
    id: 'SOL7719',
    title: 'Priority Fee Manipulation — Fee Bidding War Drainage',
    severity: 'medium',
    pattern: /ComputeBudgetInstruction|set_compute_unit_price|priority.*fee|compute_budget/,
    description: 'In competitive MEV scenarios, bots engage in priority fee bidding wars. A user\'s transaction can be sandwiched between attacker transactions that both outbid and benefit from the user\'s price impact, with the user paying inflated fees for worse execution.',
    recommendation: 'Use Jito bundles for MEV-protected transaction submission. Implement slippage controls in DeFi programs. Consider using private transaction submission channels.'
  },
  {
    id: 'SOL7720',
    title: 'Jito Bundle Atomic Arbitrage — Cross-Market Extraction',
    severity: 'medium',
    pattern: /jito|bundle|tip.*instruction|searcher|backrun/,
    description: 'Jito bundles enable atomic multi-instruction arbitrage. A searcher can bundle: 1) observe user\'s pending swap, 2) front-run with opposite position, 3) user\'s swap executes, 4) back-run to capture profit — all atomically guaranteed.',
    recommendation: 'DeFi protocols should implement commit-reveal schemes or use batch auctions. Users should use MEV-protected RPC endpoints. Set tight slippage bounds.'
  },
  // === SUPPLY CHAIN / DEPENDENCY ===
  {
    id: 'SOL7721',
    title: 'Anchor Version Pinning — IDL Mismatch After Upgrade',
    severity: 'medium',
    pattern: /anchor-lang.*=|anchor_lang.*version|declare_id|program.*mod/,
    description: 'When upgrading Anchor versions, the IDL generation may change instruction discriminators (first 8 bytes of sha256). If the client SDK uses an old IDL, instructions will fail with "unknown instruction" or worse, match a different instruction.',
    recommendation: 'Pin Anchor versions in Cargo.toml. Regenerate and distribute IDL after every program upgrade. Version IDL files alongside deployed program versions.'
  },
  {
    id: 'SOL7722',
    title: 'Crate Supply Chain — Malicious Proc Macro in Build Dependency',
    severity: 'critical',
    pattern: /proc-macro|proc_macro|build\.rs|custom_derive/,
    description: 'Rust proc macros execute arbitrary code at compile time. A compromised crate dependency with a proc macro can inject malicious code into the compiled program binary, undetectable by source code review of the main project.',
    recommendation: 'Audit proc macro dependencies thoroughly. Use cargo-vet or cargo-crev for supply chain verification. Pin exact crate versions with hash verification. Minimize proc macro dependencies.'
  },
  // === ORACLE / PRICE FEED ===
  {
    id: 'SOL7723',
    title: 'Pyth Price Feed — Confidence Interval Exploitation',
    severity: 'high',
    pattern: /pyth|price_feed|get_price|confidence|price_account|PriceUpdateV2/,
    description: 'Pyth price feeds include a confidence interval. During volatile markets, confidence intervals widen significantly. An attacker can exploit wide confidence by choosing the most favorable price within the interval for lending/borrowing operations.',
    recommendation: 'Always check and enforce maximum confidence interval relative to price (e.g., conf/price < 2%). Reject prices with abnormally wide confidence. Use TWAP alongside spot for critical operations.'
  },
  {
    id: 'SOL7724',
    title: 'Switchboard Oracle — Stale Feed with Valid Timestamp',
    severity: 'high',
    pattern: /switchboard|aggregator|AggregatorAccountData|latest_confirmed_round/,
    description: 'Switchboard oracle feeds can appear fresh (recent timestamp) but contain stale data if the oracle queue is congested or manipulated. The timestamp reflects when the round was recorded, not when the actual price was observed.',
    recommendation: 'Check both the timestamp AND the round open/close slots. Compare against multiple oracle sources. Implement maximum staleness based on slot difference, not just timestamp.'
  },
  // === FINAL: AUDIT READINESS ===
  {
    id: 'SOL7725',
    title: 'Missing Event Emission — Unauditable State Changes',
    severity: 'medium',
    pattern: /invoke_signed|transfer|mint_to|burn|close_account/,
    description: 'Critical state changes (transfers, mints, burns, authority changes) without corresponding event emission make the program unauditable. Off-chain monitoring cannot detect exploits in progress without events.',
    recommendation: 'Emit events (via msg! or Anchor events) for every state-changing operation. Include before/after values, actor pubkeys, and operation type. This is essential for incident response.'
  },
  {
    id: 'SOL7726',
    title: 'Program Upgrade Without Timelock — Instant Rug Vector',
    severity: 'critical',
    pattern: /upgrade_authority|BpfLoaderUpgradeab|programdata|set_authority.*UpgradeAuthority/,
    description: 'Programs with an active upgrade authority and no timelock can be instantly replaced with malicious code. Users interacting with the program have no warning period to withdraw funds before a malicious upgrade takes effect.',
    recommendation: 'Implement governance-controlled upgrades with minimum 48-hour timelock. Emit events on upgrade authority changes. Consider making programs immutable after audit, or use multisig upgrade authority with public transparency.'
  }
];

export function detectBatch114(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const code = input.content;

  for (const p of BATCH_114_PATTERNS) {
    if (p.pattern.test(code)) {
      findings.push({
        id: p.id,
        title: p.title,
        severity: p.severity,
        description: p.description,
        recommendation: p.recommendation,
        lineNumber: 0,
      });
    }
  }

  return findings;
}
