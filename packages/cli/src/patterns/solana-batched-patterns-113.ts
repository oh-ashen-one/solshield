/**
 * Batch 113: Feb 2026 — Owner Permission Phishing, Simulation Bypass, Wallet Drain Patterns
 * 
 * Sources:
 * - SlowMist: Solana Owner Permission phishing attacks (Dec 2025)
 * - DEXX wallet compromise affecting 9,000+ wallets ($30M, Nov 2024)
 * - NoOnes bridge exploit ($8M, Jan 2025)
 * - Upbit Solana hot wallet breach ($36M, Nov 2025)
 * - Solana Token-2022 mint/steal bug patched silently (May 2025)
 * - General wallet simulation bypass and transaction preview manipulation
 * 
 * Patterns: SOL7646-SOL7695 (50 patterns)
 * Focus: Account ownership reassignment, transaction simulation evasion,
 *        wallet drain vectors, bridge validation, hot wallet security,
 *        phishing-resistant program design
 */

import type { PatternInput, Finding } from './index.js';

const BATCH_113_PATTERNS: {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  pattern: RegExp;
  description: string;
  recommendation: string;
}[] = [
  // === OWNER PERMISSION PHISHING (SlowMist Dec 2025) ===
  {
    id: 'SOL7646',
    title: 'Unchecked Account Owner Reassignment',
    severity: 'critical',
    pattern: /system_program::assign\s*\(/i,
    description: 'Detects use of system_program::assign which can reassign account ownership to an attacker-controlled program. SlowMist reported $3M+ stolen via owner permission phishing in Dec 2025 where victims signed transactions that silently reassigned account ownership.',
    recommendation: 'Never use assign() on user-owned accounts in normal program flows. If reassignment is needed, require explicit multi-step confirmation with clear user-facing warnings. Validate the target program_id is a known trusted program.'
  },
  {
    id: 'SOL7647',
    title: 'Owner Field Modification Without Signer Validation',
    severity: 'critical',
    pattern: /\.owner\s*=\s*[^;]+program_id|set_owner|change_owner/i,
    description: 'Detects patterns where account ownership is being modified. Attackers craft transactions that reassign the Owner field to a malicious program, permanently locking out the legitimate owner from their assets.',
    recommendation: 'Ensure any owner modification requires the current owner to be a verified signer. Add time-lock delays for ownership transfers. Emit events for all ownership changes.'
  },
  {
    id: 'SOL7648',
    title: 'Assign Instruction to Arbitrary Program',
    severity: 'critical',
    pattern: /Assign\s*\{[^}]*owner:\s*(?!system_program|spl_token)/i,
    description: 'Detects account assignment to non-standard programs. Phishing attacks use assign instructions to transfer account control to attacker programs that can then drain all assets.',
    recommendation: 'Whitelist allowed program owners. Reject assign instructions targeting unknown program IDs. Implement wallet-level warnings for ownership change transactions.'
  },
  // === TRANSACTION SIMULATION BYPASS ===
  {
    id: 'SOL7649',
    title: 'Conditional Logic Based on Simulation Detection',
    severity: 'critical',
    pattern: /is_simul|simulate|dry.?run|preflight|skip.?preflight/i,
    description: 'Detects code that may behave differently during simulation vs execution. Attackers design transactions that appear harmless in wallet previews (simulation shows no token transfer) but execute malicious logic on-chain.',
    recommendation: 'Programs must behave identically in simulation and execution. Never branch on simulation detection. Wallets should warn users when transactions interact with unverified programs.'
  },
  {
    id: 'SOL7650',
    title: 'Clock-Based Simulation Evasion',
    severity: 'high',
    pattern: /Clock::get\(\).*?[<>]\s*\d{10}|unix_timestamp\s*[<>]/i,
    description: 'Detects time-based branching that could be used to evade wallet simulation. If a program checks whether the current timestamp is past a certain point, it may show benign behavior during simulation (which uses a slightly earlier time) and malicious behavior on-chain.',
    recommendation: 'Avoid time-based conditional logic that changes core transaction behavior. If time gates are needed, make them transparent and predictable.'
  },
  {
    id: 'SOL7651',
    title: 'Slot-Based Execution Branching',
    severity: 'high',
    pattern: /slot\s*[><=!]+\s*\d+|get_slot|Clock.*slot/i,
    description: 'Programs that branch on slot number can behave differently between simulation and execution since simulations may use a different slot context. Used in phishing to show safe behavior during preview.',
    recommendation: 'Do not use slot numbers to gate critical program logic. If slot checks are needed, ensure they do not affect security-critical code paths.'
  },
  // === WALLET DRAIN PATTERNS (DEXX Nov 2024) ===
  {
    id: 'SOL7652',
    title: 'Private Key Stored in Plaintext Memory',
    severity: 'critical',
    pattern: /secret_key|private_key|seed_phrase|mnemonic.*=\s*["'`\[]/i,
    description: 'Detects potential plaintext storage of private keys or seed phrases. The DEXX exploit (Nov 2024, $30M, 9000+ wallets) was traced to private key exposure through insecure server-side storage. Never store keys in application memory or logs.',
    recommendation: 'Use hardware security modules (HSMs) or secure enclaves for key storage. Never log, serialize, or transmit private keys. Use Solana Keypair only in memory with immediate zeroing after use.'
  },
  {
    id: 'SOL7653',
    title: 'Centralized Key Management for User Wallets',
    severity: 'critical',
    pattern: /generate_keypair.*user|user.*keypair|custodial.*key|server.*sign/i,
    description: 'Detects server-side keypair generation for user wallets. DEXX stored user private keys centrally, enabling a single breach to drain 9,000+ wallets. Centralized custody is a single point of failure.',
    recommendation: 'Use non-custodial wallet architecture. Let users generate and control their own keypairs. If custodial, use MPC (multi-party computation) or threshold signatures to eliminate single-key risk.'
  },
  {
    id: 'SOL7654',
    title: 'Bulk Transfer Without Rate Limiting',
    severity: 'high',
    pattern: /for.*transfer|while.*transfer|batch.*transfer|drain.*all/i,
    description: 'Detects loop-based bulk transfers that could indicate a drain pattern. In wallet compromises, attackers iterate through all user accounts and transfer assets in rapid succession.',
    recommendation: 'Implement rate limiting on transfers. Add per-epoch transfer caps. Require multi-sig for transfers above threshold amounts. Add anomaly detection for unusual transfer patterns.'
  },
  // === BRIDGE VALIDATION (NoOnes Jan 2025) ===
  {
    id: 'SOL7655',
    title: 'Bridge Message Without Cross-Chain Signature Verification',
    severity: 'critical',
    pattern: /bridge.*message|cross.?chain.*payload|relay.*msg/i,
    description: 'Detects bridge message handling without explicit signature verification. The NoOnes bridge exploit ($8M, Jan 2025) exploited weak cross-chain message validation to mint unauthorized tokens across multiple chains.',
    recommendation: 'Verify all bridge messages with multi-validator consensus signatures. Use Wormhole VAA-style attestation. Require minimum guardian threshold before processing any cross-chain message.'
  },
  {
    id: 'SOL7656',
    title: 'Bridge Relayer Without Source Chain Validation',
    severity: 'critical',
    pattern: /source_chain|emitter_chain|chain_id.*=\s*\d/i,
    description: 'Detects bridge relayer code that may not properly validate the source chain. Attackers can spoof chain IDs to trick bridges into processing forged messages from unexpected chains.',
    recommendation: 'Validate source chain ID against a strict whitelist. Cross-reference with guardian attestations. Reject messages from unknown or suspended chains.'
  },
  {
    id: 'SOL7657',
    title: 'Bridge Amount Without Maximum Cap',
    severity: 'high',
    pattern: /bridge.*amount|transfer.*amount.*bridge/i,
    description: 'Bridge transfers without maximum caps allow attackers to drain entire bridge reserves in a single transaction. Multiple bridge exploits have used uncapped amounts to maximize theft.',
    recommendation: 'Implement per-transaction and per-epoch transfer caps on bridge operations. Add time-delayed execution for large transfers. Require multi-sig approval above threshold.'
  },
  {
    id: 'SOL7658',
    title: 'Bridge Nonce Replay Vulnerability',
    severity: 'critical',
    pattern: /nonce.*bridge|bridge.*nonce|sequence.*bridge|bridge.*sequence/i,
    description: 'Bridge messages must include unique nonces to prevent replay attacks. Without proper nonce tracking, an attacker can replay a valid bridge message multiple times to drain funds.',
    recommendation: 'Store processed nonces on-chain and reject duplicates. Use monotonically increasing sequence numbers. Implement nonce expiration for time-bounded validity.'
  },
  // === HOT WALLET SECURITY (Upbit Nov 2025) ===
  {
    id: 'SOL7659',
    title: 'Hot Wallet Without Cold Storage Sweep',
    severity: 'high',
    pattern: /hot.?wallet|warm.?wallet|operational.?wallet/i,
    description: 'Detects hot wallet patterns without automated cold storage sweeping. The Upbit breach ($36M, Nov 2025) targeted Solana hot wallets. Hot wallets should hold minimal balances with automatic sweeps to cold storage.',
    recommendation: 'Implement automated sweeps from hot to cold wallets when balance exceeds threshold. Use time-locked multi-sig for hot wallet replenishment. Monitor hot wallet balances with real-time alerts.'
  },
  {
    id: 'SOL7660',
    title: 'Exchange Withdrawal Without Withdrawal Delay',
    severity: 'high',
    pattern: /withdraw.*immediate|instant.*withdraw|no.?delay.*withdraw/i,
    description: 'Immediate withdrawal processing gives attackers a narrow window to drain accounts before detection. Adding configurable delays allows security teams to intervene.',
    recommendation: 'Implement configurable withdrawal delays (15-60 min for large amounts). Allow users to set trusted withdrawal addresses with instant access. Add anomaly detection that triggers automatic holds.'
  },
  // === TOKEN-2022 MINT BUG PATTERNS (May 2025 Silent Patch) ===
  {
    id: 'SOL7661',
    title: 'Token-2022 Confidential Transfer Without Proof Validation',
    severity: 'critical',
    pattern: /confidential.*transfer(?!.*verify)|transfer.*confidential(?!.*proof)/i,
    description: 'Detects confidential transfer operations without ZK proof verification. A silently patched Solana bug (May 2025) could have allowed attackers to mint and steal certain tokens by bypassing proof validation in Token-2022 confidential transfers.',
    recommendation: 'Always verify ZK proofs before processing confidential transfers. Use the latest SPL Token-2022 library which includes the patch. Audit all confidential transfer handler code paths.'
  },
  {
    id: 'SOL7662',
    title: 'Token Mint Authority Without Multi-Sig',
    severity: 'high',
    pattern: /mint_authority\s*=\s*(?!.*multisig)|MintTo\s*\{[^}]*authority:\s*(?!.*multi)/i,
    description: 'Single-key mint authority creates a critical single point of failure. If the mint authority key is compromised, attackers can mint unlimited tokens, destroying token value.',
    recommendation: 'Use multi-sig (e.g., Squads Protocol) for mint authority. Consider using a PDA as mint authority controlled by governance. Implement mint caps and rate limits.'
  },
  {
    id: 'SOL7663',
    title: 'Token-2022 Transfer Fee Bypass',
    severity: 'high',
    pattern: /transfer_fee.*skip|bypass.*fee|fee.*exempt(?!.*check)/i,
    description: 'Detects patterns that may bypass Token-2022 transfer fees. Fee exemption without proper authorization can be exploited to avoid protocol revenue collection or manipulate tokenomics.',
    recommendation: 'Enforce transfer fees at the program level, not client level. Use Token-2022 TransferFeeConfig with properly validated fee authority. Audit all code paths that handle fee-bearing tokens.'
  },
  // === PHISHING-RESISTANT PROGRAM DESIGN ===
  {
    id: 'SOL7664',
    title: 'Missing Transaction Memo for User-Facing Operations',
    severity: 'medium',
    pattern: /invoke.*(?!.*memo)|transfer.*(?!.*memo_program)/i,
    description: 'User-facing transactions without memos make it harder for wallets to display meaningful information during signing. Phishing attacks exploit opaque transactions that wallets cannot meaningfully describe.',
    recommendation: 'Include descriptive memos in all user-facing transactions. Use SPL Memo program to attach human-readable descriptions. This helps wallets display clear signing prompts.'
  },
  {
    id: 'SOL7665',
    title: 'Multiple Instructions Without Atomic Grouping',
    severity: 'medium',
    pattern: /add_instruction.*add_instruction|instructions\.push.*instructions\.push/i,
    description: 'Multiple ungrouped instructions in a transaction can be individually simulated vs executed differently. Phishing attacks embed malicious instructions alongside benign ones, relying on users only checking the first instruction in wallet preview.',
    recommendation: 'Group related instructions logically. Use transaction versioning. Wallets should display ALL instructions, not just the first. Developers should minimize instruction count per transaction.'
  },
  {
    id: 'SOL7666',
    title: 'Approval Instruction Without Amount Display',
    severity: 'medium',
    pattern: /approve\s*\{[^}]*(?!.*amount_display)|delegate.*approve(?!.*ui_amount)/i,
    description: 'Token approval/delegation without clear amount display in transaction data makes it easy for phishing attacks to request unlimited approvals that users unknowingly sign.',
    recommendation: 'Always include human-readable amount (ui_amount) in approval instructions. Set minimal required approval amounts rather than unlimited. Implement approval expiry timestamps.'
  },
  // === AIRDROP AND CLAIM PHISHING ===
  {
    id: 'SOL7667',
    title: 'Airdrop Claim Without Merkle Proof',
    severity: 'high',
    pattern: /claim.*airdrop|airdrop.*claim(?!.*merkle|.*proof)/i,
    description: 'Airdrop claim mechanisms without Merkle proof verification are common phishing vectors. Fake airdrop sites prompt users to sign transactions that actually drain wallets or reassign account ownership.',
    recommendation: 'Use Merkle tree distribution for airdrops with on-chain proof verification. Never require users to sign transactions that include account assignment or approval instructions for claiming airdrops.'
  },
  {
    id: 'SOL7668',
    title: 'Unconstrained Claim Destination',
    severity: 'high',
    pattern: /claim.*destination|destination.*claim|claim_to\s*:/i,
    description: 'Claim instructions that allow arbitrary destination accounts can be exploited to redirect airdrop tokens to attacker wallets. The destination should be constrained to the claimant.',
    recommendation: 'Constrain claim destination to a PDA derived from the claimant pubkey. Reject claims where destination owner differs from the claimant. Log all claim destinations for audit.'
  },
  // === MULTI-SIG AND GOVERNANCE ATTACKS ===
  {
    id: 'SOL7669',
    title: 'Governance Proposal Without Timelock',
    severity: 'high',
    pattern: /execute.*proposal(?!.*timelock|.*delay)|proposal.*execute.*immediate/i,
    description: 'Governance proposals that execute immediately allow malicious proposals to drain treasuries before community can react. The Saga DAO exploit used rapid proposal execution.',
    recommendation: 'Enforce minimum timelock delay (24-72 hours) between proposal approval and execution. Allow veto during timelock period. Implement emergency pause that requires higher threshold.'
  },
  {
    id: 'SOL7670',
    title: 'Multi-Sig Threshold Too Low',
    severity: 'high',
    pattern: /threshold\s*[:=]\s*[12]\s*[,;}\)]|min_signers\s*[:=]\s*[12]\b/i,
    description: 'Multi-sig wallets with threshold of 1 or 2 provide insufficient security. A single compromised key (threshold=1) or two colluding parties (threshold=2) can drain the entire treasury.',
    recommendation: 'Use minimum 3-of-5 or higher threshold for treasury multi-sigs. Distribute keys across different security domains (hardware wallet, cold storage, geographic separation). Implement key rotation schedules.'
  },
  // === ACCOUNT VALIDATION DEEP PATTERNS ===
  {
    id: 'SOL7671',
    title: 'Account Data Length Mismatch on Deserialization',
    severity: 'high',
    pattern: /try_from_slice|deserialize.*data(?!.*len.*check)|from_account_info(?!.*data_len)/i,
    description: 'Deserializing account data without checking data length can lead to out-of-bounds reads or misinterpreted data. Attackers can pass accounts with unexpected data sizes to trigger undefined behavior.',
    recommendation: 'Always validate account data length before deserialization. Use Anchor account discriminators which automatically check data length. For native programs, compare data.len() against expected size.'
  },
  {
    id: 'SOL7672',
    title: 'Missing Rent Exemption Check on New Accounts',
    severity: 'medium',
    pattern: /create_account(?!.*rent)|init(?!.*rent_exempt|.*space)/i,
    description: 'Accounts created without ensuring rent exemption can be garbage collected by the runtime, causing loss of state. Attackers can exploit this to force-close accounts at inopportune times.',
    recommendation: 'Always ensure new accounts are rent-exempt by allocating sufficient lamports. Use Anchor init constraint which handles this automatically. Verify rent exemption with Rent::is_exempt().'
  },
  {
    id: 'SOL7673',
    title: 'PDA Seed Collision with User-Controlled Input',
    severity: 'critical',
    pattern: /find_program_address.*user_input|seeds.*\[.*user.*\]|create_program_address.*input/i,
    description: 'Using user-controlled input directly as PDA seeds without sanitization can allow attackers to craft inputs that collide with existing PDA addresses, hijacking accounts.',
    recommendation: 'Sanitize and length-limit all user-provided PDA seed components. Use fixed-length hashes of user input as seeds. Include program-specific prefixes in seed derivation to prevent cross-program collisions.'
  },
  // === LENDING AND DEFI ADVANCED ===
  {
    id: 'SOL7674',
    title: 'Lending Protocol Without Borrow Factor',
    severity: 'high',
    pattern: /collateral.*borrow(?!.*factor)|loan.?to.?value(?!.*cap)/i,
    description: 'Lending protocols without borrow factors for volatile assets allow over-borrowing against unstable collateral. Price drops can leave the protocol with bad debt if borrowing capacity is not risk-adjusted.',
    recommendation: 'Implement per-asset borrow factors that reduce effective collateral value for volatile assets. Set conservative LTV ratios. Use isolated lending pools for high-risk assets.'
  },
  {
    id: 'SOL7675',
    title: 'Oracle Staleness Without Fallback',
    severity: 'high',
    pattern: /oracle.*price(?!.*stale|.*fresh|.*fallback)|get_price(?!.*age_check)/i,
    description: 'Using oracle prices without checking staleness and having a fallback mechanism. Stale prices from Pyth/Switchboard can enable liquidation manipulation or arbitrage during network congestion.',
    recommendation: 'Check oracle price timestamps and reject stale data (>60s for volatile assets). Implement TWAP fallback oracles. Pause operations if no fresh price is available rather than using stale data.'
  },
  {
    id: 'SOL7676',
    title: 'Interest Rate Model Without Utilization Cap',
    severity: 'medium',
    pattern: /interest.*rate.*(?!.*util|.*cap)|borrow.*rate(?!.*maximum)/i,
    description: 'Interest rate models without utilization caps can lead to 100% utilization, preventing depositors from withdrawing and creating a bank-run scenario.',
    recommendation: 'Implement steep interest rate curves above 80% utilization to incentivize repayment. Add protocol-level reserve requirements. Enable emergency mode that halts new borrows at extreme utilization.'
  },
  // === PROGRAM UPGRADE SECURITY ===
  {
    id: 'SOL7677',
    title: 'Upgrade Authority Without Governance',
    severity: 'high',
    pattern: /upgrade_authority\s*=\s*(?!.*governance|.*dao|.*multisig)/i,
    description: 'Programs with single-key upgrade authority can be silently upgraded to drain user funds. This is the most common rug-pull vector in DeFi protocols.',
    recommendation: 'Transfer upgrade authority to a governance-controlled multi-sig or DAO. Implement upgrade timelock with community notification period. Consider making programs immutable after sufficient audit.'
  },
  {
    id: 'SOL7678',
    title: 'Program Upgrade Without State Migration',
    severity: 'high',
    pattern: /upgrade.*program(?!.*migration|.*migrate)|deploy.*new(?!.*state.*check)/i,
    description: 'Upgrading a program without proper state migration can corrupt existing account data, leading to fund loss or protocol malfunction.',
    recommendation: 'Always implement state migration logic in program upgrades. Version account data structures with discriminators. Test upgrade paths on devnet with production-like state before mainnet deployment.'
  },
  // === COMPUTE AND RESOURCE EXHAUSTION ===
  {
    id: 'SOL7679',
    title: 'Unbounded Iteration Over Accounts',
    severity: 'high',
    pattern: /remaining_accounts.*iter|for.*remaining|iter\(\).*accounts(?!.*limit|.*max)/i,
    description: 'Iterating over unbounded remaining_accounts can exhaust compute units, causing transaction failure. Attackers can pass many accounts to trigger DoS or exploit partial execution.',
    recommendation: 'Limit the number of remaining_accounts processed per instruction. Set explicit maximum iteration bounds. Use pagination for operations on many accounts.'
  },
  {
    id: 'SOL7680',
    title: 'Missing Compute Budget Request',
    severity: 'medium',
    pattern: /invoke(?!.*compute_budget)|process_instruction(?!.*compute)/i,
    description: 'Complex instructions without explicit compute budget requests may fail at default 200K CU limit. This can be exploited by attackers who craft inputs that maximize compute usage.',
    recommendation: 'Request appropriate compute budget for complex instructions using ComputeBudgetInstruction::set_compute_unit_limit. Profile instruction compute usage and set limits with safety margin.'
  },
  // === CROSS-PROGRAM INVOCATION DEEP PATTERNS ===
  {
    id: 'SOL7681',
    title: 'CPI to Unverified Program ID',
    severity: 'critical',
    pattern: /invoke_signed?\s*\(\s*&[^,]*(?!.*check.*program_id|.*verify.*program)/i,
    description: 'Cross-program invocations to unverified program IDs allow attackers to substitute a malicious program that mimics the expected interface but steals funds.',
    recommendation: 'Always verify the program_id of CPI targets against known constants. Use Anchor Program<> type which validates program IDs automatically. Hardcode trusted program IDs as constants.'
  },
  {
    id: 'SOL7682',
    title: 'CPI With Mutable Account Escalation',
    severity: 'high',
    pattern: /invoke.*AccountMeta::new\(\s*[^,]*,\s*true/i,
    description: 'Passing accounts as mutable in CPI when they should be read-only can allow the invoked program to modify unexpected state. Attackers exploit this to manipulate balances or authorities.',
    recommendation: 'Use AccountMeta::new_readonly() for accounts that should not be modified by the CPI target. Audit all CPI AccountMeta mutability flags. Follow principle of least privilege.'
  },
  // === STAKING AND REWARD PATTERNS ===
  {
    id: 'SOL7683',
    title: 'Staking Reward Calculation Without Snapshot',
    severity: 'high',
    pattern: /reward.*balance.*current|calculate.*reward(?!.*snapshot|.*checkpoint)/i,
    description: 'Calculating staking rewards based on current balance without snapshots allows flash-loan attacks where attackers temporarily inflate their stake to claim disproportionate rewards.',
    recommendation: 'Use checkpoint-based reward calculation that snapshots balances at reward distribution time. Implement minimum staking duration. Use cumulative reward-per-token tracking (like Synthetix model).'
  },
  {
    id: 'SOL7684',
    title: 'Unstake Without Cooldown Period',
    severity: 'medium',
    pattern: /unstake.*immediate|instant.*unstake|withdraw.*stake(?!.*cooldown|.*delay)/i,
    description: 'Allowing immediate unstaking enables flash-loan-style attacks on reward distribution and can destabilize protocol security assumptions.',
    recommendation: 'Implement unstaking cooldown periods (typically 7-21 days). Allow partial unstaking with proportional cooldowns. Penalize early withdrawal to discourage gaming.'
  },
  // === SERIALIZATION AND DATA INTEGRITY ===
  {
    id: 'SOL7685',
    title: 'Borsh Deserialization Without Bounds Check',
    severity: 'high',
    pattern: /BorshDeserialize.*(?!.*try_|.*Result)|from_slice(?!.*map_err)/i,
    description: 'Deserializing data without bounds checking can cause panics or read uninitialized memory. Attackers can craft malformed account data to crash programs or extract sensitive information.',
    recommendation: 'Always use try_from_slice or handle deserialization errors gracefully. Validate data lengths before deserialization. Use Anchor account types which handle this automatically.'
  },
  {
    id: 'SOL7686',
    title: 'Account Data Padding Not Zeroed',
    severity: 'medium',
    pattern: /realloc(?!.*zero)|resize.*account(?!.*zero|.*fill)/i,
    description: 'When reallocating account data, failing to zero new padding bytes can leak data from previously deallocated accounts, potentially exposing sensitive information.',
    recommendation: 'Zero-fill all new bytes when reallocating accounts. Use realloc::zero constraint in Anchor. For native programs, explicitly memset new space to zero.'
  },
  // === LIQUIDITY POOL ADVANCED ===
  {
    id: 'SOL7687',
    title: 'LP Token Mint Without Minimum Liquidity Lock',
    severity: 'high',
    pattern: /mint.*lp(?!.*minimum|.*lock)|liquidity.*mint(?!.*min_amount)/i,
    description: 'Liquidity pools without minimum liquidity lock allow first-depositor attacks where an attacker manipulates the LP token ratio by depositing minimal amounts and inflating price.',
    recommendation: 'Lock minimum liquidity (e.g., 1000 LP tokens) on pool creation by sending to burn address. Implement minimum deposit amounts. Use virtual reserves to prevent manipulation at low liquidity.'
  },
  {
    id: 'SOL7688',
    title: 'AMM Swap Without Slippage Protection',
    severity: 'high',
    pattern: /swap(?!.*slippage|.*min_out|.*minimum)|exchange.*token(?!.*min)/i,
    description: 'Swaps without slippage protection are vulnerable to sandwich attacks where MEV bots front-run and back-run the trade, extracting value from the user.',
    recommendation: 'Enforce minimum output amount (slippage protection) on all swaps. Set reasonable default slippage (0.5-1%). Allow users to specify custom slippage tolerance. Reject stale price quotes.'
  },
  // === INSTRUCTION INTROSPECTION ATTACKS ===
  {
    id: 'SOL7689',
    title: 'Instruction Introspection Without Full Validation',
    severity: 'high',
    pattern: /sysvar::instructions|get_instruction_relative|load_instruction_at/i,
    description: 'Using instruction introspection (reading other instructions in the same transaction) without full validation of all instruction fields allows attackers to construct transactions that pass superficial checks.',
    recommendation: 'When using instruction introspection, validate ALL fields: program_id, accounts, and data. Do not only check program_id — verify the specific instruction discriminator and account constraints.'
  },
  {
    id: 'SOL7690',
    title: 'Flash Loan Detection Bypass via Instruction Ordering',
    severity: 'high',
    pattern: /check.*flash.*loan|detect.*flash|anti.?flash/i,
    description: 'Anti-flash-loan checks based on instruction ordering can be bypassed by splitting the loan across multiple transactions within the same slot, or by using inner instructions.',
    recommendation: 'Use checkpoint-based detection rather than instruction introspection. Track balance changes across slots. Implement minimum holding periods for time-sensitive operations.'
  },
  // === VERSIONED TRANSACTIONS AND ADDRESS LOOKUP ===
  {
    id: 'SOL7691',
    title: 'Address Lookup Table Without Ownership Verification',
    severity: 'high',
    pattern: /lookup.?table|AddressLookupTable(?!.*owner.*check)/i,
    description: 'Address Lookup Tables (ALTs) can be created by anyone. Using ALTs without verifying the table authority allows attackers to substitute malicious account addresses.',
    recommendation: 'Verify ALT authority/owner before trusting resolved addresses. For critical operations, prefer direct account references over ALT-resolved addresses. Monitor ALT modifications.'
  },
  {
    id: 'SOL7692',
    title: 'Versioned Transaction Without Legacy Fallback',
    severity: 'low',
    pattern: /VersionedTransaction(?!.*legacy|.*v0.*fallback)/i,
    description: 'Using versioned transactions (v0) without legacy fallback can cause interoperability issues with older wallets and programs that do not support ALTs.',
    recommendation: 'Support both legacy and versioned transaction formats. Implement graceful degradation for wallets that do not support v0 transactions. Test with both transaction versions.'
  },
  // === ADVANCED PHISHING DEFENSE ===
  {
    id: 'SOL7693',
    title: 'Transaction Lacks Human-Readable Metadata',
    severity: 'info',
    pattern: /new Transaction\(\)(?!.*add.*memo)|Transaction::new(?!.*memo)/i,
    description: 'Transactions without human-readable metadata (memos, named instructions) are harder for users to evaluate when signing, increasing phishing success rates.',
    recommendation: 'Add descriptive memos to all user-facing transactions. Use well-named instruction variants. Support wallet-readable metadata standards for clear signing prompts.'
  },
  {
    id: 'SOL7694',
    title: 'Durable Nonce Transaction Manipulation',
    severity: 'high',
    pattern: /durable.*nonce|nonce.*advance|AdvanceNonceAccount/i,
    description: 'Durable nonce transactions remain valid indefinitely until the nonce is advanced. Attackers can trick users into signing a durable nonce transaction and hold it for execution at an advantageous time.',
    recommendation: 'Implement application-level expiry for durable nonce transactions. Warn users when signing durable nonce transactions. Monitor pending nonce transactions and auto-advance nonces for expired intents.'
  },
  {
    id: 'SOL7695',
    title: 'Pre-Authorized Debit Without Spending Limit',
    severity: 'high',
    pattern: /pre.?auth.*debit|delegate.*unlimited|approve.*max|approve.*u64::MAX/i,
    description: 'Pre-authorized debits or unlimited token delegations allow approved programs to drain entire token balances. Users often approve unlimited amounts for convenience, creating a persistent attack surface.',
    recommendation: 'Set minimal required approval amounts. Implement approval expiry timestamps. Use per-transaction approval rather than standing delegations. Warn users about unlimited approval requests.'
  }
];

export function checkBatch113Patterns(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content ?? '';

  for (const p of BATCH_113_PATTERNS) {
    if (p.pattern.test(content)) {
      findings.push({
        id: p.id,
        title: p.title,
        severity: p.severity,
        description: p.description,
        recommendation: p.recommendation,
        location: { file: input.path },
      });
    }
  }

  return findings;
}
