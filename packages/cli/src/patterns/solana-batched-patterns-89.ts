/**
 * SolShield Batch 89 Patterns
 * 
 * Source: Zellic Anchor Vulnerabilities + Cantina Security Guide + Advanced DeFi Patterns + 2026 Threats
 * Patterns SOL4901-SOL5000
 * Created: Feb 6, 2026 4:35 AM
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

const BATCH_89_PATTERNS: PatternDef[] = [
  // Zellic "Vulnerabilities You'll Write With Anchor" Patterns
  {
    id: 'SOL4901',
    name: 'Zellic - Missing Account Discriminator Check',
    severity: 'critical',
    pattern: /try_from_slice|from_account_info(?![\s\S]{0,50}discriminator|[\s\S]{0,50}DISCRIMINATOR)/i,
    description: 'Zellic: Anchor adds 8-byte discriminator but manual deserialization may skip it. Type confusion attack.',
    recommendation: 'Always verify 8-byte discriminator matches expected account type before deserializing.'
  },
  {
    id: 'SOL4902',
    name: 'Zellic - init_if_needed Race Condition',
    severity: 'critical',
    pattern: /init_if_needed(?![\s\S]{0,100}mutex|[\s\S]{0,100}atomic)/i,
    description: 'Zellic: init_if_needed can cause race conditions. Multiple transactions can initialize with different data.',
    recommendation: 'Avoid init_if_needed in production. Use separate init instruction with proper checks.'
  },
  {
    id: 'SOL4903',
    name: 'Zellic - Account Reinitialization via init_if_needed',
    severity: 'critical',
    pattern: /init_if_needed[\s\S]{0,100}data/i,
    description: 'Zellic: init_if_needed doesn\'t prevent reinit if account exists but is empty.',
    recommendation: 'Check is_initialized flag before using account data. Prefer explicit init instruction.'
  },
  {
    id: 'SOL4904',
    name: 'Zellic - Anchor Context Remaining Accounts',
    severity: 'high',
    pattern: /remaining_accounts|ctx\.remaining_accounts(?![\s\S]{0,100}verify|[\s\S]{0,100}validate)/i,
    description: 'Zellic: remaining_accounts bypass Anchor\'s type checks. Attackers can pass arbitrary accounts.',
    recommendation: 'Validate all remaining_accounts manually: check owner, program_id, data type.'
  },
  {
    id: 'SOL4905',
    name: 'Zellic - Seeds Constraint Without Bump',
    severity: 'high',
    pattern: /seeds\s*=[\s\S]{0,50}(?!bump)/i,
    description: 'Zellic: Seeds constraint without bump allows non-canonical PDA. Attacker can create spoofed accounts.',
    recommendation: 'Always include bump in seeds constraint: seeds = [b"prefix"], bump = account.bump'
  },
  {
    id: 'SOL4906',
    name: 'Zellic - Hardcoded Bump Seed',
    severity: 'high',
    pattern: /bump\s*=\s*\d+|bump\s*=\s*255/i,
    description: 'Zellic: Hardcoded bump seeds are dangerous. Only canonical bump (highest valid) should be used.',
    recommendation: 'Store and use the canonical bump from find_program_address, not hardcoded values.'
  },
  {
    id: 'SOL4907',
    name: 'Zellic - Missing has_one Constraint',
    severity: 'critical',
    pattern: /authority[\s\S]{0,30}AccountInfo(?![\s\S]{0,50}has_one|[\s\S]{0,50}constraint)/i,
    description: 'Zellic: Authority accounts without has_one constraint allow passing any account.',
    recommendation: 'Add has_one = authority constraint to verify account relationship.'
  },
  {
    id: 'SOL4908',
    name: 'Zellic - Constraint Ordering Issue',
    severity: 'medium',
    pattern: /mut[\s\S]{0,20}close(?![\s\S]{0,30}=[\s\S]{0,10}destination)/i,
    description: 'Zellic: Close constraint should specify destination. Funds may go to unexpected account.',
    recommendation: 'Always specify close = destination_account to control where lamports go.'
  },
  {
    id: 'SOL4909',
    name: 'Zellic - Signer Type vs is_signer Check',
    severity: 'critical',
    pattern: /AccountInfo[\s\S]{0,30}authority(?![\s\S]{0,50}Signer|[\s\S]{0,50}is_signer)/i,
    description: 'Zellic: Using AccountInfo instead of Signer<> for authority doesn\'t verify signature.',
    recommendation: 'Use Signer<\'info> type for authority accounts or manually check is_signer.'
  },
  {
    id: 'SOL4910',
    name: 'Zellic - UncheckedAccount Without Safety Check',
    severity: 'critical',
    pattern: /UncheckedAccount|AccountInfo(?![\s\S]{0,30}\/\/\/\s*CHECK|[\s\S]{0,30}#\[account\()/i,
    description: 'Zellic: UncheckedAccount requires manual validation. Anchor requires /// CHECK comment.',
    recommendation: 'Add /// CHECK: <reason> comment and implement manual validation for unchecked accounts.'
  },
  
  // Cantina Security Guide Patterns
  {
    id: 'SOL4911',
    name: 'Cantina - 48M CU Compute Limit Exceeded',
    severity: 'high',
    pattern: /compute|ComputeBudget(?![\s\S]{0,100}request_units|[\s\S]{0,100}limit_check)/i,
    description: 'Cantina: Exceeding 48M CU limit causes transaction failure. Can be exploited to disrupt dApps.',
    recommendation: 'Monitor compute usage. Split large operations. Add compute budget checks.'
  },
  {
    id: 'SOL4912',
    name: 'Cantina - Heap Memory Exhaustion',
    severity: 'high',
    pattern: /Vec::with_capacity|vec!\[[\s\S]{0,10}\d{5,}|alloc/i,
    description: 'Cantina: Solana programs have 32KB heap limit. Large allocations cause OOM.',
    recommendation: 'Minimize heap allocations. Use stack where possible. Check allocation sizes.'
  },
  {
    id: 'SOL4913',
    name: 'Cantina - Stack Overflow in Recursion',
    severity: 'high',
    pattern: /fn\s+\w+[\s\S]{0,50}->[\s\S]{0,100}self\.\w+\(|recursion|recursive/i,
    description: 'Cantina: Deep recursion exhausts 4KB stack. Use iteration instead.',
    recommendation: 'Convert recursive algorithms to iterative. Limit recursion depth.'
  },
  {
    id: 'SOL4914',
    name: 'Cantina - Outdated Dependency Vulnerability',
    severity: 'high',
    pattern: /Cargo\.toml|dependencies|version\s*=\s*"0\./i,
    description: 'Cantina: Using outdated dependencies is common security risk. Web3.js backdoor example.',
    recommendation: 'Keep dependencies updated. Run cargo audit. Pin exact versions in Cargo.lock.'
  },
  {
    id: 'SOL4915',
    name: 'Cantina - Account Data Size Manipulation',
    severity: 'high',
    pattern: /realloc|data_len|data\.len\(\)(?![\s\S]{0,50}require!|[\s\S]{0,50}assert)/i,
    description: 'Cantina: Account data size can be manipulated. Validate expected size before use.',
    recommendation: 'Check data.len() matches expected struct size. Reject accounts with wrong size.'
  },
  {
    id: 'SOL4916',
    name: 'Cantina - CPI Depth Limit Exceeded',
    severity: 'high',
    pattern: /invoke|invoke_signed(?![\s\S]{0,100}depth_check)/i,
    description: 'Cantina: CPI has 4-level depth limit. Deep call chains fail unexpectedly.',
    recommendation: 'Track CPI depth. Design programs to minimize nesting. Max 4 levels of invoke.'
  },
  {
    id: 'SOL4917',
    name: 'Cantina - Return Data Size Limit',
    severity: 'medium',
    pattern: /set_return_data|return_data(?![\s\S]{0,50}truncate|[\s\S]{0,50}len\s*<)/i,
    description: 'Cantina: Return data limited to 1024 bytes. Large returns silently truncate.',
    recommendation: 'Keep return data under 1024 bytes. Use account storage for larger data.'
  },
  {
    id: 'SOL4918',
    name: 'Cantina - Transaction Size Limit',
    severity: 'medium',
    pattern: /transaction|tx(?![\s\S]{0,100}size_check|[\s\S]{0,100}1232)/i,
    description: 'Cantina: Transaction size limited to 1232 bytes. Use versioned transactions and LUTs.',
    recommendation: 'Optimize instruction data. Use Address Lookup Tables for many accounts.'
  },
  {
    id: 'SOL4919',
    name: 'Cantina - Sysvars via Account Instead of Get',
    severity: 'medium',
    pattern: /Clock::get|Rent::get(?![\s\S]{0,10}\(\))/i,
    description: 'Cantina: Prefer Sysvar::get() over passing sysvar account. Saves account space.',
    recommendation: 'Use Clock::get()?, Rent::get()? instead of sysvar account parameters.'
  },
  {
    id: 'SOL4920',
    name: 'Cantina - Log Instruction Spam',
    severity: 'low',
    pattern: /msg!\([\s\S]{0,100}\)|sol_log|emit!/i,
    description: 'Cantina: Excessive logging increases compute cost and can leak information.',
    recommendation: 'Minimize production logging. Remove debug logs. Don\'t log sensitive data.'
  },
  
  // Advanced DeFi Attack Patterns
  {
    id: 'SOL4921',
    name: 'JIT Liquidity Attack',
    severity: 'critical',
    pattern: /add.*liquidity[\s\S]{0,100}remove.*liquidity|jit.*liquidity/i,
    description: 'JIT liquidity: Add liquidity before swap, earn fees, remove after. MEV attack on AMMs.',
    recommendation: 'Implement LP lockup period. Use time-weighted fee distribution.'
  },
  {
    id: 'SOL4922',
    name: 'Sandwich Attack on Swaps',
    severity: 'critical',
    pattern: /swap(?![\s\S]{0,100}slippage|[\s\S]{0,100}min_output|[\s\S]{0,100}deadline)/i,
    description: 'Sandwich attacks: Front-run swap to inflate price, back-run to profit. User loses to slippage.',
    recommendation: 'Implement slippage protection. Use deadline parameter. Consider private submission.'
  },
  {
    id: 'SOL4923',
    name: 'Atomic Arbitrage Profit Extraction',
    severity: 'high',
    pattern: /arbitrage|price.*difference(?![\s\S]{0,100}atomic_check)/i,
    description: 'Atomic arbitrage extracts value from price discrepancies. Impacts protocol efficiency.',
    recommendation: 'Use oracles with manipulation resistance. Implement trading fees to reduce arb profit.'
  },
  {
    id: 'SOL4924',
    name: 'Interest Rate Manipulation',
    severity: 'critical',
    pattern: /interest.*rate|utilization.*rate(?![\s\S]{0,100}cap|[\s\S]{0,100}max_rate)/i,
    description: 'Interest rates can be manipulated by strategic borrows/repays. Rate caps needed.',
    recommendation: 'Implement interest rate caps. Use gradual rate adjustments. Add utilization smoothing.'
  },
  {
    id: 'SOL4925',
    name: 'Bad Debt Socialization',
    severity: 'critical',
    pattern: /bad.*debt|underwater.*position(?![\s\S]{0,100}insurance|[\s\S]{0,100}backstop)/i,
    description: 'Underwater positions create bad debt. Socializing to LPs is unfair without insurance.',
    recommendation: 'Build insurance fund from fees. Implement partial liquidations. Add backstop mechanisms.'
  },
  {
    id: 'SOL4926',
    name: 'Yield Aggregator Vault Strategy Manipulation',
    severity: 'high',
    pattern: /vault.*strategy|strategy.*yield(?![\s\S]{0,100}verified_strategy|[\s\S]{0,100}whitelist)/i,
    description: 'Malicious strategies in yield aggregators can drain vault funds.',
    recommendation: 'Whitelist approved strategies. Implement strategy timelock. Audit all strategies.'
  },
  {
    id: 'SOL4927',
    name: 'Vault Share Inflation Attack',
    severity: 'critical',
    pattern: /vault.*share|share.*mint(?![\s\S]{0,100}minimum_shares|[\s\S]{0,100}initial_deposit)/i,
    description: 'First depositor can inflate share price, stealing from subsequent depositors.',
    recommendation: 'Require minimum initial deposit. Implement virtual shares or dead shares.'
  },
  {
    id: 'SOL4928',
    name: 'Donation Attack on Vaults',
    severity: 'critical',
    pattern: /vault.*balance|assets.*per.*share(?![\s\S]{0,100}exclude_donation)/i,
    description: 'Donating assets to vault inflates share price, causing rounding issues.',
    recommendation: 'Track deposited vs total assets. Use internal accounting immune to donations.'
  },
  {
    id: 'SOL4929',
    name: 'Lending Protocol Utilization Manipulation',
    severity: 'high',
    pattern: /utilization|borrow.*available(?![\s\S]{0,100}minimum_liquidity)/i,
    description: 'Manipulating utilization to 100% prevents withdrawals. Liquidity crisis attack.',
    recommendation: 'Reserve minimum liquidity. Implement dynamic interest rates that spike at high utilization.'
  },
  {
    id: 'SOL4930',
    name: 'Collateral Factor Manipulation',
    severity: 'critical',
    pattern: /collateral.*factor|ltv(?![\s\S]{0,100}oracle|[\s\S]{0,100}time_weighted)/i,
    description: 'Collateral factors based on spot prices can be manipulated. Use oracle-based valuation.',
    recommendation: 'Use time-weighted oracle prices. Implement per-asset caps. Add liquidation buffer.'
  },
  
  // Protocol-Specific Attack Patterns
  {
    id: 'SOL4931',
    name: 'Orca Whirlpool Tick Boundary Issue',
    severity: 'high',
    pattern: /tick.*boundary|tick_lower|tick_upper(?![\s\S]{0,100}tick_spacing)/i,
    description: 'CLMM tick boundaries must align with tick spacing. Misalignment causes unexpected behavior.',
    recommendation: 'Verify ticks are divisible by tick_spacing. Use SDK helpers for tick calculations.'
  },
  {
    id: 'SOL4932',
    name: 'Raydium CLMM Position NFT Validation',
    severity: 'high',
    pattern: /position.*nft|nft.*position(?![\s\S]{0,100}owner_check|[\s\S]{0,100}mint_check)/i,
    description: 'CLMM positions represented as NFTs. Must verify NFT ownership and mint.',
    recommendation: 'Verify position NFT owner matches expected. Validate NFT mint authority.'
  },
  {
    id: 'SOL4933',
    name: 'Marinade Stake Account Validation',
    severity: 'high',
    pattern: /stake.*account|stake_deposit(?![\s\S]{0,100}validator_check|[\s\S]{0,100}state_check)/i,
    description: 'Stake accounts must be validated before accepting in liquid staking protocols.',
    recommendation: 'Verify stake account state, validator, and activation epoch.'
  },
  {
    id: 'SOL4934',
    name: 'Jupiter Aggregator Route Validation',
    severity: 'high',
    pattern: /route|swap.*route(?![\s\S]{0,100}slippage|[\s\S]{0,100}intermediate_check)/i,
    description: 'Swap routes through aggregators can be manipulated. Validate intermediate steps.',
    recommendation: 'Set strict slippage on each hop. Use versioned routes with price impact limits.'
  },
  {
    id: 'SOL4935',
    name: 'Pyth Price Account Ownership',
    severity: 'critical',
    pattern: /pyth.*price|price.*feed(?![\s\S]{0,100}owner\s*==|[\s\S]{0,100}PYTH_PROGRAM)/i,
    description: 'Fake Pyth price accounts can be created. Always verify owner is Pyth program.',
    recommendation: 'Check price_account.owner == PYTH_PROGRAM_ID before using price data.'
  },
  {
    id: 'SOL4936',
    name: 'Switchboard Aggregator Validation',
    severity: 'high',
    pattern: /switchboard|aggregator(?![\s\S]{0,100}authority_check|[\s\S]{0,100}job_check)/i,
    description: 'Switchboard aggregators must be validated. Check authority and job configuration.',
    recommendation: 'Verify aggregator authority and queue. Check minimum oracles and job count.'
  },
  {
    id: 'SOL4937',
    name: 'Metaplex Metadata Account Spoofing',
    severity: 'high',
    pattern: /metadata.*account|token_metadata(?![\s\S]{0,100}owner\s*==|[\s\S]{0,100}METADATA_PROGRAM)/i,
    description: 'Metadata accounts can be spoofed if owner not verified. Fake NFT metadata attacks.',
    recommendation: 'Verify metadata.owner == TOKEN_METADATA_PROGRAM_ID. Validate PDA derivation.'
  },
  {
    id: 'SOL4938',
    name: 'Bubblegum cNFT Creator Verification',
    severity: 'high',
    pattern: /cnft|compressed.*nft(?![\s\S]{0,100}creator_verified|[\s\S]{0,100}collection_verified)/i,
    description: 'Compressed NFTs need creator verification. Anyone can set unverified creators.',
    recommendation: 'Check creator.verified == true. Verify collection membership on-chain.'
  },
  {
    id: 'SOL4939',
    name: 'SPL Governance Realm Configuration',
    severity: 'high',
    pattern: /realm|governance.*config(?![\s\S]{0,100}community_mint|[\s\S]{0,100}council_mint)/i,
    description: 'SPL Governance realms need proper mint configuration. Misconfig allows takeover.',
    recommendation: 'Verify realm community_mint and council_mint. Set appropriate voting thresholds.'
  },
  {
    id: 'SOL4940',
    name: 'Squads v4 Multisig Time Lock',
    severity: 'high',
    pattern: /squads|multisig.*time(?![\s\S]{0,100}time_lock|[\s\S]{0,100}execution_delay)/i,
    description: 'Squads v4 supports timelocks. High-value operations should have delays.',
    recommendation: 'Enable timelock for treasury operations. Set appropriate execution delay.'
  },
  
  // 2026 Emerging Attack Vectors
  {
    id: 'SOL4941',
    name: 'AI Agent Autonomous Trading Exploit',
    severity: 'critical',
    pattern: /autonomous.*trade|ai.*execute(?![\s\S]{0,100}human_approval|[\s\S]{0,100}limit_check)/i,
    description: '2026: AI agents with autonomous trading can be exploited via adversarial inputs.',
    recommendation: 'Implement trading limits. Require human approval above thresholds. Add circuit breakers.'
  },
  {
    id: 'SOL4942',
    name: 'LLM Prompt Injection in dApps',
    severity: 'critical',
    pattern: /llm|gpt|claude(?![\s\S]{0,100}sanitize|[\s\S]{0,100}filter_input)/i,
    description: '2026: dApps using LLMs vulnerable to prompt injection. Malicious inputs can bypass controls.',
    recommendation: 'Sanitize all LLM inputs. Implement output validation. Use structured data extraction.'
  },
  {
    id: 'SOL4943',
    name: 'Cross-Chain Message Replay',
    severity: 'critical',
    pattern: /cross.*chain.*message|bridge.*message(?![\s\S]{0,100}nonce|[\s\S]{0,100}sequence)/i,
    description: 'Cross-chain messages without nonces can be replayed. Double-spend across chains.',
    recommendation: 'Include unique nonce/sequence in all cross-chain messages. Track processed messages.'
  },
  {
    id: 'SOL4944',
    name: 'Intent-Based Settlement Manipulation',
    severity: 'critical',
    pattern: /intent.*settle|settlement.*order(?![\s\S]{0,100}verify_price|[\s\S]{0,100}user_check)/i,
    description: '2026: Intent-based protocols vulnerable to solver manipulation during settlement.',
    recommendation: 'Verify settlement matches intent parameters. Implement solver reputation.'
  },
  {
    id: 'SOL4945',
    name: 'Zero-Knowledge Proof Verification Bypass',
    severity: 'critical',
    pattern: /zk.*proof|zero.*knowledge(?![\s\S]{0,100}verify_proof|[\s\S]{0,100}groth16)/i,
    description: '2026: ZK proofs in Solana programs need proper verification. Invalid proofs = exploit.',
    recommendation: 'Use battle-tested ZK verification libraries. Verify all proof parameters.'
  },
  {
    id: 'SOL4946',
    name: 'FHE (Fully Homomorphic Encryption) Misuse',
    severity: 'critical',
    pattern: /fhe|homomorphic(?![\s\S]{0,100}parameter_check|[\s\S]{0,100}noise_budget)/i,
    description: '2026: FHE implementations can leak information if parameters misconfigured.',
    recommendation: 'Use standard FHE parameters. Monitor noise budget. Implement proper key management.'
  },
  {
    id: 'SOL4947',
    name: 'Rollup Sequencer Centralization',
    severity: 'high',
    pattern: /sequencer|rollup(?![\s\S]{0,100}decentralized|[\s\S]{0,100}force_inclusion)/i,
    description: '2026: Centralized sequencers can censor transactions. Need force-inclusion mechanism.',
    recommendation: 'Implement escape hatch for L1 transaction inclusion. Decentralize sequencer set.'
  },
  {
    id: 'SOL4948',
    name: 'Data Availability Layer Attack',
    severity: 'critical',
    pattern: /data.*availability|da.*layer(?![\s\S]{0,100}verify_commitment|[\s\S]{0,100}erasure_coding)/i,
    description: '2026: DA layers can withhold data, causing liveness failures. Need verification.',
    recommendation: 'Use data availability sampling. Implement erasure coding for data recovery.'
  },
  {
    id: 'SOL4949',
    name: 'Modular Stack Integration Risk',
    severity: 'high',
    pattern: /modular|layer.*integration(?![\s\S]{0,100}verify_each|[\s\S]{0,100}trust_assumption)/i,
    description: '2026: Modular blockchain stacks have integration risks. Trust assumptions compound.',
    recommendation: 'Verify each layer independently. Document and audit trust assumptions.'
  },
  {
    id: 'SOL4950',
    name: 'Cross-Rollup Bridge Exploit',
    severity: 'critical',
    pattern: /cross.*rollup|rollup.*bridge(?![\s\S]{0,100}finality|[\s\S]{0,100}fraud_proof)/i,
    description: '2026: Cross-rollup bridges need finality guarantees. Reorgs can cause double-spend.',
    recommendation: 'Wait for L1 finality before confirming cross-rollup transfers. Implement fraud proofs.'
  },
  
  // Token-2022 Advanced Patterns
  {
    id: 'SOL4951',
    name: 'Token-2022 Transfer Fee Bypass',
    severity: 'critical',
    pattern: /transfer_fee|TransferFee(?![\s\S]{0,100}collect_fee|[\s\S]{0,100}verify_fee)/i,
    description: 'Token-2022 transfer fees can be bypassed via CPI or wrapping. Ensure fee collection.',
    recommendation: 'Verify fees collected on all transfer paths. Handle wrapped token transfers.'
  },
  {
    id: 'SOL4952',
    name: 'Token-2022 Interest Bearing Manipulation',
    severity: 'high',
    pattern: /interest.*bearing|InterestBearingConfig(?![\s\S]{0,100}rate_limit|[\s\S]{0,100}authority_check)/i,
    description: 'Interest-bearing tokens need rate limits. Excessive rates can drain liquidity.',
    recommendation: 'Cap interest rates. Verify authority before rate changes. Add timelock.'
  },
  {
    id: 'SOL4953',
    name: 'Token-2022 Non-Transferable Bypass',
    severity: 'high',
    pattern: /non_transferable|NonTransferable(?![\s\S]{0,100}enforce|[\s\S]{0,100}cpi_check)/i,
    description: 'Non-transferable tokens can potentially be burned and re-minted. Check authority.',
    recommendation: 'Verify mint/burn authority is restricted. Check for bypass via CPI.'
  },
  {
    id: 'SOL4954',
    name: 'Token-2022 Metadata Extension Spoofing',
    severity: 'medium',
    pattern: /token.*metadata|metadata.*pointer(?![\s\S]{0,100}verify_authority)/i,
    description: 'Token-2022 metadata can be updated by authority. Verify before trusting.',
    recommendation: 'Pin expected metadata. Verify update_authority before trusting metadata.'
  },
  {
    id: 'SOL4955',
    name: 'Token-2022 Group/Member Token Validation',
    severity: 'high',
    pattern: /group.*member|token.*group(?![\s\S]{0,100}verify_membership|[\s\S]{0,100}group_authority)/i,
    description: 'Token groups can be exploited if membership not validated. Fake group attacks.',
    recommendation: 'Verify token group membership on-chain. Check group authority.'
  },
  
  // MEV and Transaction Ordering
  {
    id: 'SOL4956',
    name: 'Bundle Inclusion Guarantee Missing',
    severity: 'high',
    pattern: /jito.*bundle|bundle.*tip(?![\s\S]{0,100}all_or_nothing|[\s\S]{0,100}atomic)/i,
    description: 'Jito bundles need atomic execution. Partial inclusion can be exploited.',
    recommendation: 'Use Jito bundle with all-or-nothing execution. Set appropriate tip.'
  },
  {
    id: 'SOL4957',
    name: 'Mempool Observation Attack',
    severity: 'high',
    pattern: /mempool|pending.*transaction(?![\s\S]{0,100}private_mempool|[\s\S]{0,100}encrypted)/i,
    description: 'Public mempool transactions can be front-run. Use private submission.',
    recommendation: 'Use Jito block engine or other private mempool solutions.'
  },
  {
    id: 'SOL4958',
    name: 'Time-Bandit Attack on Reorgs',
    severity: 'critical',
    pattern: /reorg|reorganization(?![\s\S]{0,100}finality|[\s\S]{0,100}confirmation)/i,
    description: 'Profitable reorgs can reverse finalized transactions. Wait for sufficient confirmations.',
    recommendation: 'Wait for finality (~32 slots). Implement reorg detection and alerts.'
  },
  {
    id: 'SOL4959',
    name: 'Leader Schedule Manipulation',
    severity: 'high',
    pattern: /leader.*schedule|slot.*leader(?![\s\S]{0,100}verify_schedule)/i,
    description: 'Leader schedule is predictable. Attackers can time attacks for specific leaders.',
    recommendation: 'Monitor for targeted attacks on specific slots. Implement rate limiting.'
  },
  {
    id: 'SOL4960',
    name: 'Block Stuffing Attack',
    severity: 'high',
    pattern: /block.*stuff|fill.*block(?![\s\S]{0,100}rate_limit|[\s\S]{0,100}priority_check)/i,
    description: 'Attackers can stuff blocks with transactions, delaying legitimate users.',
    recommendation: 'Use priority fees. Implement transaction prioritization mechanisms.'
  },
  
  // Account Model Security
  {
    id: 'SOL4961',
    name: 'Account Lamport Manipulation',
    severity: 'high',
    pattern: /lamports|try_borrow_mut_lamports(?![\s\S]{0,100}checked_sub|[\s\S]{0,100}checked_add)/i,
    description: 'Lamport manipulations need checked arithmetic. Overflow can mint lamports.',
    recommendation: 'Use checked arithmetic for all lamport operations.'
  },
  {
    id: 'SOL4962',
    name: 'Account Data Alias Vulnerability',
    severity: 'critical',
    pattern: /borrow_mut|RefMut(?![\s\S]{0,100}drop|[\s\S]{0,100}single_borrow)/i,
    description: 'Multiple mutable borrows of same account data can cause aliasing issues.',
    recommendation: 'Ensure only one mutable borrow at a time. Drop borrows before re-borrowing.'
  },
  {
    id: 'SOL4963',
    name: 'Zero Account Detection Bypass',
    severity: 'high',
    pattern: /zero.*account|empty.*account(?![\s\S]{0,100}lamport_check|[\s\S]{0,100}data_len)/i,
    description: 'Zero-lamport accounts can be garbage collected. Check before use.',
    recommendation: 'Verify account has lamports and data before using. Handle GC\'d accounts.'
  },
  {
    id: 'SOL4964',
    name: 'Account Size Reallocation Race',
    severity: 'high',
    pattern: /realloc|AccountInfo.*realloc(?![\s\S]{0,100}single_transaction|[\s\S]{0,100}atomic)/i,
    description: 'Reallocation in one instruction, access in another can cause race conditions.',
    recommendation: 'Complete reallocation and usage in same instruction. Verify size after realloc.'
  },
  {
    id: 'SOL4965',
    name: 'Rent Exemption Edge Case',
    severity: 'medium',
    pattern: /rent_exempt|minimum_balance(?![\s\S]{0,100}plus_data|[\s\S]{0,100}account_size)/i,
    description: 'Rent exemption calculation must include all account data. Edge cases exist.',
    recommendation: 'Calculate rent exemption with actual data size. Account for potential reallocs.'
  },
  
  // Error Handling Patterns
  {
    id: 'SOL4966',
    name: 'Silent Error Swallowing',
    severity: 'high',
    pattern: /ok\(\)|unwrap_or_default|if let Err\(_\)/i,
    description: 'Swallowing errors silently can hide security issues. Propagate or handle explicitly.',
    recommendation: 'Propagate errors with ?. Log errors before handling. Never silently ignore.'
  },
  {
    id: 'SOL4967',
    name: 'Panic in Production Code',
    severity: 'high',
    pattern: /panic!|unreachable!|todo!|unimplemented!/i,
    description: 'Panics cause transaction failures and can be triggered by attackers.',
    recommendation: 'Replace panics with proper error handling. Use Result instead of panic.'
  },
  {
    id: 'SOL4968',
    name: 'Error Message Information Leak',
    severity: 'medium',
    pattern: /error![\s\S]{0,50}(key|secret|password|token)/i,
    description: 'Error messages can leak sensitive information in transaction logs.',
    recommendation: 'Use generic error messages. Don\'t include sensitive data in errors.'
  },
  {
    id: 'SOL4969',
    name: 'Missing Error Code Uniqueness',
    severity: 'low',
    pattern: /#\[error_code\][\s\S]{0,200}(?!#\[msg)/,
    description: 'Anchor error codes should have unique messages for debugging.',
    recommendation: 'Add #[msg("...")] to all error variants for clear debugging.'
  },
  {
    id: 'SOL4970',
    name: 'Assertion Instead of Error',
    severity: 'medium',
    pattern: /assert!|assert_eq!(?![\s\S]{0,20}test)/i,
    description: 'Assertions panic on failure. Use require! or return Err for graceful handling.',
    recommendation: 'Replace assert! with require! in Anchor. Use proper error types in native.'
  },
  
  // Cryptographic Security
  {
    id: 'SOL4971',
    name: 'Weak Randomness Source',
    severity: 'critical',
    pattern: /random|rand(?![\s\S]{0,50}vrf|[\s\S]{0,50}switchboard|[\s\S]{0,50}chainlink)/i,
    description: 'On-chain randomness is predictable. Use VRF or external randomness.',
    recommendation: 'Use Switchboard VRF or similar. Never use clock/slot for randomness.'
  },
  {
    id: 'SOL4972',
    name: 'ED25519 Signature Malleability',
    severity: 'high',
    pattern: /ed25519|verify_signature(?![\s\S]{0,100}canonical|[\s\S]{0,100}low_s)/i,
    description: 'ED25519 signatures can have multiple valid forms. Enforce canonical form.',
    recommendation: 'Verify signature is in canonical form. Use standard verification libraries.'
  },
  {
    id: 'SOL4973',
    name: 'Hash Collision Vulnerability',
    severity: 'critical',
    pattern: /hash(?![\s\S]{0,50}sha256|[\s\S]{0,50}keccak|[\s\S]{0,50}blake)/i,
    description: 'Custom hash functions may be collision-prone. Use standard cryptographic hashes.',
    recommendation: 'Use SHA256, Keccak, or Blake3. Avoid custom hash implementations.'
  },
  {
    id: 'SOL4974',
    name: 'Merkle Tree Second Preimage Attack',
    severity: 'critical',
    pattern: /merkle.*leaf|leaf.*hash(?![\s\S]{0,100}prefix|[\s\S]{0,100}domain_sep)/i,
    description: 'Merkle trees without leaf prefixes vulnerable to second preimage attack.',
    recommendation: 'Add domain separator/prefix to leaf hashes. Use 0x00 for leaves, 0x01 for nodes.'
  },
  {
    id: 'SOL4975',
    name: 'ECDSA Recovery ID Manipulation',
    severity: 'high',
    pattern: /recovery_id|ecrecover(?![\s\S]{0,100}verify_recovery)/i,
    description: 'ECDSA recovery IDs can be manipulated. Verify recovered address matches expected.',
    recommendation: 'Always verify recovered address. Don\'t trust recovery without address check.'
  },
  
  // Serialization Security
  {
    id: 'SOL4976',
    name: 'Borsh Deserialization Overflow',
    severity: 'critical',
    pattern: /borsh.*deserialize|try_from_slice(?![\s\S]{0,100}size_check|[\s\S]{0,100}length_limit)/i,
    description: 'Borsh deserialization can read past buffer bounds. Validate data length.',
    recommendation: 'Check data length before deserializing. Use try_from_slice, not from_slice.'
  },
  {
    id: 'SOL4977',
    name: 'Variable Length Field Manipulation',
    severity: 'high',
    pattern: /Vec<|String|Option<Vec(?![\s\S]{0,100}max_len|[\s\S]{0,100}bounded)/i,
    description: 'Variable length fields in accounts can be manipulated to exceed expected size.',
    recommendation: 'Bound variable length fields with max sizes. Validate on deserialization.'
  },
  {
    id: 'SOL4978',
    name: 'Account Padding Exploitation',
    severity: 'medium',
    pattern: /repr\(C\)|padding(?![\s\S]{0,100}zeroed|[\s\S]{0,100}initialized)/i,
    description: 'Padding bytes in repr(C) structs can contain uninitialized data.',
    recommendation: 'Initialize all struct fields including padding. Use #[repr(packed)] if needed.'
  },
  {
    id: 'SOL4979',
    name: 'Cross-Program Serialization Mismatch',
    severity: 'high',
    pattern: /cpi[\s\S]{0,50}serialize|invoke[\s\S]{0,50}data(?![\s\S]{0,100}verify_format)/i,
    description: 'Different programs may use different serialization. Verify format compatibility.',
    recommendation: 'Use standard Anchor/Borsh serialization. Document and verify data formats.'
  },
  {
    id: 'SOL4980',
    name: 'Instruction Data Length Manipulation',
    severity: 'high',
    pattern: /instruction.*data|data\[[\s\S]{0,20}\.\.(?![\s\S]{0,30}len\s*<|[\s\S]{0,30}len\s*==)/,
    description: 'Instruction data length can be manipulated. Validate expected length.',
    recommendation: 'Check instruction data length matches expected. Reject unexpected sizes.'
  },
  
  // State Machine Security
  {
    id: 'SOL4981',
    name: 'Invalid State Transition',
    severity: 'critical',
    pattern: /state.*transition|status.*change(?![\s\S]{0,100}valid_transition|[\s\S]{0,100}state_machine)/i,
    description: 'State machines without transition validation allow invalid state changes.',
    recommendation: 'Define valid state transitions. Reject invalid transitions with errors.'
  },
  {
    id: 'SOL4982',
    name: 'Race Condition in State Update',
    severity: 'high',
    pattern: /state.*update|update.*state(?![\s\S]{0,100}atomic|[\s\S]{0,100}single_instruction)/i,
    description: 'Non-atomic state updates can cause race conditions across transactions.',
    recommendation: 'Complete state updates atomically within single instruction.'
  },
  {
    id: 'SOL4983',
    name: 'Missing State Initialization Check',
    severity: 'critical',
    pattern: /state.*enum|Status[\s\S]{0,50}(?!Uninitialized|NotInitialized)/i,
    description: 'State enums should include Uninitialized variant to detect uninitialized accounts.',
    recommendation: 'Add Uninitialized variant to state enums. Check state before operations.'
  },
  {
    id: 'SOL4984',
    name: 'Final State Reversibility',
    severity: 'high',
    pattern: /final.*state|completed|closed(?![\s\S]{0,100}irreversible|[\s\S]{0,100}no_modify)/i,
    description: 'Final states should be irreversible. Completed/closed accounts shouldn\'t change.',
    recommendation: 'Mark final states as immutable. Reject any modifications after finalization.'
  },
  {
    id: 'SOL4985',
    name: 'Concurrent State Modification',
    severity: 'high',
    pattern: /concurrent|parallel.*update(?![\s\S]{0,100}lock|[\s\S]{0,100}mutex)/i,
    description: 'Concurrent modifications to same state can cause inconsistencies.',
    recommendation: 'Use version numbers or locks for concurrent access. Implement optimistic locking.'
  },
  
  // Access Control Patterns
  {
    id: 'SOL4986',
    name: 'Privilege Escalation via Delegation',
    severity: 'critical',
    pattern: /delegate|delegation(?![\s\S]{0,100}scope_limit|[\s\S]{0,100}privilege_check)/i,
    description: 'Delegation without scope limits allows privilege escalation.',
    recommendation: 'Limit delegated permissions. Implement scope restrictions on delegations.'
  },
  {
    id: 'SOL4987',
    name: 'Role Assignment Without Verification',
    severity: 'critical',
    pattern: /role.*assign|assign.*role(?![\s\S]{0,100}authority_check|[\s\S]{0,100}multisig)/i,
    description: 'Role assignments need proper authority verification. Single point of failure.',
    recommendation: 'Require multisig or DAO approval for role assignments.'
  },
  {
    id: 'SOL4988',
    name: 'Emergency Admin Backdoor',
    severity: 'critical',
    pattern: /emergency.*admin|admin.*override(?![\s\S]{0,100}timelock|[\s\S]{0,100}multisig)/i,
    description: 'Emergency admin powers without controls can be abused.',
    recommendation: 'Emergency powers require multisig + timelock. Log all emergency actions.'
  },
  {
    id: 'SOL4989',
    name: 'Authority Transfer Without Acceptance',
    severity: 'high',
    pattern: /transfer.*authority|set.*authority(?![\s\S]{0,100}accept|[\s\S]{0,100}two_step)/i,
    description: 'Direct authority transfer can send to wrong address. Use two-step transfer.',
    recommendation: 'Implement two-step authority transfer: propose then accept.'
  },
  {
    id: 'SOL4990',
    name: 'Missing Permission Revocation',
    severity: 'high',
    pattern: /permission|access(?![\s\S]{0,100}revoke|[\s\S]{0,100}remove)/i,
    description: 'Permissions granted should be revocable. Forgotten access = security risk.',
    recommendation: 'Implement revocation for all permissions. Audit access periodically.'
  },
  
  // Economic Security
  {
    id: 'SOL4991',
    name: 'Token Emission Without Cap',
    severity: 'critical',
    pattern: /mint.*token|token.*emission(?![\s\S]{0,100}max_supply|[\s\S]{0,100}cap)/i,
    description: 'Uncapped token emission leads to inflation. Implement hard supply cap.',
    recommendation: 'Set maximum supply. Implement emission schedule. Monitor total supply.'
  },
  {
    id: 'SOL4992',
    name: 'Fee Accumulation Exploitation',
    severity: 'high',
    pattern: /fee.*accumulate|accumulated.*fee(?![\s\S]{0,100}claim_limit|[\s\S]{0,100}distribution)/i,
    description: 'Accumulated fees can be exploited if claim mechanism is flawed.',
    recommendation: 'Implement fair fee distribution. Add claim rate limits.'
  },
  {
    id: 'SOL4993',
    name: 'Reward Distribution Front-running',
    severity: 'high',
    pattern: /reward.*distribution|distribute.*reward(?![\s\S]{0,100}snapshot|[\s\S]{0,100}merkle)/i,
    description: 'Reward distributions can be front-run. Deposit before, claim after.',
    recommendation: 'Use snapshots for reward eligibility. Implement claiming delays.'
  },
  {
    id: 'SOL4994',
    name: 'Treasury Drain via Governance',
    severity: 'critical',
    pattern: /treasury.*withdraw|governance.*treasury(?![\s\S]{0,100}timelock|[\s\S]{0,100}limit)/i,
    description: 'Governance can drain treasury if no safeguards. Synthetify DAO pattern.',
    recommendation: 'Implement withdrawal limits. Require timelock + multisig for large amounts.'
  },
  {
    id: 'SOL4995',
    name: 'Airdrop Farming Detection',
    severity: 'medium',
    pattern: /airdrop|claim.*token(?![\s\S]{0,100}sybil_check|[\s\S]{0,100}eligibility)/i,
    description: 'Airdrops can be farmed via Sybil accounts. Implement eligibility checks.',
    recommendation: 'Use on-chain activity history. Implement Sybil resistance mechanisms.'
  },
  
  // Testing and Audit Patterns
  {
    id: 'SOL4996',
    name: 'Missing Fuzz Testing',
    severity: 'medium',
    pattern: /#\[test\](?![\s\S]{0,500}fuzz|[\s\S]{0,500}proptest)/i,
    description: 'Unit tests may miss edge cases. Fuzz testing finds unexpected inputs.',
    recommendation: 'Implement fuzz testing with cargo-fuzz or proptest. Test edge cases.'
  },
  {
    id: 'SOL4997',
    name: 'No Integration Tests',
    severity: 'medium',
    pattern: /mod tests(?![\s\S]{0,500}integration|[\s\S]{0,500}BanksClient)/i,
    description: 'Unit tests don\'t catch CPI or account interaction issues. Need integration tests.',
    recommendation: 'Write integration tests with BanksClient or Anchor testing framework.'
  },
  {
    id: 'SOL4998',
    name: 'Unaudited Code Path',
    severity: 'high',
    pattern: /\/\/\s*TODO|\/\/\s*FIXME|\/\/\s*HACK(?![\s\S]{0,30}audit)/i,
    description: 'TODO/FIXME comments indicate incomplete code. Should be resolved before deploy.',
    recommendation: 'Resolve all TODOs before deployment. Mark audit exclusions explicitly.'
  },
  {
    id: 'SOL4999',
    name: 'Missing Audit Trail',
    severity: 'medium',
    pattern: /authority.*change|config.*update(?![\s\S]{0,100}emit!|[\s\S]{0,100}event)/i,
    description: 'Critical operations should emit events for audit trail.',
    recommendation: 'Emit events for all state-changing operations. Include relevant parameters.'
  },
  {
    id: 'SOL5000',
    name: 'Incomplete Documentation',
    severity: 'low',
    pattern: /pub\s+fn\s+\w+(?![\s\S]{0,30}\/\/\/|[\s\S]{0,30}#\[doc)/,
    description: 'Public functions without documentation increase audit difficulty.',
    recommendation: 'Document all public functions. Explain security considerations.'
  },
];

/**
 * Run Batch 89 patterns against input
 */
export function checkBatch89Patterns(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  const fileName = input.path || input.rust?.filePath || 'unknown';
  
  if (!content) return findings;
  
  const lines = content.split('\n');
  
  for (const pattern of BATCH_89_PATTERNS) {
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

export default BATCH_89_PATTERNS;
