/**
 * SolShield Pattern Batch 59: 2025 Latest Exploits + Advanced Attack Vectors (SOL2421-SOL2490)
 * 
 * Source: Helius Complete History (Updated Q1 2025), Sec3 2025 Report
 * 
 * New exploits covered:
 * - Loopscale ($5.8M) - April 2025
 * - Thunder Terminal - MongoDB injection
 * - Banana Gun - MEV bot compromise  
 * - NoOnes Platform - API key exposure
 * - Aurory - NFT gaming exploit
 * - Saga DAO - Governance attack
 * - Solareum - LP drain
 * - Parcl Front-End - Supply chain
 * - Web3.js - npm package compromise
 */

import type { Finding, PatternInput } from './index.js';

interface PatternDef {
  id: string;
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  pattern: RegExp;
  description: string;
  recommendation: string;
  exploit?: string;
}

const BATCH_59_PATTERNS: PatternDef[] = [
  // Loopscale $5.8M Exploit (April 2025)
  {
    id: 'SOL2421',
    name: 'Loopscale Collateral Under-Collateralization',
    severity: 'critical',
    pattern: /collateral_ratio|health_factor(?![\s\S]{0,100}minimum_ratio|[\s\S]{0,100}>=\s*\d)/i,
    description: 'Lending protocol without minimum collateral ratio enforcement (Loopscale $5.8M).',
    recommendation: 'Enforce minimum collateral ratios with constant checks.',
    exploit: 'Loopscale April 2025 - $5.8M'
  },
  {
    id: 'SOL2422',
    name: 'Loopscale Flashloan Arbitrage',
    severity: 'critical',
    pattern: /borrow[\s\S]{0,100}repay[\s\S]{0,100}(?!same_transaction|atomic)/i,
    description: 'Flash loan without same-transaction repayment verification.',
    recommendation: 'Verify flash loans repaid in same transaction.',
    exploit: 'Loopscale April 2025 - $5.8M'
  },
  {
    id: 'SOL2423',
    name: 'Loopscale Oracle Frontrunning',
    severity: 'high',
    pattern: /oracle[\s\S]{0,50}update(?![\s\S]{0,50}delay|[\s\S]{0,50}commitment)/i,
    description: 'Oracle updates without frontrunning protection.',
    recommendation: 'Add delay or use commit-reveal for oracle updates.',
    exploit: 'Loopscale April 2025 - $5.8M'
  },

  // Thunder Terminal - MongoDB Injection
  {
    id: 'SOL2424',
    name: 'Thunder Terminal External DB Query',
    severity: 'critical',
    pattern: /database|mongodb|query[\s\S]{0,50}user_input(?![\s\S]{0,50}sanitize|[\s\S]{0,50}escape)/i,
    description: 'External database queries with unsanitized input (Thunder Terminal pattern).',
    recommendation: 'Sanitize all external inputs before database queries.',
    exploit: 'Thunder Terminal 2024'
  },
  {
    id: 'SOL2425',
    name: 'Thunder Terminal Session Management',
    severity: 'high',
    pattern: /session|jwt[\s\S]{0,50}(?![\s\S]{0,50}expire|[\s\S]{0,50}rotate)/i,
    description: 'Session tokens without expiration or rotation.',
    recommendation: 'Implement session expiration and token rotation.',
    exploit: 'Thunder Terminal 2024'
  },

  // Banana Gun MEV Bot Compromise
  {
    id: 'SOL2426',
    name: 'Banana Gun MEV Bot Private Key Storage',
    severity: 'critical',
    pattern: /private_key|secret_key[\s\S]{0,50}(store|save|persist)(?![\s\S]{0,50}encrypt|[\s\S]{0,50}vault)/i,
    description: 'Private keys stored without encryption (Banana Gun pattern).',
    recommendation: 'Use hardware security modules or encrypted vaults.',
    exploit: 'Banana Gun 2024 - $1.4M'
  },
  {
    id: 'SOL2427',
    name: 'Banana Gun MEV Oracle Dependency',
    severity: 'high',
    pattern: /mev|sandwich[\s\S]{0,50}oracle(?![\s\S]{0,50}multi_source)/i,
    description: 'MEV bot relying on single oracle source.',
    recommendation: 'Use multiple oracle sources for MEV operations.',
    exploit: 'Banana Gun 2024 - $1.4M'
  },

  // NoOnes Platform - API Key Exposure
  {
    id: 'SOL2428',
    name: 'NoOnes API Key in Client',
    severity: 'critical',
    pattern: /api_key|apikey[\s\S]{0,30}(client|frontend|browser)(?![\s\S]{0,50}proxy)/i,
    description: 'API keys exposed to client-side code (NoOnes pattern).',
    recommendation: 'Use backend proxy for API key authenticated requests.',
    exploit: 'NoOnes Platform 2024'
  },
  {
    id: 'SOL2429',
    name: 'NoOnes Platform Withdrawal Rate Limit',
    severity: 'high',
    pattern: /withdraw[\s\S]{0,50}(?![\s\S]{0,50}rate_limit|[\s\S]{0,50}cooldown|[\s\S]{0,50}daily_limit)/i,
    description: 'Withdrawal operations without rate limiting.',
    recommendation: 'Implement withdrawal rate limits and daily caps.',
    exploit: 'NoOnes Platform 2024'
  },

  // Aurory NFT Gaming Exploit
  {
    id: 'SOL2430',
    name: 'Aurory NFT Attribute Manipulation',
    severity: 'high',
    pattern: /nft[\s\S]{0,50}attribute|metadata[\s\S]{0,50}(?![\s\S]{0,50}immutable|[\s\S]{0,50}freeze)/i,
    description: 'NFT attributes mutable after mint (Aurory pattern).',
    recommendation: 'Freeze NFT attributes after initial mint.',
    exploit: 'Aurory NFT Gaming 2024'
  },
  {
    id: 'SOL2431',
    name: 'Aurory Game Economy Inflation',
    severity: 'high',
    pattern: /reward|mint[\s\S]{0,50}game(?![\s\S]{0,50}cap|[\s\S]{0,50}max_supply)/i,
    description: 'Game reward minting without supply caps.',
    recommendation: 'Implement hard caps on game economy token supply.',
    exploit: 'Aurory NFT Gaming 2024'
  },

  // Saga DAO Governance Attack
  {
    id: 'SOL2432',
    name: 'Saga DAO Proposal Timing Attack',
    severity: 'critical',
    pattern: /proposal[\s\S]{0,50}vote(?![\s\S]{0,50}delay|[\s\S]{0,50}lock_period)/i,
    description: 'DAO proposals without voting delay (Saga DAO pattern).',
    recommendation: 'Implement mandatory voting delay after proposal creation.',
    exploit: 'Saga DAO 2024'
  },
  {
    id: 'SOL2433',
    name: 'Saga DAO Flash Governance',
    severity: 'critical',
    pattern: /governance[\s\S]{0,50}token[\s\S]{0,50}(?![\s\S]{0,50}snapshot|[\s\S]{0,50}lock)/i,
    description: 'Governance tokens without snapshot or lock requirement.',
    recommendation: 'Require token lock or snapshot for voting power.',
    exploit: 'Saga DAO 2024'
  },

  // Solareum LP Drain
  {
    id: 'SOL2434',
    name: 'Solareum LP Token Validation',
    severity: 'critical',
    pattern: /lp_token|liquidity[\s\S]{0,50}(?![\s\S]{0,50}verify_pool|[\s\S]{0,50}owner_check)/i,
    description: 'LP token operations without pool verification (Solareum pattern).',
    recommendation: 'Verify LP token belongs to expected pool.',
    exploit: 'Solareum 2024'
  },
  {
    id: 'SOL2435',
    name: 'Solareum Admin Backdoor',
    severity: 'critical',
    pattern: /admin[\s\S]{0,30}(emergency|bypass)(?![\s\S]{0,50}multisig|[\s\S]{0,50}timelock)/i,
    description: 'Admin emergency functions without multisig.',
    recommendation: 'Require multisig and timelock for emergency functions.',
    exploit: 'Solareum 2024'
  },

  // Parcl Front-End Supply Chain
  {
    id: 'SOL2436',
    name: 'Parcl Frontend CDN Integrity',
    severity: 'high',
    pattern: /cdn|external[\s\S]{0,50}script(?![\s\S]{0,50}integrity|[\s\S]{0,50}sri)/i,
    description: 'External scripts without SRI integrity check (Parcl pattern).',
    recommendation: 'Add Subresource Integrity (SRI) to external scripts.',
    exploit: 'Parcl Front-End 2024'
  },
  {
    id: 'SOL2437',
    name: 'Parcl DNS Hijack Risk',
    severity: 'high',
    pattern: /domain|dns(?![\s\S]{0,50}dnssec|[\s\S]{0,50}certificate_pin)/i,
    description: 'Frontend DNS without DNSSEC or certificate pinning.',
    recommendation: 'Enable DNSSEC and certificate pinning.',
    exploit: 'Parcl Front-End 2024'
  },

  // Web3.js NPM Package Compromise
  {
    id: 'SOL2438',
    name: 'Web3.js Dependency Verification',
    severity: 'critical',
    pattern: /@solana\/web3\.js(?![\s\S]{0,30}\d+\.\d+\.\d+)/i,
    description: 'Solana web3.js without pinned version (supply chain risk).',
    recommendation: 'Pin @solana/web3.js to verified version.',
    exploit: 'Web3.js NPM Compromise 2024'
  },
  {
    id: 'SOL2439',
    name: 'Web3.js Signing Interception',
    severity: 'critical',
    pattern: /signTransaction|signAllTransactions(?![\s\S]{0,50}verify_origin)/i,
    description: 'Transaction signing without origin verification.',
    recommendation: 'Verify signing requests come from trusted origin.',
    exploit: 'Web3.js NPM Compromise 2024'
  },

  // Synthetify DAO Attack
  {
    id: 'SOL2440',
    name: 'Synthetify DAO Unnoticed Proposal',
    severity: 'high',
    pattern: /proposal[\s\S]{0,50}(?![\s\S]{0,50}notify|[\s\S]{0,50}alert|[\s\S]{0,50}announce)/i,
    description: 'DAO proposals without mandatory notification (Synthetify pattern).',
    recommendation: 'Require mandatory notification for new proposals.',
    exploit: 'Synthetify DAO $230K'
  },

  // Sec3 2025 Business Logic Patterns
  {
    id: 'SOL2441',
    name: 'Sec3 State Machine Violation',
    severity: 'high',
    pattern: /state[\s\S]{0,30}=[\s\S]{0,30}(?![\s\S]{0,50}valid_transition|[\s\S]{0,50}require_state)/i,
    description: 'State transitions without validity check (Sec3 2025: 38.5% of vulns).',
    recommendation: 'Validate all state transitions against allowed paths.'
  },
  {
    id: 'SOL2442',
    name: 'Sec3 Invariant Check Missing',
    severity: 'high',
    pattern: /total|balance[\s\S]{0,30}(add|sub)(?![\s\S]{0,50}assert_invariant)/i,
    description: 'State changes without invariant preservation check.',
    recommendation: 'Assert invariants after all state-changing operations.'
  },
  {
    id: 'SOL2443',
    name: 'Sec3 Order-Dependent Logic',
    severity: 'medium',
    pattern: /instruction[\s\S]{0,30}(first|before|after)(?![\s\S]{0,50}enforce_order)/i,
    description: 'Business logic dependent on instruction ordering.',
    recommendation: 'Use explicit ordering constraints or sequence numbers.'
  },

  // Sec3 2025 Input Validation (25%)
  {
    id: 'SOL2444',
    name: 'Sec3 Input Range Validation',
    severity: 'high',
    pattern: /amount|quantity[\s\S]{0,20}:[\s\S]{0,10}u64(?![\s\S]{0,50}require!.*[<>])/i,
    description: 'Numeric inputs without range validation (Sec3 2025: 25% of vulns).',
    recommendation: 'Validate input ranges: min, max, non-zero checks.'
  },
  {
    id: 'SOL2445',
    name: 'Sec3 String Input Sanitization',
    severity: 'medium',
    pattern: /String[\s\S]{0,30}(?![\s\S]{0,50}len\(\)|[\s\S]{0,50}max_len|[\s\S]{0,50}sanitize)/i,
    description: 'String inputs without length or content validation.',
    recommendation: 'Validate string length and sanitize special characters.'
  },
  {
    id: 'SOL2446',
    name: 'Sec3 Account Data Bounds',
    severity: 'high',
    pattern: /data\[[\s\S]{0,20}\](?![\s\S]{0,30}\.get\(|[\s\S]{0,30}checked)/i,
    description: 'Direct array index access without bounds checking.',
    recommendation: 'Use .get() or bounds-checked access methods.'
  },

  // Sec3 2025 Access Control (19%)
  {
    id: 'SOL2447',
    name: 'Sec3 Role-Based Access Missing',
    severity: 'critical',
    pattern: /admin|owner[\s\S]{0,30}(?![\s\S]{0,50}has_role|[\s\S]{0,50}require_role)/i,
    description: 'Privileged operations without RBAC (Sec3 2025: 19% of vulns).',
    recommendation: 'Implement role-based access control for all admin functions.'
  },
  {
    id: 'SOL2448',
    name: 'Sec3 Privilege Escalation Path',
    severity: 'critical',
    pattern: /set_authority|transfer_authority(?![\s\S]{0,50}require_current_authority)/i,
    description: 'Authority transfer without current authority verification.',
    recommendation: 'Require current authority signature for transfers.'
  },
  {
    id: 'SOL2449',
    name: 'Sec3 Capability Leak',
    severity: 'high',
    pattern: /signer[\s\S]{0,30}seeds(?![\s\S]{0,50}verify_capability)/i,
    description: 'PDA signer seeds exposed without capability verification.',
    recommendation: 'Verify caller has capability before exposing signer seeds.'
  },

  // Sec3 2025 Data Integrity (8.9%)
  {
    id: 'SOL2450',
    name: 'Sec3 Cross-Reference Integrity',
    severity: 'high',
    pattern: /reference|pointer[\s\S]{0,30}(?![\s\S]{0,50}verify_exists|[\s\S]{0,50}constraint)/i,
    description: 'Cross-references without existence verification.',
    recommendation: 'Verify referenced accounts exist and are valid.'
  },
  {
    id: 'SOL2451',
    name: 'Sec3 Timestamp Manipulation',
    severity: 'medium',
    pattern: /clock[\s\S]{0,30}unix_timestamp(?![\s\S]{0,50}tolerance|[\s\S]{0,50}window)/i,
    description: 'Clock timestamp used without manipulation tolerance.',
    recommendation: 'Allow timestamp tolerance window for validator variance.'
  },

  // Sec3 2025 DoS/Liveness (8.5%)
  {
    id: 'SOL2452',
    name: 'Sec3 Unbounded Iteration',
    severity: 'high',
    pattern: /for[\s\S]{0,20}\.iter\(\)(?![\s\S]{0,30}\.take\(|[\s\S]{0,30}limit)/i,
    description: 'Unbounded iteration causing compute exhaustion (Sec3 2025: 8.5%).',
    recommendation: 'Limit iterations with .take() or explicit bounds.'
  },
  {
    id: 'SOL2453',
    name: 'Sec3 Account Spam Vulnerability',
    severity: 'medium',
    pattern: /create[\s\S]{0,30}account(?![\s\S]{0,50}fee|[\s\S]{0,50}deposit)/i,
    description: 'Account creation without spam prevention fee.',
    recommendation: 'Require deposit or fee for account creation.'
  },

  // Advanced Attack Vectors 2025
  {
    id: 'SOL2454',
    name: 'JIT Liquidity MEV Attack',
    severity: 'high',
    pattern: /liquidity[\s\S]{0,30}add[\s\S]{0,30}(?![\s\S]{0,50}lock_period)/i,
    description: 'Liquidity provision vulnerable to JIT liquidity attacks.',
    recommendation: 'Add lock period to prevent JIT MEV extraction.'
  },
  {
    id: 'SOL2455',
    name: 'Backrunning Opportunity',
    severity: 'medium',
    pattern: /swap[\s\S]{0,30}emit!(?![\s\S]{0,50}private)/i,
    description: 'Public swap events enabling backrunning.',
    recommendation: 'Consider private mempools or commit-reveal schemes.'
  },
  {
    id: 'SOL2456',
    name: 'Validator Concentration Risk',
    severity: 'medium',
    pattern: /validator|leader(?![\s\S]{0,50}rotate|[\s\S]{0,50}distributed)/i,
    description: 'Operations dependent on specific validator behavior.',
    recommendation: 'Design for validator-independent operation.'
  },

  // Cross-Chain Specific (2025 Trends)
  {
    id: 'SOL2457',
    name: 'Wormhole VAA Replay',
    severity: 'critical',
    pattern: /vaa|guardian[\s\S]{0,30}(?![\s\S]{0,50}nonce|[\s\S]{0,50}sequence)/i,
    description: 'Cross-chain VAA without replay protection.',
    recommendation: 'Track VAA sequence numbers to prevent replay.'
  },
  {
    id: 'SOL2458',
    name: 'Bridge Finality Assumption',
    severity: 'high',
    pattern: /bridge[\s\S]{0,30}confirm(?![\s\S]{0,50}finality|[\s\S]{0,50}confirmations)/i,
    description: 'Cross-chain bridge without finality verification.',
    recommendation: 'Wait for source chain finality before crediting.'
  },
  {
    id: 'SOL2459',
    name: 'Layer 2 Fraud Proof Window',
    severity: 'high',
    pattern: /l2|rollup[\s\S]{0,30}(?![\s\S]{0,50}challenge_period)/i,
    description: 'L2 integration without fraud proof consideration.',
    recommendation: 'Account for challenge period in L2 integrations.'
  },

  // Token-2022 Advanced Patterns
  {
    id: 'SOL2460',
    name: 'Token-2022 Confidential Audit',
    severity: 'high',
    pattern: /confidential[\s\S]{0,30}transfer(?![\s\S]{0,50}audit_key)/i,
    description: 'Confidential transfers without audit capability.',
    recommendation: 'Enable audit keys for compliance requirements.'
  },
  {
    id: 'SOL2461',
    name: 'Token-2022 Transfer Fee Accuracy',
    severity: 'medium',
    pattern: /transfer_fee[\s\S]{0,30}basis_points(?![\s\S]{0,50}max_fee)/i,
    description: 'Transfer fee without maximum cap.',
    recommendation: 'Set max_fee to prevent excessive fee accumulation.'
  },
  {
    id: 'SOL2462',
    name: 'Token-2022 Interest Bearing Calculation',
    severity: 'high',
    pattern: /interest[\s\S]{0,30}rate(?![\s\S]{0,50}compound|[\s\S]{0,50}accrue)/i,
    description: 'Interest bearing tokens without proper accrual.',
    recommendation: 'Use compound interest with regular accrual points.'
  },

  // Compressed NFT Security (2025)
  {
    id: 'SOL2463',
    name: 'cNFT Concurrent Merkle Update',
    severity: 'high',
    pattern: /merkle[\s\S]{0,30}update(?![\s\S]{0,50}concurrent|[\s\S]{0,50}canopy)/i,
    description: 'Merkle tree updates without concurrency handling.',
    recommendation: 'Use concurrent merkle trees with canopy for scale.'
  },
  {
    id: 'SOL2464',
    name: 'cNFT Proof Verification Cost',
    severity: 'medium',
    pattern: /verify_proof[\s\S]{0,30}(?![\s\S]{0,50}canopy_depth)/i,
    description: 'Merkle proof verification without canopy optimization.',
    recommendation: 'Use appropriate canopy depth to reduce proof size.'
  },

  // Blink Actions Security (2025)
  {
    id: 'SOL2465',
    name: 'Blink Action Origin Validation',
    severity: 'critical',
    pattern: /action[\s\S]{0,30}url(?![\s\S]{0,50}verify_domain|[\s\S]{0,50}allowlist)/i,
    description: 'Blink actions without origin domain validation.',
    recommendation: 'Validate action URLs against domain allowlist.'
  },
  {
    id: 'SOL2466',
    name: 'Blink Transaction Preview',
    severity: 'high',
    pattern: /blink[\s\S]{0,30}sign(?![\s\S]{0,50}simulate|[\s\S]{0,50}preview)/i,
    description: 'Blink transactions signed without simulation preview.',
    recommendation: 'Always simulate and preview blink transactions.'
  },

  // AI Agent Wallet Security (2025 Emerging)
  {
    id: 'SOL2467',
    name: 'AI Agent Transaction Limits',
    severity: 'critical',
    pattern: /agent[\s\S]{0,30}wallet(?![\s\S]{0,50}limit|[\s\S]{0,50}allowance)/i,
    description: 'AI agent wallet without transaction limits.',
    recommendation: 'Set per-transaction and daily limits for AI agents.'
  },
  {
    id: 'SOL2468',
    name: 'AI Agent Allowlist Operations',
    severity: 'high',
    pattern: /agent[\s\S]{0,30}(invoke|call)(?![\s\S]{0,50}program_allowlist)/i,
    description: 'AI agent calling arbitrary programs.',
    recommendation: 'Restrict AI agents to allowlisted programs only.'
  },
  {
    id: 'SOL2469',
    name: 'AI Agent Key Rotation',
    severity: 'high',
    pattern: /agent[\s\S]{0,30}key(?![\s\S]{0,50}rotate|[\s\S]{0,50}expire)/i,
    description: 'AI agent keys without automatic rotation.',
    recommendation: 'Implement automatic key rotation for AI agents.'
  },

  // Pump.fun Specific Patterns
  {
    id: 'SOL2470',
    name: 'Pump.fun Bonding Curve Manipulation',
    severity: 'critical',
    pattern: /bonding[\s\S]{0,30}curve[\s\S]{0,30}(?![\s\S]{0,50}atomic|[\s\S]{0,50}flash_protection)/i,
    description: 'Bonding curve vulnerable to multi-tx manipulation.',
    recommendation: 'Make bonding curve updates atomic with flash protection.'
  },
  {
    id: 'SOL2471',
    name: 'Pump.fun Insider Trading Detection',
    severity: 'high',
    pattern: /launch[\s\S]{0,30}(?![\s\S]{0,50}fair_launch|[\s\S]{0,50}delay)/i,
    description: 'Token launch without fair launch mechanics.',
    recommendation: 'Implement fair launch with initial delay.'
  },

  // Infrastructure Security (2025 Focus)
  {
    id: 'SOL2472',
    name: 'RPC Provider Validation',
    severity: 'high',
    pattern: /rpc[\s\S]{0,30}(url|endpoint)(?![\s\S]{0,50}verify|[\s\S]{0,50}https)/i,
    description: 'RPC endpoints without TLS verification.',
    recommendation: 'Use HTTPS and verify RPC provider certificates.'
  },
  {
    id: 'SOL2473',
    name: 'WebSocket Connection Security',
    severity: 'medium',
    pattern: /websocket|wss(?![\s\S]{0,50}reconnect|[\s\S]{0,50}heartbeat)/i,
    description: 'WebSocket connections without heartbeat monitoring.',
    recommendation: 'Implement heartbeat and automatic reconnection.'
  },

  // Economic Attack Vectors
  {
    id: 'SOL2474',
    name: 'First Depositor Share Inflation',
    severity: 'critical',
    pattern: /vault[\s\S]{0,30}share(?![\s\S]{0,50}minimum_deposit|[\s\S]{0,50}dead_shares)/i,
    description: 'Vault vulnerable to first depositor share inflation.',
    recommendation: 'Require minimum deposit or mint dead shares to zero address.'
  },
  {
    id: 'SOL2475',
    name: 'Fee-on-Transfer Token Handling',
    severity: 'high',
    pattern: /transfer[\s\S]{0,30}amount(?![\s\S]{0,50}actual_received|[\s\S]{0,50}fee_adjusted)/i,
    description: 'Transfer operations not accounting for fee-on-transfer tokens.',
    recommendation: 'Check actual received amount, not requested amount.'
  },
  {
    id: 'SOL2476',
    name: 'Rebasing Token Accounting',
    severity: 'high',
    pattern: /balance[\s\S]{0,30}stored(?![\s\S]{0,50}shares|[\s\S]{0,50}elastic)/i,
    description: 'Rebasing token tracked by absolute balance instead of shares.',
    recommendation: 'Use share-based accounting for rebasing tokens.'
  },

  // Audit-Derived Patterns (2025)
  {
    id: 'SOL2477',
    name: 'OtterSec: Anchor Zero-Copy Safety',
    severity: 'high',
    pattern: /#\[account\(zero_copy\)\](?![\s\S]{0,100}repr\(C\))/i,
    description: 'Zero-copy account without repr(C) (OtterSec finding).',
    recommendation: 'Add #[repr(C)] to zero-copy account structs.'
  },
  {
    id: 'SOL2478',
    name: 'Neodyme: Account Discriminator Collision',
    severity: 'critical',
    pattern: /discriminator[\s\S]{0,30}=[\s\S]{0,30}\[(?![\s\S]{0,50}unique)/i,
    description: 'Manual discriminator may collide with other accounts.',
    recommendation: 'Use unique discriminators or Anchor auto-discrimination.'
  },
  {
    id: 'SOL2479',
    name: 'Kudelski: Instruction Introspection',
    severity: 'medium',
    pattern: /sysvar::instructions(?![\s\S]{0,50}verify_program)/i,
    description: 'Instruction introspection without program verification.',
    recommendation: 'Verify instruction program IDs when introspecting.'
  },
  {
    id: 'SOL2480',
    name: 'Halborn: Serum DEX Integration',
    severity: 'high',
    pattern: /serum|openbook[\s\S]{0,30}(?![\s\S]{0,50}market_authority)/i,
    description: 'DEX integration without market authority validation.',
    recommendation: 'Verify market authority for DEX operations.'
  },

  // Latest 2025 Exploit Techniques
  {
    id: 'SOL2481',
    name: 'DEXX Private Key Leak Pattern',
    severity: 'critical',
    pattern: /export|dump[\s\S]{0,30}(key|secret)(?![\s\S]{0,50}encrypted)/i,
    description: 'Key export without encryption (DEXX $30M pattern).',
    recommendation: 'Never export keys unencrypted.',
    exploit: 'DEXX 2024 - $30M'
  },
  {
    id: 'SOL2482',
    name: 'DEXX Custodial Wallet Risk',
    severity: 'critical',
    pattern: /custodial|managed[\s\S]{0,30}wallet(?![\s\S]{0,50}insurance|[\s\S]{0,50}audit)/i,
    description: 'Custodial wallet without insurance or audit.',
    recommendation: 'Require insurance and regular audits for custodial wallets.'
  },

  // Resilience Patterns
  {
    id: 'SOL2483',
    name: 'Circuit Breaker Missing',
    severity: 'high',
    pattern: /protocol[\s\S]{0,30}(?![\s\S]{0,50}circuit_breaker|[\s\S]{0,50}pause)/i,
    description: 'Protocol without emergency circuit breaker.',
    recommendation: 'Implement circuit breaker for emergency pausing.'
  },
  {
    id: 'SOL2484',
    name: 'Graceful Degradation',
    severity: 'medium',
    pattern: /oracle[\s\S]{0,30}fail(?![\s\S]{0,50}fallback|[\s\S]{0,50}default)/i,
    description: 'No fallback behavior when oracles fail.',
    recommendation: 'Implement graceful degradation for oracle failures.'
  },

  // Testing & Verification Patterns
  {
    id: 'SOL2485',
    name: 'Fuzzing Coverage Gap',
    severity: 'low',
    pattern: /#\[test\](?![\s\S]{0,200}proptest|[\s\S]{0,200}quickcheck|[\s\S]{0,200}arbitrary)/i,
    description: 'Tests without property-based testing or fuzzing.',
    recommendation: 'Add property-based tests with proptest or quickcheck.'
  },
  {
    id: 'SOL2486',
    name: 'Invariant Testing Missing',
    severity: 'medium',
    pattern: /#\[test\][\s\S]{0,500}(?!invariant|assert_eq![\s\S]{0,30}total)/i,
    description: 'Tests without invariant assertions.',
    recommendation: 'Add invariant checks to test suite.'
  },

  // Documentation Security
  {
    id: 'SOL2487',
    name: 'Security Contact Missing',
    severity: 'info',
    pattern: /README|SECURITY(?![\s\S]{0,500}security@|[\s\S]{0,500}bug.bounty)/i,
    description: 'No security contact or bug bounty information.',
    recommendation: 'Add SECURITY.md with contact and bounty info.'
  },

  // Monitoring & Alerting
  {
    id: 'SOL2488',
    name: 'Event Logging Insufficient',
    severity: 'low',
    pattern: /pub fn (?![\s\S]{0,200}emit!|[\s\S]{0,200}msg!|[\s\S]{0,200}log)/i,
    description: 'Public functions without event logging.',
    recommendation: 'Emit events for all state-changing operations.'
  },
  {
    id: 'SOL2489',
    name: 'On-Chain Monitoring Hook',
    severity: 'info',
    pattern: /critical[\s\S]{0,30}(?![\s\S]{0,50}alert|[\s\S]{0,50}monitor)/i,
    description: 'Critical operations without monitoring hooks.',
    recommendation: 'Add monitoring hooks for critical operations.'
  },

  // Deployment Security
  {
    id: 'SOL2490',
    name: 'Deployment Script Security',
    severity: 'high',
    pattern: /deploy[\s\S]{0,30}(script|sh)(?![\s\S]{0,50}verify|[\s\S]{0,50}check)/i,
    description: 'Deployment scripts without verification steps.',
    recommendation: 'Add verification and rollback to deployment scripts.'
  }
];

export function checkBatch59Patterns(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  const fileName = input.path || input.rust?.filePath || 'unknown';
  
  if (!content) return findings;
  
  const lines = content.split('\n');
  
  for (const pattern of BATCH_59_PATTERNS) {
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
          description: pattern.description + (pattern.exploit ? ` [Exploit: ${pattern.exploit}]` : ''),
          location: { file: fileName, line: lineNum },
          recommendation: pattern.recommendation,
          code: snippet.substring(0, 200)
        });
      }
    } catch (error) {
      // Skip pattern if regex fails
    }
  }
  
  return findings;
}

export const BATCH_59_COUNT = BATCH_59_PATTERNS.length;
