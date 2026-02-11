/**
 * SolShield Security Patterns - Batch 21
 * SOL657-SOL676: Latest 2025 Exploits from Helius Research
 * 
 * Based on: https://www.helius.dev/blog/solana-hacks
 * "Solana Hacks, Bugs, and Exploits: A Complete History"
 */

import type { PatternInput } from './index.js';
import type { Finding } from '../commands/audit.js';

/**
 * SOL657: NoOnes P2P Platform Exploit
 * Loss: $4 million (Jan 2025)
 * Root cause: Unvalidated withdrawal requests from compromised hot wallet
 */
export function checkNoOnesPlatformExploit(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';

  // Check for hot wallet withdrawal patterns without proper validation
  const hotWalletPatterns = [
    { pattern: /hot_wallet|hot\.wallet|withdrawal_wallet/i, issue: 'Hot wallet reference without multi-sig validation' },
    { pattern: /process_withdrawal[^}]*signer[^}]*\{[^}]*\}/i, issue: 'Withdrawal processing without rate limiting' },
    { pattern: /transfer_from_treasury[^}]*\{[^}]*authority\s*:\s*ctx\.accounts\./i, issue: 'Treasury transfer with single authority' },
  ];

  for (const { pattern, issue } of hotWalletPatterns) {
    if (pattern.test(rustCode)) {
      findings.push({
        id: 'SOL657',
        severity: 'critical',
        title: 'NoOnes-style Hot Wallet Vulnerability',
        description: `${issue}. The NoOnes P2P platform lost $4M in January 2025 when attackers exploited unvalidated withdrawal requests from a compromised hot wallet.`,
        location: 'Program Logic',
        recommendation: 'Implement multi-signature requirements for large withdrawals, rate limiting, and daily withdrawal caps. Use cold wallets for majority of funds.',
      });
    }
  }

  return findings;
}

/**
 * SOL658: DEXX Hot Wallet Private Key Exposure
 * Loss: $30 million (Nov 2024)
 * Root cause: Private keys stored server-side, leaked via compromised infrastructure
 */
export function checkDexxHotWalletExposure(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';

  // Check for patterns suggesting key material handling
  const keyExposurePatterns = [
    /secret_key|private_key|priv_key/i,
    /keypair\.secret/i,
    /from_bytes\([^)]*secret/i,
    /std::env::var\([^)]*KEY/i,
  ];

  for (const pattern of keyExposurePatterns) {
    if (pattern.test(rustCode)) {
      findings.push({
        id: 'SOL658',
        severity: 'critical',
        title: 'DEXX-style Key Material Exposure Risk',
        description: 'Code pattern suggests private key handling. DEXX lost $30M in November 2024 when private keys stored server-side were leaked via compromised infrastructure, enabling theft from over 900 victims.',
        location: 'Key Management',
        recommendation: 'Never store private keys server-side. Use hardware security modules (HSM), secure enclaves, or multi-party computation (MPC). Implement key rotation and custody protocols.',
      });
      break;
    }
  }

  return findings;
}

/**
 * SOL659: Banana Gun Trading Bot Compromise
 * Loss: $1.4 million (Sep 2024)
 * Root cause: Vulnerability in Telegram bot allowing unauthorized fund transfers
 */
export function checkBananaGunBotVulnerability(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';

  // Check for bot/automation patterns that could be exploited
  const botPatterns = [
    { pattern: /bot_auth|bot_key|telegram_token/i, issue: 'Bot authentication token pattern detected' },
    { pattern: /auto_transfer|automated_withdraw/i, issue: 'Automated transfer without human approval' },
    { pattern: /execute_trade[^}]*\{[^}]*!.*require.*signer/i, issue: 'Trade execution without signer verification' },
  ];

  for (const { pattern, issue } of botPatterns) {
    if (pattern.test(rustCode)) {
      findings.push({
        id: 'SOL659',
        severity: 'high',
        title: 'Trading Bot Security Vulnerability',
        description: `${issue}. Banana Gun lost $1.4M in September 2024 when attackers exploited a vulnerability in their Telegram bot that allowed unauthorized fund transfers. They were able to refund users due to quick response.`,
        location: 'Bot Integration',
        recommendation: 'Implement withdrawal delays, multi-factor confirmation for large amounts, transaction limits, and out-of-band verification for automated systems.',
      });
    }
  }

  return findings;
}

/**
 * SOL660: Pump.fun Insider Employee Exploit
 * Loss: $1.9 million (May 2024)
 * Root cause: Former employee used privileged access to compromise bonding curve contracts
 */
export function checkPumpFunInsiderThreat(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';

  // Check for privileged access patterns that could enable insider attacks
  const insiderPatterns = [
    { pattern: /admin_key|super_admin|privileged_signer/i, issue: 'Super-admin key pattern without multi-sig' },
    { pattern: /bonding_curve[^}]*authority[^}]*single/i, issue: 'Bonding curve with single authority' },
    { pattern: /upgrade_authority|program_authority/i, issue: 'Program upgrade authority without timelock' },
    { pattern: /flash_loan[^}]*withdraw[^}]*\{[^}]*!/i, issue: 'Flash loan withdrawal without proper guards' },
  ];

  for (const { pattern, issue } of insiderPatterns) {
    if (pattern.test(rustCode)) {
      findings.push({
        id: 'SOL660',
        severity: 'critical',
        title: 'Pump.fun-style Insider Threat Vector',
        description: `${issue}. Pump.fun lost $1.9M in May 2024 when a former employee used privileged access to exploit bonding curve contracts via flash loans. The team was able to reimburse users.`,
        location: 'Access Control',
        recommendation: 'Implement separation of duties, multi-signature requirements for privileged operations, timelocks on sensitive actions, and immediate revocation of access upon employee departure.',
      });
    }
  }

  return findings;
}

/**
 * SOL661: Thunder Terminal MongoDB Injection
 * Loss: $240,000 (Dec 2023)
 * Root cause: MongoDB injection via third-party integration exposed session tokens
 */
export function checkThunderTerminalInjection(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';

  // Check for patterns suggesting external database/API integration
  const injectionPatterns = [
    { pattern: /mongodb|mongo_client|external_db/i, issue: 'External database integration without sanitization' },
    { pattern: /session_token|auth_token|bearer_token/i, issue: 'Session token handling pattern' },
    { pattern: /third_party|external_api|integration/i, issue: 'Third-party integration without validation' },
  ];

  for (const { pattern, issue } of injectionPatterns) {
    if (pattern.test(rustCode)) {
      findings.push({
        id: 'SOL661',
        severity: 'high',
        title: 'Thunder Terminal-style Injection Risk',
        description: `${issue}. Thunder Terminal lost $240K in December 2023 when attackers exploited a MongoDB vulnerability via third-party integrations, extracting session tokens. The team detected and halted the attack within 9 minutes.`,
        location: 'External Integration',
        recommendation: 'Sanitize all external inputs, use parameterized queries, implement proper authentication for third-party services, and maintain real-time monitoring.',
      });
    }
  }

  return findings;
}

/**
 * SOL662: Solareum Bot Payment Exploit
 * Loss: $500,000+ (May 2024)
 * Root cause: Vulnerability in bot payment processing enabled unauthorized withdrawals
 */
export function checkSolareumBotExploit(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';

  // Check for payment bot patterns
  const paymentBotPatterns = [
    /payment_bot|pay_processor|automated_payment/i,
    /process_payment[^}]*\{[^}]*unchecked/i,
    /bot_withdraw|auto_pay/i,
  ];

  for (const pattern of paymentBotPatterns) {
    if (pattern.test(rustCode)) {
      findings.push({
        id: 'SOL662',
        severity: 'high',
        title: 'Solareum-style Bot Payment Vulnerability',
        description: 'Automated payment processing pattern detected. Solareum lost over $500K in May 2024 when attackers exploited vulnerabilities in their Telegram bot payment processing. The project collapsed and could not reimburse users.',
        location: 'Payment Processing',
        recommendation: 'Implement strict validation on all payment requests, require human approval for amounts above threshold, use transaction signing with hardware wallets.',
      });
      break;
    }
  }

  return findings;
}

/**
 * SOL663: Cypher Protocol Insider Theft
 * Loss: $1.04M initially, $317K by Hoak in 2024
 * Root cause: Compromised admin access and later insider theft by a core contributor
 */
export function checkCypherInsiderTheft(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';

  // Check for patterns enabling insider theft
  const insiderTheftPatterns = [
    { pattern: /admin_withdraw|emergency_withdraw[^}]*admin/i, issue: 'Admin emergency withdrawal without multi-sig' },
    { pattern: /treasury_access|fund_recovery/i, issue: 'Treasury access pattern without timelock' },
    { pattern: /core_team|contributor_key/i, issue: 'Core team key access pattern' },
  ];

  for (const { pattern, issue } of insiderTheftPatterns) {
    if (pattern.test(rustCode)) {
      findings.push({
        id: 'SOL663',
        severity: 'critical',
        title: 'Cypher-style Insider Theft Vector',
        description: `${issue}. Cypher Protocol suffered $1.04M initial exploit, then a core contributor (Hoak) stole an additional $317K in 2024. Partial reimbursement ongoing.`,
        location: 'Treasury Management',
        recommendation: 'Implement strict multi-signature requirements with threshold >50%, independent custody providers, time-delayed withdrawals, and transparent on-chain governance.',
      });
    }
  }

  return findings;
}

/**
 * SOL664: io.net Bot Fake GPU Attack
 * Loss: Service disruption + reputation damage
 * Root cause: Sybil attack using fake GPUs to farm rewards
 */
export function checkIoNetSybilAttack(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';

  // Check for patterns vulnerable to sybil attacks
  const sybilPatterns = [
    { pattern: /node_registration|provider_register/i, issue: 'Node registration without proof-of-work/stake' },
    { pattern: /reward_claim|claim_rewards[^}]*\{[^}]*!.*verify/i, issue: 'Reward claiming without verification' },
    { pattern: /gpu_proof|resource_proof/i, issue: 'Resource proof pattern may be spoofable' },
  ];

  for (const { pattern, issue } of sybilPatterns) {
    if (pattern.test(rustCode)) {
      findings.push({
        id: 'SOL664',
        severity: 'medium',
        title: 'io.net-style Sybil Attack Vector',
        description: `${issue}. io.net suffered a Sybil attack in April 2024 where attackers registered fake GPUs to farm rewards, causing service disruption.`,
        location: 'Registration System',
        recommendation: 'Implement robust proof-of-resources, stake requirements for providers, reputation systems, and anomaly detection for suspicious registration patterns.',
      });
    }
  }

  return findings;
}

/**
 * SOL665: SVT Token Honeypot Detection
 * Loss: Unknown (prevented by CertiK alert)
 * Root cause: Hidden tax/fee mechanism with admin-controlled selling restriction
 */
export function checkSvtTokenHoneypot(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';

  // Check for honeypot patterns
  const honeypotPatterns = [
    { pattern: /hidden_fee|secret_tax|admin_tax/i, issue: 'Hidden fee mechanism detected' },
    { pattern: /sell_restriction|trading_enabled.*admin/i, issue: 'Admin-controlled trading restriction' },
    { pattern: /blacklist.*seller|whitelist.*buyer/i, issue: 'Asymmetric buy/sell restrictions' },
  ];

  for (const { pattern, issue } of honeypotPatterns) {
    if (pattern.test(rustCode)) {
      findings.push({
        id: 'SOL665',
        severity: 'critical',
        title: 'SVT Token-style Honeypot Pattern',
        description: `${issue}. CertiK detected SVT token honeypot in June 2024 - it had hidden tax mechanisms and admin-controlled selling restrictions to trap buyers.`,
        location: 'Token Logic',
        recommendation: 'Audit all token contracts for symmetric buy/sell logic, transparent fee structures, and absence of admin-only sell restrictions.',
      });
    }
  }

  return findings;
}

/**
 * SOL666: Saga DAO Governance Attack
 * Loss: $230K (Oct 2023)
 * Root cause: Malicious governance proposal went unnoticed, draining treasury
 */
export function checkSagaDaoGovernanceAttack(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';

  // Check for governance attack patterns
  const governancePatterns = [
    { pattern: /proposal[^}]*execute[^}]*\{[^}]*!.*timelock/i, issue: 'Proposal execution without timelock' },
    { pattern: /governance[^}]*quorum[^}]*low|min_quorum\s*=\s*[0-5]/i, issue: 'Low quorum threshold for governance' },
    { pattern: /treasury_withdraw[^}]*proposal/i, issue: 'Treasury withdrawal via proposal without delay' },
  ];

  for (const { pattern, issue } of governancePatterns) {
    if (pattern.test(rustCode)) {
      findings.push({
        id: 'SOL666',
        severity: 'critical',
        title: 'Saga DAO-style Governance Attack',
        description: `${issue}. Saga DAO lost $230K in October 2023 when a malicious proposal to drain the treasury went unnoticed and was executed.`,
        location: 'Governance',
        recommendation: 'Implement minimum timelock periods (48-72h), guardian veto capabilities, proposal notification systems, and quorum requirements that scale with treasury value.',
      });
    }
  }

  return findings;
}

/**
 * SOL667: Aurory SyncSpace Gaming Exploit
 * Loss: Undisclosed NFT/token theft
 * Root cause: Vulnerability in gaming reward distribution
 */
export function checkAurorySyncSpaceExploit(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';

  // Check for gaming reward patterns
  const gamingPatterns = [
    { pattern: /game_reward|play_to_earn|reward_distribution/i, issue: 'Gaming reward distribution pattern' },
    { pattern: /nft_claim[^}]*\{[^}]*!.*verify_gameplay/i, issue: 'NFT claim without gameplay verification' },
    { pattern: /sync_space|game_state.*external/i, issue: 'External game state dependency' },
  ];

  for (const { pattern, issue } of gamingPatterns) {
    if (pattern.test(rustCode)) {
      findings.push({
        id: 'SOL667',
        severity: 'medium',
        title: 'Aurory-style Gaming Exploit Vector',
        description: `${issue}. Aurory\'s SyncSpace was exploited in 2024 via vulnerabilities in gaming reward distribution, though specific losses were not disclosed.`,
        location: 'Gaming Logic',
        recommendation: 'Implement server-side gameplay verification, rate limiting on reward claims, anti-bot measures, and audit reward distribution logic.',
      });
    }
  }

  return findings;
}

/**
 * SOL668: Tulip Protocol Crank Bot Manipulation
 * Loss: Minimal (quickly patched)
 * Root cause: Crank bot manipulation to extract value from vault operations
 */
export function checkTulipCrankManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';

  // Check for crank/keeper patterns
  const crankPatterns = [
    { pattern: /crank|keeper|permissionless_trigger/i, issue: 'Permissionless crank pattern detected' },
    { pattern: /vault_harvest|compound_rewards/i, issue: 'Vault operation without MEV protection' },
    { pattern: /update_price[^}]*anyone/i, issue: 'Permissionless price update' },
  ];

  for (const { pattern, issue } of crankPatterns) {
    if (pattern.test(rustCode)) {
      findings.push({
        id: 'SOL668',
        severity: 'medium',
        title: 'Tulip-style Crank Manipulation Risk',
        description: `${issue}. Tulip Protocol had a crank bot manipulation vulnerability that was quickly patched. Attackers can extract value by front-running permissionless operations.`,
        location: 'Keeper System',
        recommendation: 'Implement commit-reveal schemes, MEV protection, or restrict crank operations to authorized keepers with slashing conditions.',
      });
    }
  }

  return findings;
}

/**
 * SOL669: UXD Protocol Stability Mechanism Flaw
 * Loss: Peg instability
 * Root cause: Delta-neutral stability mechanism vulnerable to extreme market conditions
 */
export function checkUxdStabilityFlaw(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';

  // Check for stability mechanism patterns
  const stabilityPatterns = [
    { pattern: /delta_neutral|hedge_position/i, issue: 'Delta-neutral position without circuit breakers' },
    { pattern: /stablecoin_mint[^}]*collateral/i, issue: 'Stablecoin minting tied to volatile collateral' },
    { pattern: /peg_stability|rebalance/i, issue: 'Peg stability mechanism pattern' },
  ];

  for (const { pattern, issue } of stabilityPatterns) {
    if (pattern.test(rustCode)) {
      findings.push({
        id: 'SOL669',
        severity: 'high',
        title: 'UXD-style Stability Mechanism Risk',
        description: `${issue}. UXD Protocol experienced peg instability due to flaws in their delta-neutral stability mechanism during extreme market conditions.`,
        location: 'Stability Mechanism',
        recommendation: 'Implement circuit breakers for extreme volatility, diversified collateral strategies, emergency pause mechanisms, and stress testing under extreme scenarios.',
      });
    }
  }

  return findings;
}

/**
 * SOL670: OptiFi Program Close Lockup
 * Loss: $661,000 locked forever
 * Root cause: Team accidentally called close() on mainnet, locking all user funds permanently
 */
export function checkOptiFiCloseVulnerability(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';

  // Check for dangerous program close patterns
  const closePatterns = [
    { pattern: /close\s*\(\s*ctx\s*\)|program\.close/i, issue: 'Program close function without safeguards' },
    { pattern: /close_program[^}]*\{[^}]*!.*require.*empty/i, issue: 'Close without checking for remaining funds' },
    { pattern: /#\[account\([^)]*close/i, issue: 'Account close constraint without balance check' },
  ];

  for (const { pattern, issue } of closePatterns) {
    if (pattern.test(rustCode)) {
      findings.push({
        id: 'SOL670',
        severity: 'critical',
        title: 'OptiFi-style Program Close Vulnerability',
        description: `${issue}. OptiFi accidentally called close() on mainnet in August 2022, permanently locking $661K in user funds. The program close was irreversible.`,
        location: 'Program Lifecycle',
        recommendation: 'Implement multi-sig requirements for program close, require zero balance before close, add timelock delays, and use devnet/testnet for testing destructive operations.',
      });
    }
  }

  return findings;
}

/**
 * SOL671: Web3.js Supply Chain Attack
 * Loss: ~$164,000 from compromised wallets
 * Root cause: Malicious versions 1.95.6/1.95.7 published via compromised npm account
 */
export function checkWeb3JsSupplyChainAttack(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';

  // Check for patterns suggesting supply chain vulnerability
  const supplyChainPatterns = [
    { pattern: /extern\s+crate|use\s+[a-z_]+::/i, issue: 'External crate dependency' },
    { pattern: /solana_sdk|anchor_lang/i, issue: 'Solana SDK dependency (ensure version pinning)' },
  ];

  for (const { pattern, issue } of supplyChainPatterns) {
    if (pattern.test(rustCode)) {
      findings.push({
        id: 'SOL671',
        severity: 'high',
        title: 'Web3.js Supply Chain Attack Awareness',
        description: `${issue}. In December 2024, @solana/web3.js versions 1.95.6 and 1.95.7 were compromised via a phished npm account, stealing ~$164K from wallets. The malicious packages exfiltrated private keys.`,
        location: 'Dependencies',
        recommendation: 'Pin exact dependency versions, use lockfiles, verify package integrity with checksums, enable npm 2FA, and audit dependencies regularly.',
      });
      break;
    }
  }

  return findings;
}

/**
 * SOL672: Parcl Front-End Phishing Attack
 * Loss: Undisclosed
 * Root cause: Compromised frontend served malicious transaction requests
 */
export function checkParclFrontendAttack(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';

  // This pattern checks for frontend interaction patterns
  const frontendPatterns = [
    /frontend|web_interface|dapp_url/i,
  ];

  for (const pattern of frontendPatterns) {
    if (pattern.test(rustCode)) {
      findings.push({
        id: 'SOL672',
        severity: 'info',
        title: 'Frontend Security Consideration',
        description: 'Program interacts with frontend. Parcl was attacked in December 2024 when their frontend was compromised to serve malicious transaction requests. Frontend security is critical.',
        location: 'Frontend Integration',
        recommendation: 'Implement Content Security Policy, Subresource Integrity, domain monitoring, and consider using IPFS/decentralized hosting for critical frontends.',
      });
      break;
    }
  }

  return findings;
}

/**
 * SOL673: Jito DDoS Attack
 * Loss: Service disruption
 * Root cause: Application-layer DDoS on Jito block engine
 */
export function checkJitoDdosPattern(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';

  // Check for patterns susceptible to DDoS
  const ddosPatterns = [
    { pattern: /public_endpoint|open_api|permissionless/i, issue: 'Public endpoint without rate limiting' },
    { pattern: /mempool|transaction_queue/i, issue: 'Queue system potentially susceptible to flooding' },
  ];

  for (const { pattern, issue } of ddosPatterns) {
    if (pattern.test(rustCode)) {
      findings.push({
        id: 'SOL673',
        severity: 'medium',
        title: 'Jito-style DDoS Vulnerability',
        description: `${issue}. Jito experienced an application-layer DDoS attack in February 2024 that temporarily disrupted their block engine service.`,
        location: 'API/Endpoint',
        recommendation: 'Implement rate limiting, request authentication, DDoS mitigation services, and distributed infrastructure.',
      });
    }
  }

  return findings;
}

/**
 * SOL674: Phantom Wallet DDoS
 * Loss: Service disruption
 * Root cause: Token airdrop spam causing wallet performance degradation
 */
export function checkPhantomDdosPattern(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';

  // Check for airdrop patterns that could be abused
  const airdropPatterns = [
    { pattern: /airdrop|mass_transfer|bulk_mint/i, issue: 'Bulk token operation pattern' },
    { pattern: /associated_token.*create_if_needed/i, issue: 'Auto-creating token accounts (spam vector)' },
  ];

  for (const { pattern, issue } of airdropPatterns) {
    if (pattern.test(rustCode)) {
      findings.push({
        id: 'SOL674',
        severity: 'low',
        title: 'Phantom-style Spam/DDoS Consideration',
        description: `${issue}. Phantom wallet experienced performance issues in 2023 due to token airdrop spam attacks creating unwanted accounts.`,
        location: 'Token Operations',
        recommendation: 'Consider spam implications of permissionless token creation. Wallets should filter spam tokens, and protocols should consider opt-in mechanisms.',
      });
    }
  }

  return findings;
}

/**
 * SOL675: Grape Protocol Network DoS
 * Loss: 17-hour network outage
 * Root cause: Malformed transaction caused consensus issues
 */
export function checkGrapeProtocolDos(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';

  // Check for patterns that could cause consensus issues
  const consensusPatterns = [
    { pattern: /cross_program_invocation.*recursive/i, issue: 'Recursive CPI pattern' },
    { pattern: /compute_units.*max|budget.*unlimited/i, issue: 'Unbounded compute budget' },
  ];

  for (const { pattern, issue } of consensusPatterns) {
    if (pattern.test(rustCode)) {
      findings.push({
        id: 'SOL675',
        severity: 'high',
        title: 'Grape Protocol-style DoS Pattern',
        description: `${issue}. In September 2021, a malformed transaction caused a 17-hour Solana network outage affecting all users.`,
        location: 'Transaction Structure',
        recommendation: 'Ensure transactions stay within compute limits, avoid recursive patterns that could cause validator issues.',
      });
    }
  }

  return findings;
}

/**
 * SOL676: Candy Machine Zero-Account Exploit
 * Loss: Service disruption + failed mints
 * Root cause: Attackers sent transactions with zero accounts causing mint failures
 */
export function checkCandyMachineZeroAccount(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';

  // Check for NFT minting patterns
  const mintingPatterns = [
    { pattern: /candy_machine|nft_mint|mint_nft/i, issue: 'NFT minting logic detected' },
    { pattern: /remaining_accounts\.len\(\)\s*==\s*0/i, issue: 'Zero accounts check pattern' },
  ];

  for (const { pattern, issue } of mintingPatterns) {
    if (pattern.test(rustCode)) {
      findings.push({
        id: 'SOL676',
        severity: 'medium',
        title: 'Candy Machine Zero-Account DoS',
        description: `${issue}. In 2022, attackers sent transactions with zero accounts to Candy Machine programs causing mint failures and service disruption.`,
        location: 'NFT Minting',
        recommendation: 'Validate account count requirements before processing, implement bot protection, and use allow-lists for fair launches.',
      });
    }
  }

  return findings;
}
