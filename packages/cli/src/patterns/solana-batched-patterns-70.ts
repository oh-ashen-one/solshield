/**
 * Batch 70: February 2026 Latest Security Patterns
 * Covers Step Finance hack, Solana phishing attacks, and refined vulnerability detection
 * Patterns: SOL3126-SOL3200
 */

import type { PatternInput, Finding } from './index.js';

function createFinding(
  id: string,
  title: string,
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info',
  description: string,
  location: { file: string; line?: number },
  recommendation?: string
): Finding {
  return { id, title, severity, description, location, recommendation };
}

/**
 * SOL3126: Step Finance Key Compromise Pattern
 * Based on Feb 2026 Step Finance hack - $30M stolen via wallet key exposure
 */
function checkStepFinanceKeyCompromise(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  // Check for centralized wallet authority patterns
  if (content.includes('treasury') || content.includes('vault') || content.includes('pool')) {
    // Single authority with large fund access
    if (content.includes('authority') && !content.includes('multisig') && !content.includes('multi_sig')) {
      if (content.includes('withdraw') || content.includes('transfer_all') || content.includes('drain')) {
        findings.push(createFinding(
          'SOL3126',
          'Single Authority Treasury Access (Step Finance Pattern)',
          'critical',
          'Treasury/vault controlled by single authority without multisig. In Feb 2026, Step Finance lost $30M when hot wallet keys were compromised.',
          { file: input.path },
          'Implement multisig (2-of-3 or higher) for treasury operations. Use hardware wallets for signers.'
        ));
      }
    }
  }
  
  return findings;
}

/**
 * SOL3127: Owner Permission Phishing Vulnerability
 * Based on Jan 2026 Solana phishing attack - $3M+ stolen via owner transfer
 */
function checkOwnerPermissionPhishing(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  // Check for owner/authority transfer without proper safeguards
  if (content.includes('set_authority') || content.includes('transfer_authority') || 
      content.includes('change_owner') || content.includes('update_authority')) {
    
    // Missing two-step transfer pattern
    if (!content.includes('pending_authority') && !content.includes('accept_authority') &&
        !content.includes('two_step') && !content.includes('2_step')) {
      findings.push(createFinding(
        'SOL3127',
        'Instant Authority Transfer (Phishing Vector)',
        'critical',
        'Authority transfer happens instantly without two-step confirmation. Jan 2026 phishing attacks exploited this to steal $3M+ by tricking users into signing owner transfer transactions.',
        { file: input.path },
        'Implement two-step authority transfer: propose -> accept. Add timelock for critical authority changes.'
      ));
    }
    
    // No event emission for authority changes
    if (!content.includes('emit!') && !content.includes('msg!') && !content.includes('log_authority')) {
      findings.push(createFinding(
        'SOL3128',
        'Silent Authority Transfer',
        'high',
        'Authority transfers without logging/events are harder to detect. Attackers prefer silent transfers to avoid detection.',
        { file: input.path },
        'Emit events for all authority changes: emit!(AuthorityChanged { old, new, timestamp })'
      ));
    }
  }
  
  return findings;
}

/**
 * SOL3129: Account Assign Attack Detection
 * Detects vulnerabilities to the Solana assign instruction exploit
 */
function checkAccountAssignAttack(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  // Check for proper owner verification before sensitive operations
  if (content.includes('AccountInfo') || content.includes('UncheckedAccount')) {
    if (content.includes('assign') || content.includes('system_program::assign')) {
      if (!content.includes('constraint = account.owner') && !content.includes('require!(account.owner')) {
        findings.push(createFinding(
          'SOL3129',
          'Assign Instruction Vulnerability',
          'critical',
          'System program assign instruction can change account ownership. Without proper checks, attackers can reassign account ownership via phishing.',
          { file: input.path },
          'Verify account owner before any sensitive operation. Disallow owned accounts from being reassigned without explicit user confirmation.'
        ));
      }
    }
  }
  
  return findings;
}

/**
 * SOL3130: Transaction Simulation Detection Bypass
 * Based on simulation detection bypasses used in recent exploits
 */
function checkSimulationDetectionBypass(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  // Check for anti-simulation patterns that can be bypassed
  if (content.includes('simulation') || content.includes('preflight') || content.includes('simulate')) {
    if (content.includes('skip_preflight') || content.includes('commitment: processed')) {
      findings.push(createFinding(
        'SOL3130',
        'Simulation Detection May Be Bypassed',
        'medium',
        'Anti-simulation checks can be bypassed by attackers using skip_preflight or processed commitment. Dont rely solely on simulation detection.',
        { file: input.path },
        'Use on-chain state verification instead of simulation detection for security-critical checks.'
      ));
    }
  }
  
  return findings;
}

/**
 * SOL3131: Monero/Privacy Coin Laundering Pattern
 * Step Finance attackers converted to Monero - detection patterns
 */
function checkPrivacyCoinLaundering(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  // Check for suspicious cross-chain patterns
  if (content.includes('bridge') || content.includes('cross_chain') || content.includes('wormhole')) {
    if (!content.includes('kyc') && !content.includes('whitelist') && !content.includes('rate_limit')) {
      findings.push(createFinding(
        'SOL3131',
        'Cross-Chain Bridge Without Rate Limiting',
        'medium',
        'Bridge without rate limits or whitelisting can be used for rapid fund extraction and laundering (as seen in Step Finance attack where funds were converted to Monero).',
        { file: input.path },
        'Implement rate limiting, withdrawal delays, and consider whitelisting for large transfers.'
      ));
    }
  }
  
  return findings;
}

/**
 * SOL3132: Hot Wallet Key Rotation Missing
 */
function checkHotWalletKeyRotation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  if (content.includes('hot_wallet') || content.includes('operational_wallet')) {
    if (!content.includes('rotate_key') && !content.includes('key_rotation') && !content.includes('update_signer')) {
      findings.push(createFinding(
        'SOL3132',
        'No Hot Wallet Key Rotation Mechanism',
        'high',
        'Hot wallets should support key rotation. If keys are compromised, there should be a way to rotate them immediately.',
        { file: input.path },
        'Implement key rotation: allow updating hot wallet authority with proper authorization.'
      ));
    }
  }
  
  return findings;
}

/**
 * SOL3133: Withdrawal Delay Bypass
 */
function checkWithdrawalDelayBypass(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  if (content.includes('withdraw') && content.includes('delay')) {
    // Check if delay can be bypassed via authority
    if (content.includes('skip_delay') || content.includes('emergency_withdraw') || content.includes('admin_override')) {
      if (!content.includes('multisig') && !content.includes('timelock_admin')) {
        findings.push(createFinding(
          'SOL3133',
          'Withdrawal Delay Bypass Without Multisig',
          'critical',
          'Emergency/admin withdrawal bypass without multisig protection. Single compromised key can drain funds instantly.',
          { file: input.path },
          'Require multisig approval for any delay bypass. Consider hardware wallet requirements for emergency actions.'
        ));
      }
    }
  }
  
  return findings;
}

/**
 * SOL3134: Instruction Introspection for Phishing Detection
 */
function checkInstructionIntrospection(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  // Check if sensitive operations verify instruction context
  if (content.includes('set_authority') || content.includes('transfer_all') || content.includes('close_account')) {
    if (!content.includes('sysvar::instructions') && !content.includes('load_instruction_at') && 
        !content.includes('get_instruction_relative')) {
      findings.push(createFinding(
        'SOL3134',
        'No Instruction Introspection for Context Verification',
        'medium',
        'Sensitive operations should verify they are not bundled with malicious instructions (phishing attack vector).',
        { file: input.path },
        'Use instruction introspection to verify transaction context for critical operations.'
      ));
    }
  }
  
  return findings;
}

/**
 * SOL3135: Wallet Drainer Pattern Detection
 */
function checkWalletDrainerPattern(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  // Detect patterns commonly used in wallet drainer scripts
  const drainerPatterns = [
    'remaining_accounts',
    'batch_transfer',
    'sweep_all',
    'collect_all_tokens',
    'drain_wallet'
  ];
  
  for (const pattern of drainerPatterns) {
    if (content.includes(pattern)) {
      if (!content.includes('require!(signer') && !content.includes('Signer<')) {
        findings.push(createFinding(
          'SOL3135',
          'Potential Wallet Drainer Pattern',
          'critical',
          `Pattern "${pattern}" detected without signer verification. Could be exploited in phishing attacks to drain wallets.`,
          { file: input.path },
          'Ensure all bulk/sweep operations require explicit signer verification and consider user intent confirmation.'
        ));
      }
    }
  }
  
  return findings;
}

/**
 * SOL3136: Delegate Authority Abuse
 */
function checkDelegateAuthorityAbuse(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  // Check for token delegate abuse patterns
  if (content.includes('approve') || content.includes('delegate') || content.includes('delegated_amount')) {
    // Unlimited approval patterns
    if (content.includes('u64::MAX') || content.includes('u128::MAX') || content.includes('unlimited')) {
      findings.push(createFinding(
        'SOL3136',
        'Unlimited Token Delegation',
        'high',
        'Unlimited token approvals create persistent attack surface. If delegate is compromised, all tokens are at risk.',
        { file: input.path },
        'Use minimal necessary approval amounts. Implement approval expiry and revocation mechanisms.'
      ));
    }
    
    // No revocation check
    if (!content.includes('revoke') && !content.includes('set_delegate_amount(0)')) {
      findings.push(createFinding(
        'SOL3137',
        'No Delegation Revocation Mechanism',
        'medium',
        'Token delegation without easy revocation. Users should be able to revoke approvals.',
        { file: input.path },
        'Provide clear revocation mechanism: allow setting delegate to None or amount to 0.'
      ));
    }
  }
  
  return findings;
}

/**
 * SOL3138: Trusted Frontend Assumption
 */
function checkTrustedFrontendAssumption(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  // Check for patterns that assume frontend will provide correct data
  if (content.includes('/// Frontend') || content.includes('// client') || content.includes('ui_amount')) {
    if (!content.includes('validate') && !content.includes('verify') && !content.includes('check')) {
      findings.push(createFinding(
        'SOL3138',
        'Trusting Frontend-Provided Data',
        'high',
        'Program appears to trust frontend-provided values. All input must be validated on-chain regardless of source.',
        { file: input.path },
        'Never trust client/frontend input. Validate all parameters in the program regardless of expected source.'
      ));
    }
  }
  
  return findings;
}

/**
 * SOL3139: Memory-Safe but Logic-Unsafe Pattern
 * Rust memory safety doesn't prevent business logic flaws
 */
function checkMemorySafeLogicUnsafe(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  // Complex math without business logic validation
  if (content.includes('checked_') && (content.includes('price') || content.includes('rate') || content.includes('collateral'))) {
    if (!content.includes('sanity_check') && !content.includes('bounds_check') && !content.includes('validate_range')) {
      findings.push(createFinding(
        'SOL3139',
        'Arithmetic Safety Without Business Logic Validation',
        'medium',
        'Using checked arithmetic is good, but business logic sanity checks are also needed (e.g., price within expected range, collateral ratio reasonable).',
        { file: input.path },
        'Add business logic validation: sanity check prices, rates, amounts against expected ranges.'
      ));
    }
  }
  
  return findings;
}

/**
 * SOL3140: Oracle Manipulation via Self-Trading
 */
function checkOracleSelfTrading(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  // Check for single-source oracle dependency
  if (content.includes('oracle') || content.includes('price_feed') || content.includes('get_price')) {
    if (content.includes('pool_price') || content.includes('amm_price') || content.includes('swap_price')) {
      if (!content.includes('twap') && !content.includes('multiple_sources') && !content.includes('median_price')) {
        findings.push(createFinding(
          'SOL3140',
          'Single AMM Pool as Oracle (Self-Trading Vulnerability)',
          'critical',
          'Using single AMM pool price as oracle. Attacker can self-trade to manipulate price, borrow against inflated collateral (Mango Markets attack pattern).',
          { file: input.path },
          'Use TWAP, multiple oracle sources, or Pyth/Chainlink. Never rely on single pool spot price.'
        ));
      }
    }
  }
  
  return findings;
}

/**
 * SOL3141: Concentrated Liquidity Tick Manipulation
 */
function checkCLMMTickManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  // CLMM/concentrated liquidity patterns
  if (content.includes('tick') && (content.includes('liquidity') || content.includes('position'))) {
    // Tick account validation
    if (!content.includes('tick_account.owner') && !content.includes('validate_tick')) {
      findings.push(createFinding(
        'SOL3141',
        'CLMM Tick Account Without Owner Validation',
        'critical',
        'Concentrated liquidity tick accounts must verify ownership. Crema Finance lost $8.8M when attackers created fake tick accounts.',
        { file: input.path },
        'Verify tick account ownership: require!(tick_account.owner == program_id). Validate tick data integrity.'
      ));
    }
    
    // Flash loan + tick manipulation
    if (content.includes('flash') && !content.includes('lock_tick') && !content.includes('tick_lock')) {
      findings.push(createFinding(
        'SOL3142',
        'CLMM Tick Manipulation via Flash Loan',
        'high',
        'Flash loans can be used to temporarily manipulate tick positions. Consider tick locking during sensitive operations.',
        { file: input.path },
        'Lock tick state during flash loan operations. Verify tick state consistency before and after.'
      ));
    }
  }
  
  return findings;
}

/**
 * SOL3143: Bonding Curve Flash Loan Exploitation
 */
function checkBondingCurveFlashExploit(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  if (content.includes('bonding_curve') || content.includes('bonding') && content.includes('curve')) {
    // Flash loan vulnerability
    if (content.includes('mint') || content.includes('buy')) {
      if (!content.includes('flash_guard') && !content.includes('same_slot_check') && !content.includes('cooldown')) {
        findings.push(createFinding(
          'SOL3143',
          'Bonding Curve Flash Loan Vulnerability',
          'critical',
          'Bonding curves can be exploited via flash loans (Nirvana Finance attack - $3.5M). Attacker flash loans, pumps curve, mints at inflated rate.',
          { file: input.path },
          'Implement flash loan protection: same-slot restrictions, price impact limits, or cooldown periods.'
        ));
      }
    }
    
    // Price impact limits
    if (!content.includes('max_price_impact') && !content.includes('slippage_limit') && !content.includes('price_limit')) {
      findings.push(createFinding(
        'SOL3144',
        'No Price Impact Limits on Bonding Curve',
        'high',
        'Bonding curve without price impact limits. Large trades can dramatically move price.',
        { file: input.path },
        'Implement price impact limits: max_price_impact_bps, per-trade and per-block limits.'
      ));
    }
  }
  
  return findings;
}

/**
 * SOL3145: Governance Proposal Timing Attack
 */
function checkGovernanceTimingAttack(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  if (content.includes('governance') || content.includes('proposal') || content.includes('vote')) {
    // Check for voting period safeguards
    if (content.includes('execute') || content.includes('finalize')) {
      if (!content.includes('min_voting_period') && !content.includes('quorum_check')) {
        findings.push(createFinding(
          'SOL3145',
          'Governance Proposal Without Minimum Voting Period',
          'critical',
          'Proposals can be executed too quickly, not giving token holders time to react (Synthetify DAO attack pattern).',
          { file: input.path },
          'Enforce minimum voting period (e.g., 3-7 days) and quorum requirements.'
        ));
      }
    }
    
    // Notification system
    if (!content.includes('emit!') && !content.includes('notify') && !content.includes('proposal_created_event')) {
      findings.push(createFinding(
        'SOL3146',
        'Silent Governance Proposals',
        'high',
        'Proposals without event emission are harder to monitor. Malicious proposals can slip through unnoticed.',
        { file: input.path },
        'Emit events for all proposal lifecycle: ProposalCreated, VoteCast, ProposalExecuted.'
      ));
    }
  }
  
  return findings;
}

/**
 * SOL3147: RateX PT Token Pricing Vulnerability
 * Based on Loopscale exploit (April 2025) - $5.8M
 */
function checkRateXPTVulnerability(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  // Check for principal token / yield token pricing
  if (content.includes('pt_token') || content.includes('principal_token') || content.includes('yield_token')) {
    if (content.includes('collateral') || content.includes('borrow') || content.includes('lending')) {
      // Check for proper pricing mechanism
      if (!content.includes('oracle_price') && !content.includes('market_price') && !content.includes('fair_value')) {
        findings.push(createFinding(
          'SOL3147',
          'Principal Token Without Proper Pricing Oracle',
          'critical',
          'PT tokens used as collateral without proper pricing mechanism. Loopscale lost $5.8M when RateX PT token was mispriced.',
          { file: input.path },
          'Use reliable oracle for PT token pricing. Consider time-to-maturity and underlying value.'
        ));
      }
      
      // Check for under-collateralization protection
      if (!content.includes('ltv_check') && !content.includes('collateral_ratio') && !content.includes('health_factor')) {
        findings.push(createFinding(
          'SOL3148',
          'Missing Collateralization Check for Novel Assets',
          'high',
          'Novel assets (like PT tokens) as collateral need strict LTV monitoring to prevent under-collateralization.',
          { file: input.path },
          'Implement conservative LTV limits for novel collateral types. Add price staleness checks.'
        ));
      }
    }
  }
  
  return findings;
}

/**
 * SOL3149: Trust Wallet Style Vulnerability
 */
function checkTrustWalletStyle(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  // Check for wallet-related patterns
  if (content.includes('wallet') || content.includes('sign') || content.includes('signature')) {
    // Weak entropy for key generation
    if (content.includes('random') || content.includes('seed')) {
      if (!content.includes('getrandom') && !content.includes('rand::') && !content.includes('OsRng')) {
        findings.push(createFinding(
          'SOL3149',
          'Potentially Weak Random Number Generation',
          'critical',
          'Wallet key generation must use cryptographically secure randomness. Weak RNG has led to massive wallet compromises.',
          { file: input.path },
          'Use getrandom or rand::OsRng for all cryptographic operations. Never use weak/predictable RNG.'
        ));
      }
    }
    
    // Key derivation without proper hardening
    if (content.includes('derive') && content.includes('key')) {
      if (!content.includes('hardened') && !content.includes("'") && !content.includes('BIP44')) {
        findings.push(createFinding(
          'SOL3150',
          'Non-Hardened Key Derivation',
          'high',
          'Key derivation should use hardened paths to prevent child key compromise from exposing parent keys.',
          { file: input.path },
          'Use hardened derivation paths (m/44h/501h/0h/0h) for wallet key generation.'
        ));
      }
    }
  }
  
  return findings;
}

/**
 * SOL3151: Phantom DDoS Protection Patterns
 */
function checkDDoSProtection(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  // Check for rate limiting patterns
  if (content.includes('rpc') || content.includes('endpoint') || content.includes('request')) {
    if (!content.includes('rate_limit') && !content.includes('throttle') && !content.includes('cooldown')) {
      findings.push(createFinding(
        'SOL3151',
        'No Rate Limiting for RPC/API Endpoints',
        'medium',
        'Endpoints without rate limiting are vulnerable to DDoS attacks (Phantom Feb 2024 attack pattern).',
        { file: input.path },
        'Implement rate limiting per IP/account. Use circuit breakers for service protection.'
      ));
    }
  }
  
  return findings;
}

/**
 * SOL3152: Seed Phrase Exfiltration Pattern (Slope Wallet)
 */
function checkSeedPhraseExfiltration(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  // Check for logging/telemetry patterns near sensitive data
  if (content.includes('mnemonic') || content.includes('seed_phrase') || content.includes('private_key')) {
    if (content.includes('log') || content.includes('trace') || content.includes('debug') || content.includes('telemetry')) {
      findings.push(createFinding(
        'SOL3152',
        'Sensitive Data Near Logging Code',
        'critical',
        'Seed phrases or private keys should never be near logging code. Slope Wallet lost $8M when seed phrases were inadvertently logged.',
        { file: input.path },
        'Never log or transmit seed phrases/private keys. Use secure memory for sensitive data. Audit all telemetry.'
      ));
    }
  }
  
  return findings;
}

/**
 * SOL3153: OptiFi Program Close Pattern
 */
function checkProgramClosePattern(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  // Check for program upgrade/close patterns
  if (content.includes('program close') || content.includes('close_program') || content.includes('solana program close')) {
    findings.push(createFinding(
      'SOL3153',
      'Program Close Command Usage',
      'critical',
      'Program close is IRREVERSIBLE and locks all funds in PDAs. OptiFi lost $661K this way. NEVER use in production scripts.',
      { file: input.path },
      'Never use `solana program close` on mainnet. Use upgrade authority instead. Implement peer review for all deployments.'
    ));
  }
  
  // Check for upgrade authority patterns
  if (content.includes('upgrade_authority') || content.includes('BpfUpgradeableLoader')) {
    if (!content.includes('multi_sig') && !content.includes('multisig')) {
      findings.push(createFinding(
        'SOL3154',
        'Single Upgrade Authority',
        'high',
        'Single upgrade authority creates single point of failure. Compromise leads to malicious program upgrade.',
        { file: input.path },
        'Use multisig for program upgrade authority. Consider Squads or similar for upgrade governance.'
      ));
    }
  }
  
  return findings;
}

/**
 * SOL3155: NoOnes Bridge Vulnerability Pattern
 */
function checkCrossChainBridgeVulnerability(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  if (content.includes('bridge') || content.includes('cross_chain') || content.includes('cross-chain')) {
    // Check for message validation
    if (!content.includes('verify_message') && !content.includes('validate_vaa') && !content.includes('signature_set')) {
      findings.push(createFinding(
        'SOL3155',
        'Cross-Chain Message Without Signature Verification',
        'critical',
        'Bridge messages must be cryptographically verified. NoOnes lost $8M in Jan 2025 due to bridge vulnerability.',
        { file: input.path },
        'Verify all cross-chain messages with guardian/validator signatures. Use established bridge SDKs.'
      ));
    }
    
    // Check for replay protection
    if (!content.includes('nonce') && !content.includes('sequence') && !content.includes('replay_protection')) {
      findings.push(createFinding(
        'SOL3156',
        'Bridge Without Replay Protection',
        'critical',
        'Cross-chain messages can be replayed if no nonce/sequence tracking. Each message should only be processed once.',
        { file: input.path },
        'Implement sequence/nonce tracking for bridge messages. Mark messages as processed after execution.'
      ));
    }
  }
  
  return findings;
}

/**
 * SOL3157: Banana Gun Trading Bot Pattern
 */
function checkTradingBotVulnerability(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  if (content.includes('bot') || content.includes('sniper') || content.includes('auto_trade')) {
    // Check for user fund isolation
    if (content.includes('user_balance') || content.includes('deposit')) {
      if (!content.includes('isolated') && !content.includes('segregated') && !content.includes('per_user_vault')) {
        findings.push(createFinding(
          'SOL3157',
          'Trading Bot Without Fund Isolation',
          'critical',
          'Trading bot funds should be isolated per user. Banana Gun ($1.4M) and DEXX ($30M) exploits targeted shared/hot wallet funds.',
          { file: input.path },
          'Use per-user PDAs for fund storage. Never commingle user funds in hot wallets.'
        ));
      }
    }
    
    // Check for secure key storage
    if (!content.includes('encrypted_key') && !content.includes('secure_enclave') && !content.includes('vault_service')) {
      findings.push(createFinding(
        'SOL3158',
        'Trading Bot Key Storage Concerns',
        'high',
        'Bot private keys stored without encryption. DEXX lost $30M due to private key exposure.',
        { file: input.path },
        'Use encrypted key storage, HSMs, or secure enclaves. Never store plaintext keys.'
      ));
    }
  }
  
  return findings;
}

/**
 * SOL3159: Pump.fun Flash Loan Pattern
 */
function checkBondingCurveLiquidityManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  if (content.includes('bonding_curve') || content.includes('liquidity_pool') || content.includes('market_cap')) {
    // Check for internal privileged wallets
    if (content.includes('service_wallet') || content.includes('5PXxuZ') || content.includes('internal_wallet')) {
      findings.push(createFinding(
        'SOL3159',
        'Privileged Service Wallet Pattern',
        'critical',
        'Internal service wallets with privileged access are attack vectors. Pump.fun lost $2M when employee exploited service wallet.',
        { file: input.path },
        'Minimize service wallet privileges. Use multisig. Implement time-locked actions for sensitive operations.'
      ));
    }
    
    // Liquidity withdrawal patterns
    if (content.includes('withdraw_liquidity') || content.includes('remove_liquidity')) {
      if (!content.includes('lock_period') && !content.includes('time_lock') && !content.includes('vesting')) {
        findings.push(createFinding(
          'SOL3160',
          'Liquidity Removal Without Time Lock',
          'high',
          'Liquidity can be removed instantly, enabling rug pulls or flash loan attacks.',
          { file: input.path },
          'Implement liquidity lock periods, especially for protocol-owned liquidity.'
        ));
      }
    }
  }
  
  return findings;
}

/**
 * SOL3161-SOL3170: Advanced DeFi Vulnerability Patterns
 */
function checkAdvancedDeFiPatterns(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  // SOL3161: Oracle Staleness Check
  if (content.includes('oracle') || content.includes('price_feed')) {
    if (!content.includes('staleness') && !content.includes('last_update') && !content.includes('max_age')) {
      findings.push(createFinding(
        'SOL3161',
        'Oracle Without Staleness Check',
        'high',
        'Using stale oracle prices can lead to exploits during network congestion or oracle downtime.',
        { file: input.path },
        'Check oracle timestamp: require!(Clock::get()?.unix_timestamp - oracle.last_update < MAX_STALENESS)'
      ));
    }
  }
  
  // SOL3162: Negative Interest Rate
  if (content.includes('interest_rate') || content.includes('borrow_rate')) {
    if (!content.includes('min_rate') && !content.includes('>= 0') && !content.includes('saturating')) {
      findings.push(createFinding(
        'SOL3162',
        'Interest Rate Without Floor',
        'medium',
        'Interest rates should have a minimum floor to prevent negative rates in edge cases.',
        { file: input.path },
        'Implement minimum interest rate floor: rate = max(calculated_rate, MIN_RATE)'
      ));
    }
  }
  
  // SOL3163: Liquidation Cascade Risk
  if (content.includes('liquidate') || content.includes('liquidation')) {
    if (!content.includes('partial_liquidation') && !content.includes('max_liquidation_percent')) {
      findings.push(createFinding(
        'SOL3163',
        'Full Liquidation Without Partial Option',
        'medium',
        'Allowing only full liquidations can cause cascade liquidations during volatile markets.',
        { file: input.path },
        'Implement partial liquidations with configurable max percentage (e.g., 50% per liquidation).'
      ));
    }
  }
  
  // SOL3164: Redemption Sandwich Attack
  if (content.includes('redeem') || content.includes('redemption')) {
    if (!content.includes('min_output') && !content.includes('slippage') && !content.includes('deadline')) {
      findings.push(createFinding(
        'SOL3164',
        'Redemption Without Slippage Protection',
        'high',
        'Redemptions without minimum output can be sandwiched for MEV extraction.',
        { file: input.path },
        'Add min_output_amount parameter and validate: require!(output >= min_output)'
      ));
    }
  }
  
  // SOL3165: LP Token Pricing
  if (content.includes('lp_token') && content.includes('price')) {
    if (!content.includes('fair_lp_price') && !content.includes('underlying_value') && !content.includes('reserve_ratio')) {
      findings.push(createFinding(
        'SOL3165',
        'LP Token Without Fair Pricing',
        'critical',
        'LP token pricing must use fair pricing formula based on reserves, not spot price (OtterSec $200M at risk finding).',
        { file: input.path },
        'Use fair LP pricing: lp_price = sqrt(reserve0 * reserve1) / total_supply'
      ));
    }
  }
  
  // SOL3166: Vault Share Manipulation
  if (content.includes('vault') && (content.includes('shares') || content.includes('deposit'))) {
    if (content.includes('first_deposit') || content.includes('initial_deposit')) {
      if (!content.includes('min_shares') && !content.includes('dead_shares') && !content.includes('virtual_shares')) {
        findings.push(createFinding(
          'SOL3166',
          'First Deposit Share Manipulation',
          'high',
          'First depositor can manipulate share price by depositing tiny amount then donating tokens.',
          { file: input.path },
          'Use virtual shares or require minimum first deposit to prevent share price manipulation.'
        ));
      }
    }
  }
  
  // SOL3167: Leverage Position Risk
  if (content.includes('leverage') || content.includes('margin')) {
    if (!content.includes('max_leverage') && !content.includes('leverage_limit')) {
      findings.push(createFinding(
        'SOL3167',
        'No Maximum Leverage Limit',
        'high',
        'Unlimited leverage creates systemic risk during volatile markets (see $258M Solana whale liquidation).',
        { file: input.path },
        'Set maximum leverage limits based on asset volatility and liquidity.'
      ));
    }
  }
  
  // SOL3168: Insurance Fund Adequacy
  if (content.includes('insurance') || content.includes('insurance_fund')) {
    if (!content.includes('min_insurance') && !content.includes('insurance_ratio')) {
      findings.push(createFinding(
        'SOL3168',
        'Insurance Fund Without Minimum Threshold',
        'medium',
        'Insurance fund should maintain minimum ratio to total protocol TVL for protection.',
        { file: input.path },
        'Set minimum insurance fund ratio (e.g., 5% of TVL) and halt risky operations when below threshold.'
      ));
    }
  }
  
  // SOL3169: MEV Protection
  if (content.includes('swap') || content.includes('trade') || content.includes('order')) {
    if (!content.includes('private') && !content.includes('commit_reveal') && !content.includes('batch')) {
      findings.push(createFinding(
        'SOL3169',
        'Trade Without MEV Protection',
        'medium',
        'Trades without MEV protection can be front-run or sandwiched. Consider private mempools or batch auctions.',
        { file: input.path },
        'Consider Jito bundles for MEV protection, commit-reveal schemes, or batch auction mechanisms.'
      ));
    }
  }
  
  // SOL3170: Circuit Breaker Implementation
  if (content.includes('protocol') || content.includes('pool')) {
    if (!content.includes('circuit_breaker') && !content.includes('pause') && !content.includes('emergency_stop')) {
      findings.push(createFinding(
        'SOL3170',
        'No Circuit Breaker Mechanism',
        'high',
        'Protocols need circuit breakers to halt operations during attacks or extreme volatility.',
        { file: input.path },
        'Implement pausable pattern with authorized pausers and automatic triggers for anomalies.'
      ));
    }
  }
  
  return findings;
}

/**
 * SOL3171-SOL3180: Emerging 2026 Attack Patterns
 */
function check2026EmergingPatterns(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  // SOL3171: AI/Agent Wallet Integration
  if (content.includes('agent') || content.includes('ai_wallet') || content.includes('autonomous')) {
    if (!content.includes('spending_limit') && !content.includes('allowance')) {
      findings.push(createFinding(
        'SOL3171',
        'AI Agent Without Spending Limits',
        'high',
        'AI agents controlling wallets should have strict spending limits to prevent runaway transactions.',
        { file: input.path },
        'Implement per-transaction and daily spending limits for AI-controlled wallets.'
      ));
    }
  }
  
  // SOL3172: Compressed NFT Security
  if (content.includes('compressed') || content.includes('merkle_tree') || content.includes('bubblegum')) {
    if (!content.includes('verify_leaf') && !content.includes('verify_proof')) {
      findings.push(createFinding(
        'SOL3172',
        'cNFT Without Merkle Proof Verification',
        'critical',
        'Compressed NFTs must verify merkle proofs to prevent fake asset claims.',
        { file: input.path },
        'Always verify merkle proofs for cNFT operations using Bubblegum CPI.'
      ));
    }
  }
  
  // SOL3173: Token-2022 Extension Risks
  if (content.includes('token_2022') || content.includes('Token2022') || content.includes('token-2022')) {
    // Transfer hook validation
    if (content.includes('transfer_hook') && !content.includes('validate_hook')) {
      findings.push(createFinding(
        'SOL3173',
        'Token-2022 Transfer Hook Without Validation',
        'high',
        'Transfer hooks can contain malicious logic. Validate hook program before accepting Token-2022 tokens.',
        { file: input.path },
        'Whitelist approved transfer hooks or verify hook program source.'
      ));
    }
    
    // Confidential transfers
    if (content.includes('confidential') && !content.includes('audit_trail')) {
      findings.push(createFinding(
        'SOL3174',
        'Confidential Transfers Without Audit Capability',
        'medium',
        'Confidential transfers complicate compliance. Ensure audit trail capabilities if needed.',
        { file: input.path },
        'Consider compliance requirements for confidential transfer implementations.'
      ));
    }
  }
  
  // SOL3175: Blink/Actions Security
  if (content.includes('blink') || content.includes('actions.json') || content.includes('action_url')) {
    if (!content.includes('action_identity') && !content.includes('verify_action_url')) {
      findings.push(createFinding(
        'SOL3175',
        'Solana Action Without Identity Verification',
        'high',
        'Solana Actions (Blinks) should verify action provider identity to prevent phishing.',
        { file: input.path },
        'Verify action provider identity. Display clear transaction details before signing.'
      ));
    }
  }
  
  // SOL3176: Validator Stake Concentration
  if (content.includes('stake') || content.includes('validator')) {
    if (content.includes('delegate') && !content.includes('diversify') && !content.includes('max_single_validator')) {
      findings.push(createFinding(
        'SOL3176',
        'Stake Delegation Without Concentration Limits',
        'medium',
        'Delegating all stake to single validator creates concentration risk. Top validators control 43% of stake.',
        { file: input.path },
        'Diversify stake across multiple validators. Set maximum per-validator limits.'
      ));
    }
  }
  
  // SOL3177: Jito Client Dependency
  if (content.includes('jito') || content.includes('mev') || content.includes('bundle')) {
    if (!content.includes('fallback') && !content.includes('alternative_client')) {
      findings.push(createFinding(
        'SOL3177',
        'Jito Dependency Without Fallback',
        'low',
        'Jito client has 88% validator dominance. Consider fallback options for client diversity.',
        { file: input.path },
        'Implement fallback to standard client if Jito services are unavailable.'
      ));
    }
  }
  
  // SOL3178: Real-World Asset (RWA) Patterns
  if (content.includes('rwa') || content.includes('real_world_asset') || content.includes('tokenized')) {
    if (!content.includes('off_chain_verification') && !content.includes('attestation')) {
      findings.push(createFinding(
        'SOL3178',
        'RWA Without Off-Chain Attestation',
        'high',
        'Tokenized real-world assets need trusted attestation for backing verification.',
        { file: input.path },
        'Implement oracle-based attestation for RWA backing. Use trusted attesters or ZK proofs.'
      ));
    }
  }
  
  // SOL3179: Yield Aggregator Complex Routes
  if (content.includes('yield') && content.includes('aggregate')) {
    if (!content.includes('route_verification') && !content.includes('max_hops')) {
      findings.push(createFinding(
        'SOL3179',
        'Yield Aggregator Without Route Limits',
        'medium',
        'Complex yield routes increase attack surface and gas costs. Limit route complexity.',
        { file: input.path },
        'Set maximum hops for yield routes. Verify each protocol in the route is trusted.'
      ));
    }
  }
  
  // SOL3180: Social Recovery Patterns
  if (content.includes('social_recovery') || content.includes('guardian')) {
    if (!content.includes('threshold') && !content.includes('m_of_n')) {
      findings.push(createFinding(
        'SOL3180',
        'Social Recovery Without Threshold',
        'high',
        'Social recovery should require threshold of guardians, not single guardian approval.',
        { file: input.path },
        'Implement m-of-n guardian scheme (e.g., 3-of-5) for social recovery.'
      ));
    }
  }
  
  return findings;
}

/**
 * SOL3181-SOL3200: Protocol-Specific Deep Patterns
 */
function checkProtocolSpecificPatterns(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  // SOL3181: SPL Lending Rounding Direction
  if (content.includes('lending') || content.includes('borrow')) {
    if (content.includes('round') && !content.includes('round_down') && !content.includes('floor')) {
      findings.push(createFinding(
        'SOL3181',
        'Lending Protocol Rounding Direction',
        'high',
        'Lending protocols must round against user: interest up, collateral down (Neodyme $2.6B at risk finding).',
        { file: input.path },
        'Always round in protocol favor: interest = ceil(calculated), collateral_value = floor(calculated)'
      ));
    }
  }
  
  // SOL3182: Stake Pool Semantic Consistency
  if (content.includes('stake_pool') || content.includes('StakePool')) {
    if (content.includes('withdraw') && !content.includes('consistent_withdraw')) {
      findings.push(createFinding(
        'SOL3182',
        'Stake Pool Semantic Inconsistency Risk',
        'medium',
        'Stake pool operations should have consistent semantics (Sec3 Stake Pool vulnerability).',
        { file: input.path },
        'Ensure withdraw/deposit semantics are consistent. Document expected behavior clearly.'
      ));
    }
  }
  
  // SOL3183: Metaplex Verification
  if (content.includes('metaplex') || content.includes('Metadata') || content.includes('nft')) {
    if (content.includes('creator') && !content.includes('verified_creator') && !content.includes('is_verified')) {
      findings.push(createFinding(
        'SOL3183',
        'NFT Creator Without Verification Check',
        'high',
        'NFT creator addresses should check is_verified flag. Anyone can add themselves as unverified creator.',
        { file: input.path },
        'Check creator.verified == true when validating NFT authenticity.'
      ));
    }
  }
  
  // SOL3184: Marinade Delayed Unstake Pattern
  if (content.includes('unstake') || content.includes('withdrawal_delay')) {
    if (!content.includes('epoch_delay') && !content.includes('cooling_period')) {
      findings.push(createFinding(
        'SOL3184',
        'Liquid Staking Without Proper Delay',
        'medium',
        'Liquid staking should mirror native staking delays to prevent instant arbitrage.',
        { file: input.path },
        'Implement epoch-based delay for unstaking operations.'
      ));
    }
  }
  
  // SOL3185: Orca Whirlpool Specific
  if (content.includes('whirlpool') || content.includes('concentrated_liquidity')) {
    if (content.includes('tick_array') && !content.includes('verify_tick_array_pda')) {
      findings.push(createFinding(
        'SOL3185',
        'Whirlpool Tick Array Without PDA Verification',
        'high',
        'Tick arrays should be verified as PDAs derived from the pool.',
        { file: input.path },
        'Verify tick array PDAs: seeds = ["tick_array", pool, tick_index]'
      ));
    }
  }
  
  // SOL3186: Phoenix Order Book Security
  if (content.includes('order_book') || content.includes('phoenix') || content.includes('limit_order')) {
    if (!content.includes('self_trade_prevention') && !content.includes('wash_trading')) {
      findings.push(createFinding(
        'SOL3186',
        'Order Book Without Self-Trade Prevention',
        'medium',
        'Order books should prevent self-trading to avoid wash trading and manipulation.',
        { file: input.path },
        'Implement self-trade prevention: check maker != taker for all matches.'
      ));
    }
  }
  
  // SOL3187: Drift Protocol Oracle Guardrails
  if (content.includes('oracle') && content.includes('perp')) {
    if (!content.includes('oracle_guardrail') && !content.includes('price_band')) {
      findings.push(createFinding(
        'SOL3187',
        'Perpetual Without Oracle Guardrails',
        'high',
        'Perpetual protocols need oracle guardrails to prevent manipulation (Drift protocol pattern).',
        { file: input.path },
        'Implement price bands: require oracle price within X% of mark price.'
      ));
    }
  }
  
  // SOL3188: Jupiter Aggregator Route Verification
  if (content.includes('aggregator') || content.includes('route') || content.includes('jupiter')) {
    if (!content.includes('verify_route') && !content.includes('trusted_amm')) {
      findings.push(createFinding(
        'SOL3188',
        'DEX Aggregator Without Route Verification',
        'high',
        'Aggregator routes should only include verified/trusted AMMs to prevent malicious swaps.',
        { file: input.path },
        'Maintain allowlist of trusted AMM programs. Verify each hop in aggregation route.'
      ));
    }
  }
  
  // SOL3189: Pyth Price Confidence
  if (content.includes('pyth') || content.includes('price_account')) {
    if (content.includes('price') && !content.includes('confidence') && !content.includes('conf')) {
      findings.push(createFinding(
        'SOL3189',
        'Pyth Oracle Without Confidence Check',
        'high',
        'Pyth prices have confidence intervals. Wide confidence indicates uncertain price.',
        { file: input.path },
        'Check Pyth confidence: require!(price.conf / price.price < MAX_CONFIDENCE_RATIO)'
      ));
    }
  }
  
  // SOL3190: Switchboard Aggregator Patterns
  if (content.includes('switchboard') || content.includes('aggregator_account')) {
    if (!content.includes('min_oracle_results') && !content.includes('result_count')) {
      findings.push(createFinding(
        'SOL3190',
        'Switchboard Without Minimum Results',
        'medium',
        'Switchboard aggregators should require minimum oracle responses for reliability.',
        { file: input.path },
        'Check aggregator has sufficient responses: require!(result_count >= MIN_REQUIRED)'
      ));
    }
  }
  
  // SOL3191-3200: Additional Deep Patterns
  // SOL3191: Squads Multisig Integration
  if (content.includes('squads') || content.includes('multisig')) {
    if (content.includes('execute') && !content.includes('threshold_check')) {
      findings.push(createFinding(
        'SOL3191',
        'Multisig Execute Without Threshold Verification',
        'critical',
        'Multisig execution must verify threshold signatures are met.',
        { file: input.path },
        'Verify signature count meets threshold before executing multisig transactions.'
      ));
    }
  }
  
  // SOL3192: Anchor Event Manipulation
  if (content.includes('emit!') || content.includes('Event')) {
    if (content.includes('amount') || content.includes('value')) {
      findings.push(createFinding(
        'SOL3192',
        'Event Emission Without State Verification',
        'low',
        'Events should reflect actual state changes, not just input parameters.',
        { file: input.path },
        'Emit events after state mutation, using actual resulting values.'
      ));
    }
  }
  
  // SOL3193: CPI Guard Bypass
  if (content.includes('cpi_guard') || content.includes('CpiGuard')) {
    if (!content.includes('toggle_off') && !content.includes('disable_guard')) {
      findings.push(createFinding(
        'SOL3193',
        'CPI Guard Without Disable Option',
        'info',
        'CPI guard should have authorized disable for legitimate use cases.',
        { file: input.path },
        'Allow authorized users to toggle CPI guard when needed for legitimate protocols.'
      ));
    }
  }
  
  // SOL3194: Token Account Authority Mismatch
  if (content.includes('token_account') || content.includes('TokenAccount')) {
    if (content.includes('authority') && !content.includes('delegate') && !content.includes('close_authority')) {
      findings.push(createFinding(
        'SOL3194',
        'Token Account Authority Incomplete Check',
        'medium',
        'Token accounts have owner, delegate, and close_authority. Check all relevant authorities.',
        { file: input.path },
        'Verify all token account authority fields as needed: owner, delegate, close_authority.'
      ));
    }
  }
  
  // SOL3195: Rent Epoch Check
  if (content.includes('account') && content.includes('close')) {
    if (!content.includes('rent_epoch') && !content.includes('data_is_empty')) {
      findings.push(createFinding(
        'SOL3195',
        'Account Close Without Rent Epoch Check',
        'low',
        'Check rent_epoch for account lifecycle patterns to detect account resurrection.',
        { file: input.path },
        'Monitor rent_epoch changes for security-sensitive account operations.'
      ));
    }
  }
  
  // SOL3196: Native SOL vs Wrapped SOL
  if (content.includes('lamports') && content.includes('token')) {
    if (!content.includes('native_mint') && !content.includes('NATIVE_MINT')) {
      findings.push(createFinding(
        'SOL3196',
        'Native SOL Handling May Be Missing',
        'low',
        'Programs handling tokens should also handle native SOL (WSOL) cases.',
        { file: input.path },
        'Handle native SOL: check for NATIVE_MINT and sync_native for wrapped SOL.'
      ));
    }
  }
  
  // SOL3197: Account Size Limits
  if (content.includes('realloc') || content.includes('resize')) {
    if (!content.includes('MAX_PERMITTED_DATA_INCREASE') && !content.includes('max_size')) {
      findings.push(createFinding(
        'SOL3197',
        'Account Reallocation Without Size Limit',
        'medium',
        'Account reallocation should respect MAX_PERMITTED_DATA_INCREASE (10KB per transaction).',
        { file: input.path },
        'Limit reallocation: require!(new_size - old_size <= 10240)'
      ));
    }
  }
  
  // SOL3198: Compute Unit Estimation
  if (content.includes('compute') || content.includes('cu_limit')) {
    if (!content.includes('estimate_compute') && !content.includes('set_compute_unit_limit')) {
      findings.push(createFinding(
        'SOL3198',
        'Missing Compute Unit Estimation',
        'low',
        'Complex operations should estimate compute units to avoid transaction failures.',
        { file: input.path },
        'Estimate and set appropriate compute unit limits for complex transactions.'
      ));
    }
  }
  
  // SOL3199: Versioned Transaction Lookup Table
  if (content.includes('v0') || content.includes('versioned')) {
    if (content.includes('lookup_table') && !content.includes('verify_table_authority')) {
      findings.push(createFinding(
        'SOL3199',
        'Lookup Table Without Authority Verification',
        'high',
        'Address lookup tables can be modified by authority. Verify table authority or use immutable tables.',
        { file: input.path },
        'Freeze lookup tables after creation or verify authority before each use.'
      ));
    }
  }
  
  // SOL3200: Block Hash Expiry
  if (content.includes('recent_blockhash') || content.includes('blockhash')) {
    if (!content.includes('get_latest_blockhash') && !content.includes('blockhash_valid')) {
      findings.push(createFinding(
        'SOL3200',
        'Blockhash Freshness Not Verified',
        'low',
        'Transactions with old blockhashes will fail. Use recent blockhashes (< 150 slots old).',
        { file: input.path },
        'Always fetch fresh blockhash before signing. Consider durable nonces for long-lived transactions.'
      ));
    }
  }
  
  return findings;
}

// Export all check functions
export function checkBatch70Patterns(input: PatternInput): Finding[] {
  return [
    ...checkStepFinanceKeyCompromise(input),
    ...checkOwnerPermissionPhishing(input),
    ...checkAccountAssignAttack(input),
    ...checkSimulationDetectionBypass(input),
    ...checkPrivacyCoinLaundering(input),
    ...checkHotWalletKeyRotation(input),
    ...checkWithdrawalDelayBypass(input),
    ...checkInstructionIntrospection(input),
    ...checkWalletDrainerPattern(input),
    ...checkDelegateAuthorityAbuse(input),
    ...checkTrustedFrontendAssumption(input),
    ...checkMemorySafeLogicUnsafe(input),
    ...checkOracleSelfTrading(input),
    ...checkCLMMTickManipulation(input),
    ...checkBondingCurveFlashExploit(input),
    ...checkGovernanceTimingAttack(input),
    ...checkRateXPTVulnerability(input),
    ...checkTrustWalletStyle(input),
    ...checkDDoSProtection(input),
    ...checkSeedPhraseExfiltration(input),
    ...checkProgramClosePattern(input),
    ...checkCrossChainBridgeVulnerability(input),
    ...checkTradingBotVulnerability(input),
    ...checkBondingCurveLiquidityManipulation(input),
    ...checkAdvancedDeFiPatterns(input),
    ...check2026EmergingPatterns(input),
    ...checkProtocolSpecificPatterns(input),
  ];
}

export default checkBatch70Patterns;
