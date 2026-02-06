/**
 * Batch 67: 2025-2026 Emerging Attack Vectors & Infrastructure Security
 * Based on SEC3 2025 Report, Helius Research, and Academic Papers
 * Patterns: SOL3001-SOL3050
 */

import type { PatternInput, Finding, Pattern } from './index.js';

/**
 * Creates a finding with consistent structure
 */
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
 * SOL3001: Whale Liquidation Cascade
 * Based on Nov 2025 $258M whale liquidation incident
 */
function checkWhaleLiquidationCascade(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;

  // Check for liquidation without cascade protection
  if (input.rust.content.includes('liquidate') && 
      !input.rust.content.includes('cascade_protection') &&
      !input.rust.content.includes('max_liquidation_per_block')) {
    findings.push(createFinding(
      'SOL3001',
      'Whale Liquidation Cascade Vulnerability',
      'critical',
      'Liquidation logic lacks cascade protection. Large position liquidations can trigger cascading losses across DeFi protocols.',
      { file: input.path },
      'Implement max_liquidation_per_block limits and cascade circuit breakers'
    ));
  }

  return findings;
}

/**
 * SOL3002: MEV-Dependent Validator Stability
 * Based on Nov 2025 analysis of Jito client dominance (88%)
 */
function checkMevValidatorDependency(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;

  if ((input.rust.content.includes('jito') || input.rust.content.includes('bundle')) &&
      !input.rust.content.includes('fallback_validator') &&
      !input.rust.content.includes('mev_protection')) {
    findings.push(createFinding(
      'SOL3002',
      'MEV-Dependent Validator Concentration Risk',
      'high',
      'Protocol relies on MEV infrastructure (Jito) without fallback. 88% validator concentration creates systemic risk.',
      { file: input.path },
      'Implement MEV-agnostic transaction submission with fallback to standard validators'
    ));
  }

  return findings;
}

/**
 * SOL3003: Hosting Provider Concentration Risk
 * Teraswitch/Latitude.sh control ~43% of stake
 */
function checkInfrastructureConcentration(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;

  if (input.rust.content.includes('validator') && 
      input.rust.content.includes('stake') &&
      !input.rust.content.includes('geographic_distribution') &&
      !input.rust.content.includes('provider_diversity')) {
    findings.push(createFinding(
      'SOL3003',
      'Infrastructure Provider Concentration',
      'medium',
      'Validator staking logic should consider hosting provider diversity to avoid systemic failures.',
      { file: input.path },
      'Add provider diversity checks and avoid concentration in single hosting providers'
    ));
  }

  return findings;
}

/**
 * SOL3004: Account Validation Failure in High-Speed Context
 * Per arXiv paper on Solana vulnerabilities
 */
function checkHighSpeedAccountValidation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;

  // Check for parallel processing without proper account validation
  if ((input.rust.content.includes('parallel') || input.rust.content.includes('concurrent')) &&
      input.rust.content.includes('AccountInfo') &&
      !input.rust.content.includes('is_signer') &&
      !input.rust.content.includes('owner ==')) {
    findings.push(createFinding(
      'SOL3004',
      'Account Validation Missing in Parallel Context',
      'critical',
      'Parallel processing context lacks proper account validation. High-speed execution can bypass safety checks.',
      { file: input.path },
      'Ensure all AccountInfo validations (signer, owner) are performed before parallel operations'
    ));
  }

  return findings;
}

/**
 * SOL3005: Oracle Manipulation in High-TVL Context
 * Per Sec3 2025 report - $1.8B in preventable losses
 */
function checkHighTvlOracleProtection(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;

  if (input.rust.content.includes('oracle') && 
      input.rust.content.includes('price') &&
      !input.rust.content.includes('twap') &&
      !input.rust.content.includes('confidence_interval') &&
      !input.rust.content.includes('staleness_check')) {
    findings.push(createFinding(
      'SOL3005',
      'Oracle Price Without Confidence/TWAP Protection',
      'critical',
      'Oracle price used without TWAP or confidence interval checks. $1.8B in 2025 losses were from oracle manipulation.',
      { file: input.path },
      'Implement TWAP averaging, confidence intervals, and staleness checks for all oracle reads'
    ));
  }

  return findings;
}

/**
 * SOL3006: Missing Access Control in Admin Functions
 * Per Sec3 2025 - 19% of findings were access control issues
 */
function checkAdminAccessControl(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;

  const adminPatterns = /pub\s+fn\s+(admin_|set_|update_|configure_|withdraw_|emergency_)/g;
  const matches = input.rust.content.match(adminPatterns);
  
  if (matches && matches.length > 0) {
    // Check if access control exists
    if (!input.rust.content.includes('#[access_control') &&
        !input.rust.content.includes('require!(ctx.accounts.authority') &&
        !input.rust.content.includes('has_one = authority')) {
      findings.push(createFinding(
        'SOL3006',
        'Admin Function Missing Access Control',
        'critical',
        `Found ${matches.length} admin function(s) without explicit access control. 19% of 2025 audit findings were access control issues.`,
        { file: input.path },
        'Add #[access_control] or require!(authority) checks to all admin functions'
      ));
    }
  }

  return findings;
}

/**
 * SOL3007: Reentrancy in CPI Context
 * Per arXiv paper - classic vulnerability in Solana context
 */
function checkCpiReentrancy(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;

  if (input.rust.content.includes('invoke(') || input.rust.content.includes('invoke_signed(')) {
    if (input.rust.content.includes('.try_borrow_mut') ||
        input.rust.content.includes('.borrow_mut()')) {
      // Check if mutable borrow happens after CPI
      const cpiIndex = Math.max(
        input.rust.content.indexOf('invoke('),
        input.rust.content.indexOf('invoke_signed(')
      );
      const borrowIndex = Math.max(
        input.rust.content.indexOf('.try_borrow_mut'),
        input.rust.content.indexOf('.borrow_mut()')
      );
      
      if (borrowIndex > cpiIndex && !input.rust.content.includes('reentrancy_guard')) {
        findings.push(createFinding(
          'SOL3007',
          'Potential CPI Reentrancy Vulnerability',
          'critical',
          'Mutable account borrow occurs after CPI. Called program could re-enter and exploit stale state.',
          { file: input.path },
          'Complete all state updates before CPI or implement reentrancy guards'
        ));
      }
    }
  }

  return findings;
}

/**
 * SOL3008: Integer Overflow in Arithmetic
 * Still 25% of findings per Sec3 2025
 */
function checkArithmeticOverflow(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;

  // Check for unchecked arithmetic in sensitive contexts
  if ((input.rust.content.includes('+ ') || input.rust.content.includes('* ')) &&
      input.rust.content.includes('u64') &&
      !input.rust.content.includes('checked_add') &&
      !input.rust.content.includes('checked_mul') &&
      !input.rust.content.includes('saturating_') &&
      !input.rust.content.includes('overflow-checks = true')) {
    findings.push(createFinding(
      'SOL3008',
      'Unchecked Arithmetic Operations',
      'high',
      'u64 arithmetic without checked_add/checked_mul. Overflow vulnerabilities remain 25% of audit findings.',
      { file: input.path },
      'Use checked_add, checked_mul, or saturating operations for all arithmetic'
    ));
  }

  return findings;
}

/**
 * SOL3009: Missing Input Validation Bounds
 * 25% of Sec3 2025 findings
 */
function checkInputValidationBounds(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;

  // Check for function parameters without validation
  const funcPattern = /pub\s+fn\s+\w+\([^)]*amount:\s*u64[^)]*\)/g;
  if (funcPattern.test(input.rust.content)) {
    if (!input.rust.content.includes('require!(amount >') &&
        !input.rust.content.includes('require!(amount <') &&
        !input.rust.content.includes('amount == 0')) {
      findings.push(createFinding(
        'SOL3009',
        'Missing Amount Bounds Validation',
        'high',
        'Amount parameters lack bounds validation. Input validation issues are 25% of findings.',
        { file: input.path },
        'Add minimum and maximum bounds checks for all amount parameters'
      ));
    }
  }

  return findings;
}

/**
 * SOL3010: Business Logic State Machine Violation
 * 38.5% of findings per Sec3 2025
 */
function checkStateTransitionValidation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;

  // Check for state enums without transition validation
  if (input.rust.content.includes('pub enum') && 
      input.rust.content.includes('State') &&
      !input.rust.content.includes('valid_transition') &&
      !input.rust.content.includes('can_transition')) {
    findings.push(createFinding(
      'SOL3010',
      'State Machine Without Transition Validation',
      'high',
      'State enum found without transition validation. Business logic issues are 38.5% of findings.',
      { file: input.path },
      'Implement explicit state transition validation with can_transition() checks'
    ));
  }

  return findings;
}

/**
 * SOL3011: Data Integrity Race Condition
 * 8.9% of Sec3 2025 findings
 */
function checkDataIntegrityRace(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;

  // Check for parallel account access without locking
  if (input.rust.content.includes('AccountInfo') &&
      (input.rust.content.includes('mut') || input.rust.content.includes('RefMut')) &&
      !input.rust.content.includes('try_lock') &&
      !input.rust.content.includes('atomic')) {
    findings.push(createFinding(
      'SOL3011',
      'Potential Data Integrity Race Condition',
      'medium',
      'Mutable account access without explicit locking. Race conditions can cause data corruption.',
      { file: input.path },
      'Use atomic operations or explicit locking for shared mutable state'
    ));
  }

  return findings;
}

/**
 * SOL3012: DoS via Unbounded Iteration
 * 8.5% of Sec3 2025 findings
 */
function checkUnboundedIteration(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;

  // Check for loops without bounds
  if ((input.rust.content.includes('for ') || input.rust.content.includes('.iter()')) &&
      input.rust.content.includes('.len()') &&
      !input.rust.content.includes('MAX_') &&
      !input.rust.content.includes('.take(')) {
    findings.push(createFinding(
      'SOL3012',
      'Unbounded Iteration DoS Risk',
      'high',
      'Iteration over dynamic-length collection without bounds. DoS/Liveness issues are 8.5% of findings.',
      { file: input.path },
      'Add MAX_ITEMS constant and use .take(MAX_ITEMS) or explicit bounds checking'
    ));
  }

  return findings;
}

/**
 * SOL3013: Transfer Hook Reentrancy (Token-2022)
 * Emerging 2025-2026 attack vector
 */
function checkTransferHookReentrancy(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;

  if (input.rust.content.includes('transfer_hook') || 
      input.rust.content.includes('TransferHook')) {
    if (!input.rust.content.includes('reentrancy_check') &&
        !input.rust.content.includes('in_transfer')) {
      findings.push(createFinding(
        'SOL3013',
        'Transfer Hook Reentrancy Risk',
        'critical',
        'Token-2022 transfer hook without reentrancy protection. Hooks can be exploited for reentry attacks.',
        { file: input.path },
        'Implement reentrancy guard flag that prevents nested transfer hook execution'
      ));
    }
  }

  return findings;
}

/**
 * SOL3014: Compressed NFT Proof Validation
 * Bubblegum/cNFT security pattern
 */
function checkCnftProofValidation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;

  if ((input.rust.content.includes('merkle') || input.rust.content.includes('bubblegum')) &&
      input.rust.content.includes('proof') &&
      !input.rust.content.includes('verify_proof') &&
      !input.rust.content.includes('validate_proof')) {
    findings.push(createFinding(
      'SOL3014',
      'cNFT Merkle Proof Validation Missing',
      'critical',
      'Compressed NFT operations without proper Merkle proof verification.',
      { file: input.path },
      'Always verify Merkle proofs before any cNFT state changes'
    ));
  }

  return findings;
}

/**
 * SOL3015: Governance Flash Loan Attack
 * Multiple 2024-2025 DAO exploits
 */
function checkGovernanceFlashLoan(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;

  if ((input.rust.content.includes('governance') || input.rust.content.includes('vote')) &&
      input.rust.content.includes('token_balance') &&
      !input.rust.content.includes('snapshot') &&
      !input.rust.content.includes('voting_escrow')) {
    findings.push(createFinding(
      'SOL3015',
      'Governance Flash Loan Voting Attack',
      'critical',
      'Governance uses current token balance for voting power. Flash loans can manipulate votes.',
      { file: input.path },
      'Use snapshot-based voting power or require time-locked tokens (veTokens)'
    ));
  }

  return findings;
}

/**
 * SOL3016: Insider Threat - Single Admin Key
 * Pump.fun $1.9M, Saga DAO patterns
 */
function checkSingleAdminKey(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;

  if (input.rust.content.includes('admin') && 
      input.rust.content.includes('Pubkey') &&
      !input.rust.content.includes('multisig') &&
      !input.rust.content.includes('threshold') &&
      !input.rust.content.includes('signers')) {
    findings.push(createFinding(
      'SOL3016',
      'Single Admin Key Risk',
      'high',
      'Admin controlled by single key without multisig. Pump.fun lost $1.9M to insider attack.',
      { file: input.path },
      'Implement multisig with minimum 2-of-3 threshold for admin operations'
    ));
  }

  return findings;
}

/**
 * SOL3017: Private Key Exposure in Code
 * DEXX $30M pattern
 */
function checkPrivateKeyExposure(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;

  const keyPatterns = [
    /private_key/i,
    /secret_key/i,
    /keypair\s*=/,
    /seed_phrase/i,
    /mnemonic/i
  ];

  for (const pattern of keyPatterns) {
    if (pattern.test(input.rust.content)) {
      findings.push(createFinding(
        'SOL3017',
        'Potential Private Key Exposure',
        'critical',
        'Code references private key material. DEXX lost $30M due to private key server storage.',
        { file: input.path },
        'Never store or reference private keys in code. Use hardware wallets or secure enclaves.'
      ));
      break;
    }
  }

  return findings;
}

/**
 * SOL3018: Supply Chain Dependency Risk
 * Web3.js Dec 2024 attack pattern
 */
function checkSupplyChainRisk(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;

  // Check for version pinning in dependencies
  if (input.rust.content.includes('use ') && 
      input.rust.content.includes('::')) {
    // This is a simplified check - actual check would parse Cargo.toml
    if (input.path.endsWith('Cargo.toml')) {
      if (!input.rust.content.includes('=') || input.rust.content.includes('*')) {
        findings.push(createFinding(
          'SOL3018',
          'Unpinned Dependency Version',
          'high',
          'Dependencies should use exact version pinning. Web3.js supply chain attack affected millions.',
          { file: input.path },
          'Pin all dependency versions exactly (e.g., "1.2.3" not "^1.2.3" or "*")'
        ));
      }
    }
  }

  return findings;
}

/**
 * SOL3019: Bonding Curve Flash Loan Attack
 * Nirvana $3.5M pattern
 */
function checkBondingCurveFlashLoan(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;

  if (input.rust.content.includes('bonding_curve') &&
      (input.rust.content.includes('buy') || input.rust.content.includes('sell'))) {
    if (!input.rust.content.includes('flash_loan_guard') &&
        !input.rust.content.includes('same_block_restriction')) {
      findings.push(createFinding(
        'SOL3019',
        'Bonding Curve Flash Loan Vulnerability',
        'critical',
        'Bonding curve without flash loan protection. Nirvana lost $3.5M to flash loan + bonding curve exploit.',
        { file: input.path },
        'Implement same-block buy/sell restrictions or flash loan detection'
      ));
    }
  }

  return findings;
}

/**
 * SOL3020: Bridge Guardian Set Validation
 * Wormhole $326M pattern
 */
function checkBridgeGuardianValidation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;

  if (input.rust.content.includes('guardian') && 
      input.rust.content.includes('signature')) {
    if (!input.rust.content.includes('guardian_set_index') ||
        !input.rust.content.includes('quorum')) {
      findings.push(createFinding(
        'SOL3020',
        'Bridge Guardian Validation Incomplete',
        'critical',
        'Bridge guardian signature without proper set index and quorum validation. Wormhole lost $326M.',
        { file: input.path },
        'Validate guardian set index, check quorum requirements, and verify all signatures'
      ));
    }
  }

  return findings;
}

// Export all patterns
export const BATCH_67_PATTERNS: Pattern[] = [
  { id: 'SOL3001', name: 'Whale Liquidation Cascade', severity: 'critical', run: checkWhaleLiquidationCascade },
  { id: 'SOL3002', name: 'MEV-Dependent Validator Risk', severity: 'high', run: checkMevValidatorDependency },
  { id: 'SOL3003', name: 'Infrastructure Concentration', severity: 'medium', run: checkInfrastructureConcentration },
  { id: 'SOL3004', name: 'High-Speed Account Validation', severity: 'critical', run: checkHighSpeedAccountValidation },
  { id: 'SOL3005', name: 'High-TVL Oracle Protection', severity: 'critical', run: checkHighTvlOracleProtection },
  { id: 'SOL3006', name: 'Admin Access Control', severity: 'critical', run: checkAdminAccessControl },
  { id: 'SOL3007', name: 'CPI Reentrancy', severity: 'critical', run: checkCpiReentrancy },
  { id: 'SOL3008', name: 'Arithmetic Overflow', severity: 'high', run: checkArithmeticOverflow },
  { id: 'SOL3009', name: 'Input Bounds Validation', severity: 'high', run: checkInputValidationBounds },
  { id: 'SOL3010', name: 'State Machine Validation', severity: 'high', run: checkStateTransitionValidation },
  { id: 'SOL3011', name: 'Data Integrity Race', severity: 'medium', run: checkDataIntegrityRace },
  { id: 'SOL3012', name: 'Unbounded Iteration DoS', severity: 'high', run: checkUnboundedIteration },
  { id: 'SOL3013', name: 'Transfer Hook Reentrancy', severity: 'critical', run: checkTransferHookReentrancy },
  { id: 'SOL3014', name: 'cNFT Proof Validation', severity: 'critical', run: checkCnftProofValidation },
  { id: 'SOL3015', name: 'Governance Flash Loan', severity: 'critical', run: checkGovernanceFlashLoan },
  { id: 'SOL3016', name: 'Single Admin Key', severity: 'high', run: checkSingleAdminKey },
  { id: 'SOL3017', name: 'Private Key Exposure', severity: 'critical', run: checkPrivateKeyExposure },
  { id: 'SOL3018', name: 'Supply Chain Risk', severity: 'high', run: checkSupplyChainRisk },
  { id: 'SOL3019', name: 'Bonding Curve Flash Loan', severity: 'critical', run: checkBondingCurveFlashLoan },
  { id: 'SOL3020', name: 'Bridge Guardian Validation', severity: 'critical', run: checkBridgeGuardianValidation },
];

export function checkBatch67Patterns(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  for (const pattern of BATCH_67_PATTERNS) {
    findings.push(...pattern.run(input));
  }
  return findings;
}
