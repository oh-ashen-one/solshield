/**
 * SolGuard Security Patterns SOL677-SOL696 (20 patterns)
 * Based on Sec3 2025 Report + sannykim/solsec Research
 * Focus: Business Logic Flaws (38.5% of all vulns)
 */

import type { Finding } from '../commands/audit.js';
import type { ParsedIdl } from '../parsers/idl.js';
import type { ParsedRust } from '../parsers/rust.js';

interface PatternInput {
  idl?: ParsedIdl;
  rust?: ParsedRust;
  raw?: string;
}

// SOL677: Neodyme Rounding Attack ($2.6B at risk)
// Reference: https://blog.neodyme.io/posts/lending_disclosure
export function checkNeodymeRoundingAttack(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const raw = input.raw || '';
  
  // Look for round() usage in financial contexts
  const roundPatterns = [
    /\.round\s*\(\)/gi,
    /\.round_up\s*\(\)/gi,
    /f64::round/gi,
    /\.round\s*\(\s*\)\s*as\s+u64/gi,
    /rounding_mode\s*:\s*RoundingMode::Round/gi,
  ];
  
  for (const pattern of roundPatterns) {
    if (pattern.test(raw)) {
      // Check if it's in a financial context
      if (/deposit|withdraw|borrow|repay|interest|fee|amount|collateral/i.test(raw)) {
        findings.push({
          id: 'SOL677',
          name: 'Neodyme Rounding Attack Vector',
          severity: 'critical',
          description: 'Using round() instead of floor()/ceil() in financial calculations can lead to fund extraction. The Neodyme disclosure showed how rounding errors put $2.6B at risk in SPL lending.',
          location: 'Detected round() in financial context',
          recommendation: 'Use floor() for user-favorable rounding (deposits) and ceil() for protocol-favorable rounding (withdrawals). Never use round() for financial calculations.'
        });
        break;
      }
    }
  }
  
  return findings;
}

// SOL678: Jet Protocol Break Statement Bug
// Reference: https://medium.com/@0xjayne/how-to-freely-borrow-all-the-tvl-from-the-jet-protocol
export function checkJetBreakStatementBug(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const raw = input.raw || '';
  
  // Look for break statements in validation loops
  const breakInLoopPattern = /for\s+.*?\{[\s\S]*?if\s+.*?\{[\s\S]*?break;[\s\S]*?\}[\s\S]*?\}/gi;
  
  if (breakInLoopPattern.test(raw)) {
    // Check if it's in a validation context
    if (/validate|check|verify|require|assert/i.test(raw)) {
      findings.push({
        id: 'SOL678',
        name: 'Break Statement in Validation Loop',
        severity: 'high',
        description: 'Break statements in validation loops can skip remaining checks. The Jet Protocol bug allowed borrowing all TVL due to an unintended break statement.',
        location: 'Detected break in validation loop',
        recommendation: 'Use return with explicit error instead of break in validation loops. Ensure all validations complete before proceeding.'
      });
    }
  }
  
  return findings;
}

// SOL679: Cope Roulette Revert Exploit
// Reference: https://github.com/Arrowana/cope-roulette-pro
export function checkCopeRouletteExploit(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const raw = input.raw || '';
  
  // Look for patterns that could be exploited via reverting transactions
  const revertablePatterns = [
    /random|rng|lottery|roulette|dice|gamble/i,
    /slot_hashes|recent_slothashes/i,
    /clock\.unix_timestamp.*random/i,
  ];
  
  for (const pattern of revertablePatterns) {
    if (pattern.test(raw)) {
      findings.push({
        id: 'SOL679',
        name: 'Cope Roulette Revert Exploit Pattern',
        severity: 'critical',
        description: 'Randomness based on slot hashes or timestamps can be exploited by reverting transactions until favorable outcome. Attackers submit transactions and revert unfavorable results.',
        location: 'Detected revertable randomness pattern',
        recommendation: 'Use commit-reveal schemes or VRF (Verifiable Random Function) for randomness. Implement cooldowns or stake requirements that prevent rapid retry attacks.'
      });
      break;
    }
  }
  
  return findings;
}

// SOL680: Simulation Detection Bypass
// Reference: https://opcodes.fr/en/publications/2022-01/detecting-transaction-simulation/
export function checkSimulationDetectionBypass(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const raw = input.raw || '';
  
  // Look for simulation detection attempts
  const simDetectionPatterns = [
    /is_simulation|simulation_mode/i,
    /bank\.is_testnet/i,
    /detect.*simulation/i,
    /simulation.*detect/i,
  ];
  
  for (const pattern of simDetectionPatterns) {
    if (pattern.test(raw)) {
      findings.push({
        id: 'SOL680',
        name: 'Simulation Detection Bypass Risk',
        severity: 'medium',
        description: 'Attempting to detect transaction simulation can be bypassed. Security logic should not rely on simulation detection.',
        location: 'Detected simulation detection attempt',
        recommendation: 'Do not rely on simulation detection for security. Design your protocol to be secure whether simulated or not.'
      });
      break;
    }
  }
  
  return findings;
}

// SOL681: Root of Trust Chain Validation (Cashio)
// Reference: https://www.sec3.dev/blog/cashioapp-attack-whats-the-vulnerability-and-how-soteria-detects-it
export function checkRootOfTrustChainValidation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const raw = input.raw || '';
  
  // Look for collateral or backing validation
  const trustChainPatterns = [
    /collateral.*mint|mint.*collateral/i,
    /backing.*token|token.*backing/i,
    /validate_collateral|verify_backing/i,
  ];
  
  let hasCollateralLogic = false;
  for (const pattern of trustChainPatterns) {
    if (pattern.test(raw)) {
      hasCollateralLogic = true;
      break;
    }
  }
  
  if (hasCollateralLogic) {
    // Check if there's proper root validation
    const hasRootValidation = /root_bank|root_oracle|primary_source|canonical/i.test(raw);
    
    if (!hasRootValidation) {
      findings.push({
        id: 'SOL681',
        name: 'Missing Root of Trust Chain Validation',
        severity: 'critical',
        description: 'Collateral or backing validation without establishing a root of trust can allow attackers to create fake collateral chains. Cashio lost $52.8M due to this.',
        location: 'Collateral validation without root trust check',
        recommendation: 'Always validate back to a canonical, trusted root. Never accept collateral chains without verifying the entire trust path to an immutable source.'
      });
    }
  }
  
  return findings;
}

// SOL682: Unchecked Account (Anchor CHECK Documentation)
// Reference: Candy Machine exploit + Anchor requirements
export function checkUncheckedAccountDocumentation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const raw = input.raw || '';
  
  // Look for UncheckedAccount or AccountInfo without CHECK comment
  const uncheckedPattern = /UncheckedAccount|AccountInfo<'info>/g;
  const checkCommentPattern = /\/\/\/\s*CHECK:|\/\/\s*CHECK:|#\[account\(.*\)\]/;
  
  const matches = raw.match(uncheckedPattern);
  if (matches && matches.length > 0) {
    // Check if there are CHECK comments
    if (!checkCommentPattern.test(raw)) {
      findings.push({
        id: 'SOL682',
        name: 'Unchecked Account Without Documentation',
        severity: 'high',
        description: 'UncheckedAccount or AccountInfo used without /// CHECK documentation. This bypasses Anchor safety checks and was the root cause of Candy Machine exploits.',
        location: `Found ${matches.length} unchecked account(s)`,
        recommendation: 'Add /// CHECK documentation explaining why the account is safe, or use proper account constraints. Never use UncheckedAccount without explicit validation.'
      });
    }
  }
  
  return findings;
}

// SOL683: LP Token Oracle Manipulation ($200M risk)
// Reference: https://osec.io/blog/reports/2022-02-16-lp-token-oracle-manipulation/
export function checkLpTokenOracleManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const raw = input.raw || '';
  
  // Look for LP token pricing patterns
  const lpPricingPatterns = [
    /lp.*price|price.*lp/i,
    /pool_token.*value|value.*pool_token/i,
    /get_lp_value|calculate_lp_price/i,
    /reserve.*ratio|ratio.*reserve/i,
  ];
  
  for (const pattern of lpPricingPatterns) {
    if (pattern.test(raw)) {
      // Check if using fair pricing
      const hasFairPricing = /fair_price|sqrt.*price|geometric_mean/i.test(raw);
      const hasTwap = /twap|time_weighted|average_price/i.test(raw);
      
      if (!hasFairPricing && !hasTwap) {
        findings.push({
          id: 'SOL683',
          name: 'LP Token Oracle Manipulation Risk',
          severity: 'critical',
          description: 'LP token pricing without fair pricing or TWAP protection can be manipulated via flash loans. OtterSec disclosed $200M at risk in Solana lending protocols.',
          location: 'LP token pricing without fair pricing protection',
          recommendation: 'Use fair LP pricing formulas (geometric mean) or implement TWAP oracles with sufficient delay. Never use spot reserve ratios directly.'
        });
        break;
      }
    }
  }
  
  return findings;
}

// SOL684: Signature Set Fabrication (Wormhole $326M)
// Reference: https://twitter.com/samczsun/status/1489044939732406275
export function checkSignatureSetFabrication(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const raw = input.raw || '';
  
  // Look for signature verification patterns
  const sigVerifyPatterns = [
    /verify_signatures|signature.*verify/i,
    /guardian.*signature|signature.*guardian/i,
    /validator.*signature|multi.*sig/i,
    /SignatureSet|signature_set/i,
  ];
  
  for (const pattern of sigVerifyPatterns) {
    if (pattern.test(raw)) {
      // Check for proper initialization and ownership checks
      const hasOwnerCheck = /owner\s*==|owner\.key\(\)|is_owned_by/i.test(raw);
      const hasInitCheck = /is_initialized|initialized\s*==\s*true/i.test(raw);
      
      if (!hasOwnerCheck || !hasInitCheck) {
        findings.push({
          id: 'SOL684',
          name: 'Signature Set Fabrication Risk (Wormhole Pattern)',
          severity: 'critical',
          description: 'Signature verification without proper ownership and initialization checks allows attackers to fabricate signature sets. Wormhole lost $326M due to this vulnerability.',
          location: 'Signature verification without ownership/init checks',
          recommendation: 'Always verify: 1) The signature set account is owned by your program, 2) The account is properly initialized, 3) All signatures are from authorized guardians.'
        });
        break;
      }
    }
  }
  
  return findings;
}

// SOL685: Incinerator NFT Attack (Schrodinger's NFT)
// Reference: https://medium.com/@solens_io/schrodingers-nft-an-incinerator-spl-token-program
export function checkIncineratorNftAttack(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const raw = input.raw || '';
  
  // Look for incinerator or burn patterns
  const incineratorPatterns = [
    /incinerator|burn.*address|dead.*address/i,
    /1nc1nerator11111111111111111111111111111111/,
    /burn.*token|token.*burn/i,
  ];
  
  for (const pattern of incineratorPatterns) {
    if (pattern.test(raw)) {
      // Check if there's proper NFT ownership validation
      if (/nft|token.*id|mint.*id/i.test(raw)) {
        findings.push({
          id: 'SOL685',
          name: 'Incinerator NFT Attack Pattern',
          severity: 'high',
          description: 'Sending NFTs to incinerator addresses without proper validation can be exploited through attack chaining. The Schrodinger NFT attack combined multiple small vulnerabilities.',
          location: 'Incinerator/burn pattern in NFT context',
          recommendation: 'Implement comprehensive ownership validation before any burn operations. Consider using locked vaults instead of incinerator addresses.'
        });
        break;
      }
    }
  }
  
  return findings;
}

// SOL686: Semantic Inconsistency (Stake Pool)
// Reference: https://www.sec3.dev/blog/solana-stake-pool-a-semantic-inconsistency-vulnerability
export function checkSemanticInconsistency(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const raw = input.raw || '';
  
  // Look for stake pool or delegation patterns
  const stakePatterns = [
    /stake_pool|staking.*pool/i,
    /delegate.*stake|stake.*delegate/i,
    /validator.*stake|stake.*validator/i,
  ];
  
  for (const pattern of stakePatterns) {
    if (pattern.test(raw)) {
      // Check for state consistency patterns
      const hasAtomicUpdate = /atomic|transaction.*batch|single.*tx/i.test(raw);
      const hasConsistencyCheck = /state.*consistent|consistent.*state|verify.*state/i.test(raw);
      
      if (!hasAtomicUpdate && !hasConsistencyCheck) {
        findings.push({
          id: 'SOL686',
          name: 'Semantic Inconsistency in Stake Operations',
          severity: 'high',
          description: 'Stake pool operations without atomic updates or consistency checks can lead to semantic inconsistencies. The Stake Pool vulnerability showed even audited code can have these issues.',
          location: 'Stake operations without consistency guarantees',
          recommendation: 'Ensure all stake operations are atomic or include explicit consistency validation. Test edge cases where operations partially complete.'
        });
        break;
      }
    }
  }
  
  return findings;
}

// SOL687: Token Approval Revocation Missing
// Reference: https://2501babe.github.io/tools/revoken.html
export function checkTokenApprovalRevocation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const raw = input.raw || '';
  
  // Look for approve patterns
  const approvePatterns = [
    /approve\s*\(|spl_token::instruction::approve/i,
    /delegate.*amount|set_authority/i,
  ];
  
  for (const pattern of approvePatterns) {
    if (pattern.test(raw)) {
      // Check if there's revocation logic
      const hasRevocation = /revoke|set_authority.*None|delegate.*0/i.test(raw);
      
      if (!hasRevocation) {
        findings.push({
          id: 'SOL687',
          name: 'Missing Token Approval Revocation',
          severity: 'medium',
          description: 'Token approvals without corresponding revocation can leave lingering permissions. Users may forget to revoke approvals, leaving funds at risk.',
          location: 'Approve without revocation pattern',
          recommendation: 'Implement automatic revocation after operations complete. Provide clear UI for users to manage and revoke approvals.'
        });
        break;
      }
    }
  }
  
  return findings;
}

// SOL688: Checked Math Not Used (BlockSec)
// Reference: https://blocksecteam.medium.com/new-integer-overflow-bug-discovered-in-solana-rbpf
export function checkCheckedMathNotUsed(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const raw = input.raw || '';
  
  // Look for unchecked arithmetic
  const uncheckedPatterns = [
    /[^_](\+|-|\*|\/)\s*=?\s*[^=]/g,
    /\.wrapping_add|\.wrapping_sub|\.wrapping_mul/g,
  ];
  
  let hasUncheckedMath = false;
  for (const pattern of uncheckedPatterns) {
    const matches = raw.match(pattern);
    if (matches && matches.length > 3) { // More than a few uses
      hasUncheckedMath = true;
      break;
    }
  }
  
  if (hasUncheckedMath) {
    // Check for checked math usage
    const checkedPatterns = /checked_add|checked_sub|checked_mul|checked_div|saturating_/i;
    if (!checkedPatterns.test(raw)) {
      findings.push({
        id: 'SOL688',
        name: 'Checked Math Not Used (BlockSec Pattern)',
        severity: 'high',
        description: 'Arithmetic operations without checked_* or saturating_* functions can overflow. BlockSec discovered integer overflow bugs in Solana rBPF itself.',
        location: 'Unchecked arithmetic operations detected',
        recommendation: 'Use checked_add(), checked_sub(), checked_mul(), checked_div() for all arithmetic. Consider saturating_* for safe underflow/overflow handling.'
      });
    }
  }
  
  return findings;
}

// SOL689: Drift Protocol Oracle Guardrails Missing
// Reference: https://github.com/drift-labs/protocol-v1/blob/4c2d447a677693da506e4de9596a07e4b9ba4d5d/tests/admin.ts#L212
export function checkDriftOracleGuardrails(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const raw = input.raw || '';
  
  // Look for oracle usage
  const oraclePatterns = [
    /oracle.*price|price.*oracle/i,
    /pyth|switchboard|chainlink/i,
    /get_price|fetch_price|price_feed/i,
  ];
  
  for (const pattern of oraclePatterns) {
    if (pattern.test(raw)) {
      // Check for guardrails
      const hasConfidenceCheck = /confidence|conf_interval|deviation/i.test(raw);
      const hasStalenessCheck = /stale|last_update|age.*check|timestamp.*check/i.test(raw);
      const hasBoundsCheck = /max_price|min_price|price_bounds|sanity.*check/i.test(raw);
      
      if (!hasConfidenceCheck || !hasStalenessCheck || !hasBoundsCheck) {
        const missing = [];
        if (!hasConfidenceCheck) missing.push('confidence');
        if (!hasStalenessCheck) missing.push('staleness');
        if (!hasBoundsCheck) missing.push('bounds');
        
        findings.push({
          id: 'SOL689',
          name: 'Missing Oracle Guardrails (Drift Pattern)',
          severity: 'high',
          description: `Oracle usage missing ${missing.join(', ')} checks. Drift Protocol implements comprehensive oracle guardrails to prevent manipulation.`,
          location: 'Oracle usage without guardrails',
          recommendation: 'Implement oracle guardrails: confidence interval checks, staleness validation, and price bounds. Reference Drift Protocol implementation.'
        });
        break;
      }
    }
  }
  
  return findings;
}

// SOL690: Mango Markets Price Manipulation
// Reference: Mango Markets $116M exploit
export function checkMangoMarketsPattern(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const raw = input.raw || '';
  
  // Look for perp/leveraged trading patterns
  const perpPatterns = [
    /perp|perpetual|leverage|margin/i,
    /open_interest|position_size/i,
    /liquidation_price|mark_price/i,
  ];
  
  for (const pattern of perpPatterns) {
    if (pattern.test(raw)) {
      // Check for manipulation protections
      const hasOiLimit = /open_interest.*limit|max_position|position.*cap/i.test(raw);
      const hasLiquidityCheck = /liquidity.*check|depth.*check|slippage.*limit/i.test(raw);
      
      if (!hasOiLimit || !hasLiquidityCheck) {
        findings.push({
          id: 'SOL690',
          name: 'Mango Markets Style Price Manipulation Risk',
          severity: 'critical',
          description: 'Perpetual/leveraged trading without open interest limits or liquidity checks can enable price manipulation attacks. Mango Markets lost $116M.',
          location: 'Leveraged trading without manipulation protection',
          recommendation: 'Implement: open interest caps, position size limits relative to liquidity, oracle-based mark prices with guardrails, and funding rate mechanisms.'
        });
        break;
      }
    }
  }
  
  return findings;
}

// SOL691: Solend Reserve Config Bypass
// Reference: Solend malicious lending market incident
export function checkSolendReserveBypass(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const raw = input.raw || '';
  
  // Look for lending/reserve configuration
  const lendingPatterns = [
    /reserve.*config|lending.*market/i,
    /collateral.*factor|ltv.*ratio/i,
    /liquidation.*threshold|borrow.*limit/i,
  ];
  
  for (const pattern of lendingPatterns) {
    if (pattern.test(raw)) {
      // Check for authority validation
      const hasAuthorityCheck = /authority.*check|admin.*only|require.*owner/i.test(raw);
      const hasConfigValidation = /validate.*config|config.*bounds|sanity.*config/i.test(raw);
      
      if (!hasAuthorityCheck || !hasConfigValidation) {
        findings.push({
          id: 'SOL691',
          name: 'Lending Reserve Configuration Bypass',
          severity: 'critical',
          description: 'Lending markets without proper authority checks or config validation can be exploited by creating malicious markets. Reference: Solend incident report.',
          location: 'Lending config without proper validation',
          recommendation: 'Validate all reserve configurations against bounds. Require proper authority for config changes. Implement timelocks for sensitive parameters.'
        });
        break;
      }
    }
  }
  
  return findings;
}

// SOL692: Kudelski Ownership Check Pattern
// Reference: Kudelski Solana Program Security research
export function checkKudelskiOwnershipPattern(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const raw = input.raw || '';
  
  // Check for account processing without owner verification
  const accountAccessPattern = /account\.(data|try_borrow_data|try_borrow_mut_data)/gi;
  const ownerCheckPattern = /\.owner\s*==|is_owned_by|owner\.key\(\)/i;
  
  const accessMatches = raw.match(accountAccessPattern);
  if (accessMatches && accessMatches.length > 0) {
    if (!ownerCheckPattern.test(raw)) {
      findings.push({
        id: 'SOL692',
        name: 'Missing Ownership Check (Kudelski Pattern)',
        severity: 'critical',
        description: 'Account data access without ownership verification allows malicious accounts. Kudelski research highlights this as fundamental Solana security.',
        location: `${accessMatches.length} account access(es) without owner check`,
        recommendation: 'Always verify account.owner == expected_program_id before deserializing or trusting account data. Use Anchor constraints where possible.'
      });
    }
  }
  
  return findings;
}

// SOL693: Sec3 Audit Common Findings
// Reference: Sec3 2025 Report - 1,669 vulnerabilities analyzed
export function checkSec3AuditCommonFindings(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const raw = input.raw || '';
  
  // Business Logic (38.5% of all findings)
  const businessLogicPatterns = [
    { pattern: /transfer.*fee.*0|fee.*=\s*0/i, name: 'Zero Fee Edge Case' },
    { pattern: /balance.*<.*0|negative.*balance/i, name: 'Negative Balance Risk' },
    { pattern: /infinite.*loop|while\s*\(\s*true\s*\)/i, name: 'Infinite Loop Risk' },
  ];
  
  for (const { pattern, name } of businessLogicPatterns) {
    if (pattern.test(raw)) {
      findings.push({
        id: 'SOL693',
        name: `Business Logic Flaw: ${name}`,
        severity: 'high',
        description: `Sec3 2025 report shows business logic flaws account for 38.5% of all vulnerabilities. Detected: ${name}`,
        location: `Business logic pattern: ${name}`,
        recommendation: 'Review all business logic paths. Test edge cases including zero values, maximum values, and boundary conditions.'
      });
      break;
    }
  }
  
  return findings;
}

// SOL694: Trail of Bits DeFi Security Pattern
// Reference: Trail of Bits DeFi security research
export function checkTrailOfBitsDefiPattern(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const raw = input.raw || '';
  
  // Check for common DeFi vulnerabilities
  const defiPatterns = [
    /flash.*loan.*attack|atomic.*arbitrage/i,
    /governance.*attack|proposal.*spam/i,
    /oracle.*front.*run|front.*run.*oracle/i,
  ];
  
  for (const pattern of defiPatterns) {
    if (pattern.test(raw)) {
      findings.push({
        id: 'SOL694',
        name: 'DeFi Security Anti-Pattern (Trail of Bits)',
        severity: 'high',
        description: 'Detected pattern associated with DeFi attacks identified by Trail of Bits research.',
        location: 'DeFi attack vector detected',
        recommendation: 'Review Trail of Bits DeFi security guidelines. Implement flash loan guards, governance timelocks, and oracle manipulation protection.'
      });
      break;
    }
  }
  
  return findings;
}

// SOL695: Zellic Anchor Vulnerability Pattern
// Reference: https://www.zellic.io/blog/the-vulnerabilities-youll-write-with-anchor/
export function checkZellicAnchorVulnerability(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const raw = input.raw || '';
  
  // Check for Anchor-specific vulnerabilities from Zellic
  const anchorVulns = [
    { pattern: /init_if_needed/i, name: 'init_if_needed Race Condition' },
    { pattern: /#\[account\(mut\)\].*without.*signer/i, name: 'Mutable Without Signer' },
    { pattern: /remaining_accounts.*iter/i, name: 'Unchecked Remaining Accounts' },
  ];
  
  for (const { pattern, name } of anchorVulns) {
    if (pattern.test(raw)) {
      findings.push({
        id: 'SOL695',
        name: `Zellic Anchor Pattern: ${name}`,
        severity: 'high',
        description: `Zellic research identified this as a common Anchor vulnerability: ${name}`,
        location: `Anchor pattern: ${name}`,
        recommendation: 'Review Zellic\'s "Vulnerabilities You\'ll Write With Anchor" article. Use proper constraints and avoid dangerous patterns.'
      });
      break;
    }
  }
  
  return findings;
}

// SOL696: OtterSec Audit Methodology Pattern
// Reference: OtterSec public audits and methodology
export function checkOttersecAuditPattern(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const raw = input.raw || '';
  
  // OtterSec commonly finds these patterns
  const ottersecPatterns = [
    { pattern: /ProgramError::Custom\(\d+\)/g, name: 'Generic Error Codes' },
    { pattern: /unwrap\(\)|expect\(/g, name: 'Unsafe Unwrap Usage' },
    { pattern: /todo!|unimplemented!/g, name: 'Unimplemented Code Paths' },
  ];
  
  for (const { pattern, name } of ottersecPatterns) {
    const matches = raw.match(pattern);
    if (matches && matches.length > 2) {
      findings.push({
        id: 'SOL696',
        name: `OtterSec Finding: ${name}`,
        severity: 'medium',
        description: `OtterSec audits commonly flag this pattern: ${name}. Found ${matches.length} instances.`,
        location: `${matches.length} instances of ${name}`,
        recommendation: 'Use descriptive error types, handle errors explicitly with match or ?, and implement all code paths before deployment.'
      });
      break;
    }
  }
  
  return findings;
}

export const patterns677to696 = [
  checkNeodymeRoundingAttack,
  checkJetBreakStatementBug,
  checkCopeRouletteExploit,
  checkSimulationDetectionBypass,
  checkRootOfTrustChainValidation,
  checkUncheckedAccountDocumentation,
  checkLpTokenOracleManipulation,
  checkSignatureSetFabrication,
  checkIncineratorNftAttack,
  checkSemanticInconsistency,
  checkTokenApprovalRevocation,
  checkCheckedMathNotUsed,
  checkDriftOracleGuardrails,
  checkMangoMarketsPattern,
  checkSolendReserveBypass,
  checkKudelskiOwnershipPattern,
  checkSec3AuditCommonFindings,
  checkTrailOfBitsDefiPattern,
  checkZellicAnchorVulnerability,
  checkOttersecAuditPattern,
];
