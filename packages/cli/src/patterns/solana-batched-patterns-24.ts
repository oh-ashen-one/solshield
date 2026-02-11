/**
 * SolShield Security Patterns SOL717-SOL736 (20 patterns)
 * Based on Sec3 2025 Report + Real Exploits
 * Focus: Access Control & Authorization (19% of all vulns)
 */

import type { Finding } from '../commands/audit.js';
import type { ParsedIdl } from '../parsers/idl.js';
import type { ParsedRust } from '../parsers/rust.js';

interface PatternInput {
  idl?: ParsedIdl;
  rust?: ParsedRust;
  raw?: string;
}

// SOL717: Role-Based Access Control Missing
export function checkRoleBasedAccessControl(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const raw = input.raw || '';
  
  // Look for admin/privileged functions
  const adminFunctions = [
    /fn\s+(admin_|set_|update_|emergency_|pause_|unpause_)/gi,
    /fn\s+\w*(config|setting|param|fee|authority|owner)/gi,
  ];
  
  let hasAdminFunctions = false;
  for (const pattern of adminFunctions) {
    if (pattern.test(raw)) {
      hasAdminFunctions = true;
      break;
    }
  }
  
  if (hasAdminFunctions) {
    // Check for role-based access
    const hasRBAC = /role|permission|capability|has_role|is_admin|access_control/i.test(raw);
    
    if (!hasRBAC) {
      findings.push({
        id: 'SOL717',
        name: 'Missing Role-Based Access Control',
        severity: 'high',
        description: 'Admin functions without role-based access control use simple owner checks which create single points of failure.',
        location: 'Admin functions without RBAC',
        recommendation: 'Implement role-based access control with separation of duties. Use multiple roles (admin, operator, upgrader) with different permissions.'
      });
    }
  }
  
  return findings;
}

// SOL718: Hardcoded Admin Address
export function checkHardcodedAdminAddress(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const raw = input.raw || '';
  
  // Look for hardcoded pubkeys that might be admin addresses
  const hardcodedPubkey = /Pubkey::new_from_array\s*\(\s*\[[\d\s,]+\]\s*\)|declare_id!\s*\(\s*"[A-Za-z0-9]{43,44}"\s*\)/gi;
  
  if (hardcodedPubkey.test(raw)) {
    // Check if it's used as admin
    if (/admin|authority|owner/i.test(raw)) {
      findings.push({
        id: 'SOL718',
        name: 'Hardcoded Admin Address',
        severity: 'medium',
        description: 'Hardcoded admin addresses cannot be rotated if compromised and require program upgrades to change.',
        location: 'Hardcoded admin pubkey detected',
        recommendation: 'Store admin addresses in updateable account state. Implement admin rotation mechanisms with timelocks.'
      });
    }
  }
  
  return findings;
}

// SOL719: Missing Multisig for Critical Operations
export function checkMissingMultisigCritical(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const raw = input.raw || '';
  
  // Look for critical operations
  const criticalOps = [
    /upgrade.*program|set.*upgrade.*authority/i,
    /emergency.*withdraw|drain|rescue/i,
    /set.*fee|change.*protocol.*param/i,
    /transfer.*ownership|set.*owner/i,
  ];
  
  for (const pattern of criticalOps) {
    if (pattern.test(raw)) {
      // Check for multisig
      const hasMultisig = /multisig|multi.*sig|threshold.*sign|m.*of.*n/i.test(raw);
      
      if (!hasMultisig) {
        findings.push({
          id: 'SOL719',
          name: 'Missing Multisig for Critical Operation',
          severity: 'high',
          description: 'Critical operations (upgrades, emergency withdrawals, ownership transfers) should require multiple signatures.',
          location: 'Critical operation without multisig',
          recommendation: 'Use Squads or similar multisig program for critical operations. Implement at least 2-of-3 threshold for sensitive actions.'
        });
        break;
      }
    }
  }
  
  return findings;
}

// SOL720: Authority Delegation Chain Too Deep
export function checkAuthorityDelegationChain(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const raw = input.raw || '';
  
  // Look for delegation patterns
  const delegationPatterns = [
    /delegate|delegated.*authority/i,
    /sub_authority|derived.*authority/i,
    /proxy.*authority|forwarded.*auth/i,
  ];
  
  for (const pattern of delegationPatterns) {
    if (pattern.test(raw)) {
      // Check for depth limits
      const hasDepthLimit = /max.*delegation|delegation.*depth|delegation.*level/i.test(raw);
      
      if (!hasDepthLimit) {
        findings.push({
          id: 'SOL720',
          name: 'Authority Delegation Chain Depth Risk',
          severity: 'medium',
          description: 'Deep authority delegation chains make it harder to audit access and can hide unauthorized escalation.',
          location: 'Delegation without depth limit',
          recommendation: 'Limit delegation depth. Prefer direct authority grants over delegation chains. Audit all delegation paths.'
        });
        break;
      }
    }
  }
  
  return findings;
}

// SOL721: Missing Authority Expiry
export function checkMissingAuthorityExpiry(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const raw = input.raw || '';
  
  // Look for authority grants
  const authorityGrant = /grant.*authority|set.*authority|approve.*delegate/i;
  
  if (authorityGrant.test(raw)) {
    // Check for expiry
    const hasExpiry = /expiry|expires|valid_until|ttl|time_limit/i.test(raw);
    
    if (!hasExpiry) {
      findings.push({
        id: 'SOL721',
        name: 'Authority Grant Without Expiry',
        severity: 'medium',
        description: 'Authority grants without expiry remain valid indefinitely, increasing risk from compromised or stale permissions.',
        location: 'Authority grant without time limit',
        recommendation: 'Add expiry timestamps to authority grants. Require periodic renewal of permissions. Implement auto-revocation for stale authorities.'
      });
    }
  }
  
  return findings;
}

// SOL722: Signer Check Bypass via CPI
export function checkSignerBypassCpi(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const raw = input.raw || '';
  
  // Look for signer checks
  const signerCheck = /is_signer|require.*signer|Signer<'info>/i;
  const hasCpi = /invoke|invoke_signed|CpiContext/i;
  
  if (signerCheck.test(raw) && hasCpi.test(raw)) {
    // Check if CPI could bypass signer
    const hasSignerPropagation = /signer.*cpi|cpi.*signer|signed.*invoke/i.test(raw);
    
    if (!hasSignerPropagation) {
      findings.push({
        id: 'SOL722',
        name: 'Potential Signer Check Bypass via CPI',
        severity: 'high',
        description: 'Signer checks in calling program may not propagate correctly through CPI. Called program must independently verify signers.',
        location: 'Signer check with CPI calls',
        recommendation: 'Ensure called programs verify signers independently. Do not assume signer status propagates through CPI.'
      });
    }
  }
  
  return findings;
}

// SOL723: Owner Check on Derived Account
export function checkOwnerCheckDerivedAccount(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const raw = input.raw || '';
  
  // Look for PDA derivation
  const pdaPattern = /Pubkey::find_program_address|create_program_address/i;
  
  if (pdaPattern.test(raw)) {
    // Check for owner validation after derivation
    const hasOwnerCheck = /\.owner\s*==|is_owned_by|owner\.key\(\)/i.test(raw);
    
    if (!hasOwnerCheck) {
      findings.push({
        id: 'SOL723',
        name: 'Missing Owner Check on PDA',
        severity: 'critical',
        description: 'PDAs derived from seeds must still have their owner verified. Attacker could provide account with matching address but different owner.',
        location: 'PDA without owner verification',
        recommendation: 'Always verify the owner of PDA accounts matches your program ID before trusting the data.'
      });
    }
  }
  
  return findings;
}

// SOL724: Permission Escalation via Init
export function checkPermissionEscalationInit(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const raw = input.raw || '';
  
  // Look for init patterns
  const initPattern = /init_if_needed|#\[account\(init/i;
  
  if (initPattern.test(raw)) {
    // Check for reinit protection
    const hasReinitProtection = /is_initialized|already.*initialized|discriminator/i.test(raw);
    
    if (!hasReinitProtection) {
      findings.push({
        id: 'SOL724',
        name: 'Permission Escalation via Reinitialization',
        severity: 'critical',
        description: 'init_if_needed or similar patterns can allow reinitialization of accounts, potentially escalating attacker permissions.',
        location: 'Init pattern without reinit protection',
        recommendation: 'Always check if account is already initialized before init. Prefer init over init_if_needed. Use discriminators.'
      });
    }
  }
  
  return findings;
}

// SOL725: Unprotected Emergency Functions
export function checkUnprotectedEmergencyFunctions(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const raw = input.raw || '';
  
  // Look for emergency functions
  const emergencyPattern = /emergency|pause|freeze|halt|shutdown|kill_switch/i;
  
  if (emergencyPattern.test(raw)) {
    // Check for protection
    const hasProtection = /admin|owner|authority|multisig|governance/i.test(raw);
    const hasTimelock = /timelock|delay|cooldown/i.test(raw);
    
    if (!hasProtection) {
      findings.push({
        id: 'SOL725',
        name: 'Unprotected Emergency Function',
        severity: 'critical',
        description: 'Emergency functions without access control can be triggered by anyone, causing denial of service.',
        location: 'Emergency function without protection',
        recommendation: 'Protect emergency functions with proper access control. Consider timelock for non-critical emergencies.'
      });
    }
  }
  
  return findings;
}

// SOL726: Timelock Bypass via Parameter
export function checkTimelockBypassParameter(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const raw = input.raw || '';
  
  // Look for timelock
  const timelockPattern = /timelock|delay|wait_period|cooldown/i;
  
  if (timelockPattern.test(raw)) {
    // Check if delay is a parameter
    const delayIsParam = /fn.*delay\s*:|delay\s*:\s*u64/i.test(raw);
    const hasMinDelay = /MIN_DELAY|min_timelock|minimum.*delay/i.test(raw);
    
    if (delayIsParam && !hasMinDelay) {
      findings.push({
        id: 'SOL726',
        name: 'Timelock Bypass via Zero Delay',
        severity: 'critical',
        description: 'Timelocks with user-provided delay can be bypassed by setting delay to zero.',
        location: 'Timelock with parameterized delay',
        recommendation: 'Enforce minimum delay constants. Do not allow users to set delay values. Use hardcoded or governance-controlled delays.'
      });
    }
  }
  
  return findings;
}

// SOL727: Cross-Program Authority Confusion
export function checkCrossProgramAuthorityConfusion(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const raw = input.raw || '';
  
  // Look for CPI with authority
  const cpiAuthPattern = /invoke.*authority|CpiContext.*authority|authority.*invoke/i;
  
  if (cpiAuthPattern.test(raw)) {
    // Check for explicit authority validation
    const hasExplicitAuth = /validate.*authority|check.*authority.*match|authority\.key\(\)\s*==/i.test(raw);
    
    if (!hasExplicitAuth) {
      findings.push({
        id: 'SOL727',
        name: 'Cross-Program Authority Confusion',
        severity: 'high',
        description: 'Authority passed to CPI may not match expected authority. Malicious programs could accept any authority.',
        location: 'CPI authority without explicit validation',
        recommendation: 'Explicitly validate authority matches expected account before CPI. Do not trust called program to validate.'
      });
    }
  }
  
  return findings;
}

// SOL728: PDA Signer Seeds Mismatch
export function checkPdaSignerSeedsMismatch(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const raw = input.raw || '';
  
  // Look for invoke_signed
  const invokeSignedPattern = /invoke_signed\s*\(/i;
  
  if (invokeSignedPattern.test(raw)) {
    // Check for seed validation
    const hasSeedValidation = /seeds.*match|validate.*seeds|expected.*seeds/i.test(raw);
    
    if (!hasSeedValidation) {
      findings.push({
        id: 'SOL728',
        name: 'PDA Signer Seeds Validation Missing',
        severity: 'high',
        description: 'invoke_signed seeds must match the PDA derivation exactly. Mismatched seeds can sign for wrong accounts.',
        location: 'invoke_signed without seed validation',
        recommendation: 'Derive PDA and validate address matches before invoke_signed. Store canonical bump seeds in account data.'
      });
    }
  }
  
  return findings;
}

// SOL729: Account Ownership Transfer without Confirmation
export function checkOwnershipTransferConfirmation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const raw = input.raw || '';
  
  // Look for ownership transfer
  const transferPattern = /transfer.*owner|set.*owner|change.*owner|new.*owner/i;
  
  if (transferPattern.test(raw)) {
    // Check for two-step transfer
    const hasTwoStep = /pending.*owner|accept.*owner|confirm.*owner|claim.*owner/i.test(raw);
    
    if (!hasTwoStep) {
      findings.push({
        id: 'SOL729',
        name: 'Ownership Transfer Without Confirmation',
        severity: 'high',
        description: 'Single-step ownership transfers can lock out access if transferred to wrong address.',
        location: 'Direct ownership transfer without confirmation',
        recommendation: 'Implement two-step transfer: nominate new owner, then new owner accepts. This prevents accidental transfers to wrong addresses.'
      });
    }
  }
  
  return findings;
}

// SOL730: Insufficient Pause Protection
export function checkInsufficientPauseProtection(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const raw = input.raw || '';
  
  // Look for pausable functionality
  const pausePattern = /pause|paused|is_paused|when_not_paused/i;
  
  if (pausePattern.test(raw)) {
    // Check if pause affects all critical functions
    const criticalFunctions = raw.match(/fn\s+(withdraw|deposit|swap|transfer|liquidate)/gi);
    const pauseChecks = raw.match(/paused|is_paused/gi);
    
    if (criticalFunctions && pauseChecks) {
      // Rough check: should have pause check for each critical function
      if (pauseChecks.length < criticalFunctions.length) {
        findings.push({
          id: 'SOL730',
          name: 'Incomplete Pause Protection',
          severity: 'medium',
          description: 'Not all critical functions may be protected by pause. Attackers can exploit unpaused functions during emergency.',
          location: 'Pause may not cover all critical functions',
          recommendation: 'Ensure pause affects all user-facing critical functions. Review each function for pause protection.'
        });
      }
    }
  }
  
  return findings;
}

// SOL731: Governance Quorum Manipulation
export function checkGovernanceQuorumManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const raw = input.raw || '';
  
  // Look for governance
  const govPattern = /governance|proposal|vote|quorum/i;
  
  if (govPattern.test(raw)) {
    // Check for anti-manipulation
    const hasAntiManip = /snapshot|block.*height|checkpoint|locked.*voting/i.test(raw);
    
    if (!hasAntiManip) {
      findings.push({
        id: 'SOL731',
        name: 'Governance Quorum Manipulation Risk',
        severity: 'high',
        description: 'Governance without voting snapshots allows vote manipulation via flash loans or token transfers during voting.',
        location: 'Governance without snapshot',
        recommendation: 'Implement voting snapshots at proposal creation. Lock tokens during voting period. Require vote weight from past block.'
      });
    }
  }
  
  return findings;
}

// SOL732: Missing Function Selector Validation
export function checkMissingFunctionSelectorValidation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const raw = input.raw || '';
  
  // Look for instruction discriminator handling
  const discriminatorPattern = /instruction.*data|process_instruction|deserialize.*instruction/i;
  
  if (discriminatorPattern.test(raw)) {
    // Check for explicit variant matching
    const hasExplicitMatch = /match.*instruction|instruction.*type|discriminator.*check/i.test(raw);
    
    if (!hasExplicitMatch) {
      findings.push({
        id: 'SOL732',
        name: 'Missing Instruction Discriminator Validation',
        severity: 'high',
        description: 'Instructions without discriminator validation can be confused with other instruction types.',
        location: 'Instruction processing without discriminator check',
        recommendation: 'Use Anchor discriminators or explicitly validate instruction type bytes before processing.'
      });
    }
  }
  
  return findings;
}

// SOL733: Reentrancy via State Update Order
export function checkReentrancyStateUpdateOrder(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const raw = input.raw || '';
  
  // Look for CPI after state reads but before writes
  const pattern = /borrow\(\)[\s\S]*?invoke[\s\S]*?borrow_mut\(\)/i;
  
  if (pattern.test(raw)) {
    findings.push({
      id: 'SOL733',
      name: 'Reentrancy Risk: CPI Before State Update',
      severity: 'critical',
      description: 'CPI calls between state reads and writes enable reentrancy. Attacker can re-enter with stale state.',
      location: 'CPI between read and write operations',
      recommendation: 'Follow checks-effects-interactions pattern: validate, update state, then CPI. Never CPI before state updates complete.'
    });
  }
  
  return findings;
}

// SOL734: Token Account Authority Not Validated
export function checkTokenAccountAuthorityValidation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const raw = input.raw || '';
  
  // Look for token operations
  const tokenOp = /spl_token::instruction::|token::transfer|token::mint/i;
  
  if (tokenOp.test(raw)) {
    // Check for authority validation
    const hasAuthorityCheck = /authority\.key\(\)|authority.*==|validate.*authority|owner.*token/i.test(raw);
    
    if (!hasAuthorityCheck) {
      findings.push({
        id: 'SOL734',
        name: 'Token Account Authority Not Validated',
        severity: 'high',
        description: 'Token operations without validating the authority could allow unauthorized transfers.',
        location: 'Token operation without authority validation',
        recommendation: 'Always validate the token account authority/owner matches expected signer before token operations.'
      });
    }
  }
  
  return findings;
}

// SOL735: Upgrade Authority Not Restricted
export function checkUpgradeAuthorityRestriction(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const raw = input.raw || '';
  
  // Look for program upgrade patterns
  const upgradePattern = /upgrade.*authority|program.*data|bpf_loader/i;
  
  if (upgradePattern.test(raw)) {
    // Check for restrictions
    const hasRestriction = /multisig.*upgrade|timelock.*upgrade|governance.*upgrade|frozen/i.test(raw);
    
    if (!hasRestriction) {
      findings.push({
        id: 'SOL735',
        name: 'Upgrade Authority Not Restricted',
        severity: 'high',
        description: 'Single-key upgrade authority can unilaterally change program code, compromising user funds.',
        location: 'Program upgrade without restrictions',
        recommendation: 'Use multisig for upgrade authority. Implement timelocks. Consider freezing programs after audit.'
      });
    }
  }
  
  return findings;
}

// SOL736: Missing Event Emission on Authority Change
export function checkMissingEventAuthorityChange(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const raw = input.raw || '';
  
  // Look for authority changes
  const authChangePattern = /set.*authority|change.*owner|transfer.*admin|update.*config/i;
  
  if (authChangePattern.test(raw)) {
    // Check for event emission
    const hasEvent = /emit!|msg!.*author|log.*author|event.*author/i.test(raw);
    
    if (!hasEvent) {
      findings.push({
        id: 'SOL736',
        name: 'Missing Event on Authority Change',
        severity: 'medium',
        description: 'Authority changes without events are harder to monitor and audit. Unauthorized changes may go unnoticed.',
        location: 'Authority change without event emission',
        recommendation: 'Emit events for all authority and configuration changes. Include old and new values in events for auditability.'
      });
    }
  }
  
  return findings;
}

// Export with aliases for naming conflicts
export const checkAuthorityDelegationChainV2 = checkAuthorityDelegationChain;
export const checkMissingAuthorityExpiryV2 = checkMissingAuthorityExpiry;
export const checkTimelockBypassParameterV2 = checkTimelockBypassParameter;
export const checkGovernanceQuorumManipulationV2 = checkGovernanceQuorumManipulation;

export const patterns717to736 = [
  checkRoleBasedAccessControl,
  checkHardcodedAdminAddress,
  checkMissingMultisigCritical,
  checkAuthorityDelegationChain,
  checkMissingAuthorityExpiry,
  checkSignerBypassCpi,
  checkOwnerCheckDerivedAccount,
  checkPermissionEscalationInit,
  checkUnprotectedEmergencyFunctions,
  checkTimelockBypassParameter,
  checkCrossProgramAuthorityConfusion,
  checkPdaSignerSeedsMismatch,
  checkOwnershipTransferConfirmation,
  checkInsufficientPauseProtection,
  checkGovernanceQuorumManipulation,
  checkMissingFunctionSelectorValidation,
  checkReentrancyStateUpdateOrder,
  checkTokenAccountAuthorityValidation,
  checkUpgradeAuthorityRestriction,
  checkMissingEventAuthorityChange,
];
