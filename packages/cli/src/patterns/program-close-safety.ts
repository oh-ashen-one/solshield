import type { Finding } from '../commands/audit.js';
import type { ParsedRust } from '../parsers/rust.js';

/**
 * Program Close Safety Patterns
 * 
 * Based on OptiFi incident (Aug 2022) where accidental use of
 * "solana program close" permanently locked $661,000 in USDC.
 * 
 * Detects:
 * - Dangerous program close operations
 * - Missing close guards
 * - Unsafe PDA closure patterns
 * - Missing recovery mechanisms
 */

export function checkProgramCloseSafety(parsed: ParsedRust): Finding[] {
  const findings: Finding[] = [];
  const content = parsed.content;

  // Pattern 1: Dangerous program close without guards
  if (/program\s*close|close_program|solana\s+program\s+close/i.test(content)) {
    findings.push({
      id: 'PROGRAM_CLOSE_DANGEROUS',
      severity: 'critical',
      title: 'Dangerous Program Close Operation',
      description: 'Program close operations can permanently lock funds in PDAs. The OptiFi incident ($661K locked) shows the catastrophic impact of accidental program closure.',
      location: parsed.path,
      recommendation: 'Implement multi-sig requirements for program close operations. Add peer review for any deployment commands. Consider using upgradeable programs instead.'
    });
  }

  // Pattern 2: Account closure without fund recovery
  if (/close\s*=\s*\w+/.test(content) && !/close.*destination|close.*receiver|close.*recipient/i.test(content)) {
    const match = content.match(/close\s*=\s*(\w+)/);
    if (match) {
      findings.push({
        id: 'ACCOUNT_CLOSE_NO_DESTINATION',
        severity: 'high',
        title: 'Account Close Without Explicit Destination',
        description: 'Account being closed without explicit fund destination. Remaining lamports may be lost or sent to unintended recipient.',
        location: parsed.path,
        recommendation: 'Always specify explicit close destination for remaining funds. Verify destination is user-controlled.'
      });
    }
  }

  // Pattern 3: PDA closure with locked funds risk
  if (/close.*pda|close.*program_derived|pda.*close/i.test(content)) {
    if (!/recover|rescue|emergency.*withdraw/i.test(content)) {
      findings.push({
        id: 'PDA_CLOSE_NO_RECOVERY',
        severity: 'high',
        title: 'PDA Closure Without Recovery Mechanism',
        description: 'Closing PDAs without a recovery mechanism can permanently lock funds if the program is later closed or upgraded incorrectly.',
        location: parsed.path,
        recommendation: 'Implement emergency recovery functions for PDA funds. Add admin rescue capabilities with timelock.'
      });
    }
  }

  // Pattern 4: Missing deployment peer review
  if (/deploy|upgrade|program.*update/i.test(content)) {
    if (!/multisig|multi_sig|require.*signers?.*>=?\s*[23]|quorum/i.test(content)) {
      findings.push({
        id: 'DEPLOYMENT_NO_MULTISIG',
        severity: 'medium',
        title: 'Deployment Without Multi-Sig Requirement',
        description: 'Program deployment/upgrade without multi-sig could lead to accidental or malicious changes. OptiFi lost $661K due to single-person deployment error.',
        location: parsed.path,
        recommendation: 'Require multi-sig approval for all deployment operations. Implement peer-surveillance system with at least 3 reviewers.'
      });
    }
  }

  // Pattern 5: Close instruction without validation
  if (/pub\s+fn\s+close|fn\s+close_account|instruction.*close/i.test(content)) {
    if (!/require!|constraint|#\[account\(.*constraint/i.test(content)) {
      findings.push({
        id: 'CLOSE_INSTRUCTION_NO_VALIDATION',
        severity: 'high',
        title: 'Close Instruction Without Proper Validation',
        description: 'Close instruction implementation lacks validation constraints. Could allow unauthorized account closure.',
        location: parsed.path,
        recommendation: 'Add authority validation, ensure only authorized users can close accounts. Verify all funds are transferred before closure.'
      });
    }
  }

  // Pattern 6: Irreversible operations without confirmation
  if (/irreversible|permanent|cannot.*undo|non.*reversible/i.test(content)) {
    if (!/confirm|acknowledge|verify.*intent|double.*check/i.test(content)) {
      findings.push({
        id: 'IRREVERSIBLE_NO_CONFIRMATION',
        severity: 'medium',
        title: 'Irreversible Operation Without Confirmation',
        description: 'Irreversible operations should require explicit confirmation to prevent accidental execution.',
        location: parsed.path,
        recommendation: 'Implement two-step confirmation for irreversible operations. Add explicit acknowledgment requirements.'
      });
    }
  }

  // Pattern 7: Program data account risks
  if (/programdata|program.*data.*account|upgrade.*authority/i.test(content)) {
    if (!/protected|secured|validated/i.test(content)) {
      findings.push({
        id: 'PROGRAM_DATA_UNPROTECTED',
        severity: 'high',
        title: 'Program Data Account May Be Unprotected',
        description: 'Program data accounts control upgrade authority. If compromised or closed incorrectly, program becomes non-upgradeable.',
        location: parsed.path,
        recommendation: 'Protect program data account access. Consider using immutable programs for critical operations.'
      });
    }
  }

  return findings;
}
