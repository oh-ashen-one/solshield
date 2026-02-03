import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL068: Anchor Constraint Validation
 * Detects missing or insufficient Anchor constraints
 */
export function checkConstraintValidation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;

  if (!rust || !rust.content) return findings;

  // Check for Account without constraints
  const accountWithoutConstraint = /#\[account\(\s*\)\]/;
  if (accountWithoutConstraint.test(rust.content)) {
    findings.push({
      id: 'SOL068',
      severity: 'medium',
      title: 'Empty Account Constraint',
      description: 'Account defined with empty constraint block provides no validation',
      location: input.path,
      recommendation: 'Add appropriate constraints like mut, has_one, seeds, or constraint checks',
    });
  }

  // Check for init without space
  if (rust.content.includes('#[account(init') && !rust.content.includes('space')) {
    findings.push({
      id: 'SOL068',
      severity: 'high',
      title: 'Init Without Space Constraint',
      description: 'Account initialization without explicit space constraint may cause issues',
      location: input.path,
      recommendation: 'Always specify space = 8 + <struct_size> for initialized accounts',
    });
  }

  // Check for has_one without corresponding field validation
  const hasOneMatch = /#\[account\([^)]*has_one\s*=\s*(\w+)/g;
  let match;
  while ((match = hasOneMatch.exec(rust.content)) !== null) {
    const fieldName = match[1];
    // Check if the field is actually a public key field
    const fieldDef = new RegExp(`pub\\s+${fieldName}\\s*:\\s*(Pubkey|AccountInfo|Account)`);
    if (!fieldDef.test(rust.content)) {
      findings.push({
        id: 'SOL068',
        severity: 'medium',
        title: 'Suspicious has_one Constraint',
        description: `has_one constraint on '${fieldName}' may not reference a valid pubkey field`,
        location: input.path,
        recommendation: 'Ensure has_one references a Pubkey field that exists in the account struct',
      });
    }
  }

  // Check for mut without signer on critical operations
  const mutWithoutSigner = /#\[account\(\s*mut\s*\)]\s*(?:pub\s+)?\w+\s*:\s*(?:Account|AccountInfo)/g;
  if (mutWithoutSigner.test(rust.content)) {
    // Check if function has any signer account
    const fnBlock = rust.content.match(/pub\s+fn\s+\w+[\s\S]*?#\[account\(\s*mut\s*\)]/);
    if (fnBlock && !fnBlock[0].includes('Signer') && !fnBlock[0].includes('signer')) {
      findings.push({
        id: 'SOL068',
        severity: 'high',
        title: 'Mutable Account Without Signer Check',
        description: 'Mutable account modification without any signer validation in context',
        location: input.path,
        recommendation: 'Add a signer constraint or has_one to validate who can modify the account',
      });
    }
  }

  // Check for seeds without bump
  if (rust.content.includes('seeds =') && !rust.content.includes('bump')) {
    findings.push({
      id: 'SOL068',
      severity: 'high',
      title: 'Seeds Without Bump Constraint',
      description: 'PDA seeds defined without bump constraint - vulnerable to bump seed manipulation',
      location: input.path,
      recommendation: 'Always include bump constraint when using seeds for PDA validation',
    });
  }

  // Check for close without proper target
  if (rust.content.includes('close') && rust.content.includes('#[account(')) {
    const closeWithoutTarget = /#\[account\([^)]*close\s*(?!\s*=)/;
    if (closeWithoutTarget.test(rust.content)) {
      findings.push({
        id: 'SOL068',
        severity: 'critical',
        title: 'Close Constraint Without Target',
        description: 'Close constraint without specifying recipient - lamports may be lost',
        location: input.path,
        recommendation: 'Specify close target: close = recipient_account',
      });
    }
  }

  // Check for realloc without proper constraints
  if (rust.content.includes('realloc')) {
    if (!rust.content.includes('realloc::payer') || !rust.content.includes('realloc::zero')) {
      findings.push({
        id: 'SOL068',
        severity: 'medium',
        title: 'Incomplete Realloc Constraints',
        description: 'Realloc used without specifying payer or zero initialization',
        location: input.path,
        recommendation: 'Include realloc::payer and realloc::zero = true/false constraints',
      });
    }
  }

  return findings;
}
