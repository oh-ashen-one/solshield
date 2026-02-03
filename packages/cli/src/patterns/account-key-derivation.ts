import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL106: Account Key Derivation
 * Detects issues with how account keys are derived or compared
 */
export function checkAccountKeyDerivation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;

  if (!rust || !rust.content) return findings;

  // Check for Pubkey::new_from_array with user input
  if (rust.content.includes('Pubkey::new_from_array') || rust.content.includes('Pubkey::new(')) {
    if (!rust.content.includes('const') && !rust.content.includes('CONST')) {
      findings.push({
        id: 'SOL106',
        severity: 'high',
        title: 'Dynamic Pubkey Construction',
        description: 'Creating Pubkey from array at runtime - verify source is trusted',
        location: input.path,
        recommendation: 'Use declared constants or PDAs instead of dynamic construction',
      });
    }
  }

  // Check for key comparison issues
  if (rust.content.includes('.key()') && rust.content.includes('==')) {
    // Check for comparing with wrong account
    const keyCompare = /(\w+)\.key\(\)\s*==\s*(\w+)\.key\(\)/g;
    let match;
    while ((match = keyCompare.exec(rust.content)) !== null) {
      if (match[1] === match[2]) {
        findings.push({
          id: 'SOL106',
          severity: 'medium',
          title: 'Self Key Comparison',
          description: 'Comparing account key with itself - always true',
          location: input.path,
          recommendation: 'Verify this comparison is intentional',
        });
      }
    }
  }

  // Check for missing key validation in account structs
  if (rust.content.includes('#[account') && !rust.content.includes('key =')) {
    if (rust.content.includes('/// CHECK:')) {
      findings.push({
        id: 'SOL106',
        severity: 'medium',
        title: 'Unchecked Account Without Key Constraint',
        description: 'CHECK account should use key = constraint when possible',
        location: input.path,
        recommendation: 'Add key = expected_pubkey constraint for explicit validation',
      });
    }
  }

  return findings;
}
