import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL103: Anchor CPI Safety
 * Detects issues specific to Anchor CPI patterns
 */
export function checkAnchorCpiSafety(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;

  if (!rust || !rust.content) return findings;

  if (!rust.content.includes('CpiContext')) return findings;

  // Check for CPI without account validation
  if (rust.content.includes('CpiContext::new') && !rust.content.includes('constraint')) {
    const cpiCount = (rust.content.match(/CpiContext::new/g) || []).length;
    if (cpiCount > 2) {
      findings.push({
        id: 'SOL103',
        severity: 'medium',
        title: 'Multiple CPIs Without Constraints',
        description: `${cpiCount} CPI calls - ensure all target accounts are validated`,
        location: input.path,
        recommendation: 'Add account constraints to validate CPI targets',
      });
    }
  }

  // Check for CPI with_signer without seeds validation
  if (rust.content.includes('new_with_signer') && !rust.content.includes('seeds =')) {
    findings.push({
      id: 'SOL103',
      severity: 'high',
      title: 'CPI with_signer Without Seeds Constraint',
      description: 'Using CPI with signer seeds but no seeds constraint for validation',
      location: input.path,
      recommendation: 'Add seeds constraint to validate PDA used in CPI',
    });
  }

  return findings;
}
