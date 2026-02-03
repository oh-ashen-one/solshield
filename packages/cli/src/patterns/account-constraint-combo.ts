import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL120: Account Constraint Combinations
 * Detects problematic constraint combinations
 */
export function checkAccountConstraintCombo(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;

  if (!rust || !rust.content) return findings;

  if (!rust.content.includes('#[account(')) return findings;

  // Check for init + close in same struct (unusual)
  if (rust.content.includes('init') && rust.content.includes('close')) {
    // Check if in same derive context
    const structMatch = rust.content.match(/#\[derive[\s\S]*?struct\s+\w+[\s\S]*?\}/g) || [];
    for (const struct of structMatch) {
      if (struct.includes('init') && struct.includes('close')) {
        findings.push({
          id: 'SOL120',
          severity: 'medium',
          title: 'Init and Close in Same Context',
          description: 'Account struct has both init and close - unusual pattern',
          location: input.path,
          recommendation: 'Verify this is intentional lifecycle behavior',
        });
        break;
      }
    }
  }

  // Check for mut without any other constraints
  const mutOnly = /#\[account\(\s*mut\s*\)]/;
  if (mutOnly.test(rust.content)) {
    findings.push({
      id: 'SOL120',
      severity: 'high',
      title: 'Mutable Account Without Constraints',
      description: 'Account is mutable but has no validation constraints',
      location: input.path,
      recommendation: 'Add has_one, seeds, or constraint checks',
    });
  }

  return findings;
}
