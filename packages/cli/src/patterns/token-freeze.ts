import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL117: Token Freeze Operations
 * Detects issues with token freeze/thaw operations
 */
export function checkTokenFreeze(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;

  if (!rust || !rust.content) return findings;

  if (!rust.content.includes('Freeze') && !rust.content.includes('freeze')) return findings;

  // Check for freeze without authority
  if (rust.content.includes('FreezeAccount') && !rust.content.includes('freeze_authority')) {
    findings.push({
      id: 'SOL117',
      severity: 'critical',
      title: 'Freeze Without Authority Check',
      description: 'Freezing token account without validating freeze authority',
      location: input.path,
      recommendation: 'Verify freeze_authority matches mint.freeze_authority',
    });
  }

  // Check for freeze in user-facing functions
  if (rust.content.includes('freeze') && 
      (rust.content.includes('pub fn') || rust.content.includes('#[instruction]'))) {
    findings.push({
      id: 'SOL117',
      severity: 'medium',
      title: 'User-Accessible Freeze Function',
      description: 'Freeze functionality exposed - ensure proper access control',
      location: input.path,
      recommendation: 'Restrict freeze to admin/authority only',
    });
  }

  return findings;
}
