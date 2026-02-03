import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL130: PDA Bump Storage
 * Detects issues with PDA bump seed storage and usage
 */
export function checkAccountPdaBumpStorage(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;

  if (!rust || !rust.content) return findings;

  // Check if bump is stored in account
  if (rust.content.includes('bump') && rust.content.includes('pub struct')) {
    if (!rust.content.includes('pub bump') && !rust.content.includes('bump:')) {
      findings.push({
        id: 'SOL130',
        severity: 'low',
        title: 'PDA Bump Not Stored',
        description: 'PDA bump not stored in account - must recompute each time',
        location: input.path,
        recommendation: 'Store bump in account struct to save compute units',
      });
    }
  }

  // Check for bump recomputation
  if (rust.content.includes('find_program_address') && !rust.content.includes('bump')) {
    findings.push({
      id: 'SOL130',
      severity: 'low',
      title: 'Bump Discarded',
      description: 'find_program_address called but bump not stored',
      location: input.path,
      recommendation: 'Store the bump for later use in invoke_signed',
    });
  }

  return findings;
}
