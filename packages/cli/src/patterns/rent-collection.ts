import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL113: Rent Collection Security
 * Detects issues with rent/lamport collection patterns
 */
export function checkRentCollection(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;

  if (!rust || !rust.content) return findings;

  // Check for rent collection to wrong destination
  if (rust.content.includes('close') || rust.content.includes('sub_lamports')) {
    // Ensure lamports go to validated destination
    if (!rust.content.includes('authority') && !rust.content.includes('owner')) {
      findings.push({
        id: 'SOL113',
        severity: 'high',
        title: 'Rent Collection Destination Not Validated',
        description: 'Account rent/lamports sent to potentially unvalidated destination',
        location: input.path,
        recommendation: 'Verify rent recipient is the intended authority/owner',
      });
    }
  }

  // Check for rent collection in CPI
  if (rust.content.includes('invoke') && rust.content.includes('lamports')) {
    findings.push({
      id: 'SOL113',
      severity: 'medium',
      title: 'Lamport Transfer in CPI',
      description: 'Transferring lamports via CPI - ensure destination is controlled',
      location: input.path,
      recommendation: 'Verify lamport destination account before CPI',
    });
  }

  return findings;
}
