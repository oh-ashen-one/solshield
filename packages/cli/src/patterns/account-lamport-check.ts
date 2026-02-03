import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL126: Account Lamport Checks
 * Detects issues with lamport balance validation
 */
export function checkAccountLamportCheck(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;

  if (!rust || !rust.content) return findings;

  // Check for lamport operations without validation
  if (rust.content.includes('lamports') && rust.content.includes('sub')) {
    if (!rust.content.includes('checked_sub') && !rust.content.includes('>=')) {
      findings.push({
        id: 'SOL126',
        severity: 'high',
        title: 'Unchecked Lamport Subtraction',
        description: 'Subtracting lamports without checking sufficient balance',
        location: input.path,
        recommendation: 'Use checked_sub or verify balance >= amount first',
      });
    }
  }

  return findings;
}
