import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL111: Account Discriminator Validation
 * Detects missing or improper discriminator checks on deserialization
 */
export function checkAccountDiscriminatorCheck(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;

  if (!rust || !rust.content) return findings;

  // Check for manual account loading without discriminator
  if (rust.content.includes('try_from_slice') && !rust.content.includes('DISCRIMINATOR')) {
    if (rust.content.includes('AccountInfo') && !rust.content.includes('[8..]')) {
      findings.push({
        id: 'SOL111',
        severity: 'critical',
        title: 'Deserialization Without Discriminator Skip',
        description: 'Deserializing account data without skipping 8-byte discriminator',
        location: input.path,
        recommendation: 'Use &data[8..] or Account<T> which handles discriminator automatically',
      });
    }
  }

  // Check for Account type with AccountInfo fallback
  if (rust.content.includes('Account<') && rust.content.includes('AccountInfo<')) {
    if (rust.content.includes('from_account_info')) {
      findings.push({
        id: 'SOL111',
        severity: 'medium',
        title: 'Mixed Account Types',
        description: 'Using both typed Account and raw AccountInfo - ensure consistent validation',
        location: input.path,
        recommendation: 'Prefer Account<T> for automatic discriminator validation',
      });
    }
  }

  return findings;
}
