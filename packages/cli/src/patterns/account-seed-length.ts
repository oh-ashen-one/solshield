import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL128: Account Seed Length
 * Detects PDA seed length issues
 */
export function checkAccountSeedLength(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;

  if (!rust || !rust.content) return findings;

  // Check for potentially long seeds
  if (rust.content.includes('seeds') && rust.content.includes('as_bytes()')) {
    if (rust.content.includes('String') || rust.content.includes('string')) {
      findings.push({
        id: 'SOL128',
        severity: 'medium',
        title: 'Variable Length Seed',
        description: 'Using string as PDA seed - max seed length is 32 bytes',
        location: input.path,
        recommendation: 'Validate string length <= 32 bytes or use hash',
      });
    }
  }

  return findings;
}
