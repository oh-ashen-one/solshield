import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL129: Token Decimal Handling
 * Detects issues with token decimal calculations
 */
export function checkTokenDecimalHandling(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;

  if (!rust || !rust.content) return findings;

  // Check for hardcoded decimals
  if (rust.content.includes('decimals') || rust.content.includes('10_u64.pow')) {
    if (rust.content.includes('6') || rust.content.includes('9')) {
      if (!rust.content.includes('mint.decimals')) {
        findings.push({
          id: 'SOL129',
          severity: 'medium',
          title: 'Hardcoded Token Decimals',
          description: 'Using hardcoded decimals instead of reading from mint',
          location: input.path,
          recommendation: 'Read decimals from mint.decimals for flexibility',
        });
      }
    }
  }

  return findings;
}
