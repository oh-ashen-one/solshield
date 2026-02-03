import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL110: Account Reallocation
 * Detects issues with account size reallocation
 */
export function checkAccountReallocation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;

  if (!rust || !rust.content) return findings;

  if (!rust.content.includes('realloc')) return findings;

  // Check for realloc with shrinking
  if (rust.content.includes('realloc') && rust.content.includes('<')) {
    findings.push({
      id: 'SOL110',
      severity: 'medium',
      title: 'Account Shrinking via Realloc',
      description: 'Shrinking account size may cause data truncation',
      location: input.path,
      recommendation: 'Ensure important data is preserved when shrinking',
    });
  }

  // Check for realloc without payer
  if (rust.content.includes('realloc =') && !rust.content.includes('realloc::payer')) {
    findings.push({
      id: 'SOL110',
      severity: 'high',
      title: 'Realloc Without Payer',
      description: 'Account reallocation may need additional lamports for rent',
      location: input.path,
      recommendation: 'Add realloc::payer for accounts that may grow',
    });
  }

  // Check for unbounded realloc
  if (rust.content.includes('realloc') && (rust.content.includes('len()') || rust.content.includes('size'))) {
    if (!rust.content.includes('MAX') && !rust.content.includes('max_')) {
      findings.push({
        id: 'SOL110',
        severity: 'high',
        title: 'Unbounded Reallocation',
        description: 'Realloc size not bounded - may exceed max account size',
        location: input.path,
        recommendation: 'Add maximum size check (Solana max: 10MB)',
      });
    }
  }

  return findings;
}
