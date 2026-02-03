import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL108: Associated Program Security
 * Detects issues with associated program usage (ATA, etc.)
 */
export function checkAssociatedProgram(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;

  if (!rust || !rust.content) return findings;

  // Check for associated_token program validation
  if (rust.content.includes('associated_token') && !rust.content.includes('::ID')) {
    findings.push({
      id: 'SOL108',
      severity: 'high',
      title: 'Associated Token Program Not Validated',
      description: 'Using associated_token without verifying program ID',
      location: input.path,
      recommendation: 'Verify associated_token_program.key() == associated_token::ID',
    });
  }

  // Check for create_associated_token_account usage
  if (rust.content.includes('create_associated_token_account') || 
      rust.content.includes('CreateAssociatedTokenAccount')) {
    if (!rust.content.includes('if ') && !rust.content.includes('match')) {
      findings.push({
        id: 'SOL108',
        severity: 'low',
        title: 'ATA Creation Without Existence Check',
        description: 'Creating ATA without checking if it exists first',
        location: input.path,
        recommendation: 'Use init_if_needed or check account existence first',
      });
    }
  }

  return findings;
}
