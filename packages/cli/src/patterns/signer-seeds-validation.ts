import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL109: Signer Seeds Validation
 * Detects issues with PDA signer seeds construction
 */
export function checkSignerSeedsValidation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;

  if (!rust || !rust.content) return findings;

  if (!rust.content.includes('signer_seeds') && !rust.content.includes('invoke_signed')) {
    return findings;
  }

  // Check for signer seeds with user input
  if (rust.content.includes('signer_seeds') && rust.content.includes('instruction_data')) {
    findings.push({
      id: 'SOL109',
      severity: 'high',
      title: 'Signer Seeds From Instruction Data',
      description: 'PDA signer seeds include raw instruction data - may be exploitable',
      location: input.path,
      recommendation: 'Derive seeds from validated account state, not raw input',
    });
  }

  // Check for empty signer seeds
  const emptySeeds = /signer_seeds\s*=\s*&\[\s*&\[\s*\]\s*\]/;
  if (emptySeeds.test(rust.content)) {
    findings.push({
      id: 'SOL109',
      severity: 'critical',
      title: 'Empty Signer Seeds',
      description: 'invoke_signed with empty seeds - PDA cannot sign',
      location: input.path,
      recommendation: 'Provide correct seeds for PDA signing',
    });
  }

  return findings;
}
