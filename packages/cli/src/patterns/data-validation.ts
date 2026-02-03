import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL061: Data Validation Issues
 * Missing validation of account data integrity.
 */
export function checkDataValidation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (!input.rust || !input.rust.files) return findings;

  for (const file of input.rust.files) {
    const lines = file.lines;

    lines.forEach((line, index) => {
      const lineNum = index + 1;

      // Pattern 1: Account loaded without discriminator check
      if (line.includes('Account::try_from') || line.includes('AccountLoader')) {
        const contextStart = Math.max(0, index - 5);
        const context = lines.slice(contextStart, index + 5).join('\n');

        if (!context.includes('discriminator') && !context.includes('#[account]')) {
          findings.push({
            id: `SOL061-${findings.length + 1}`,
            pattern: 'Data Validation Issue',
            severity: 'high',
            title: 'Account loaded without discriminator validation',
            description: 'Manual account loading may skip discriminator check.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Verify discriminator: require!(data[0..8] == EXPECTED_DISCRIMINATOR)',
          });
        }
      }

      // Pattern 2: String/bytes without sanitization
      if ((line.includes('String') || line.includes('str')) && 
          (line.includes('from_utf8') || line.includes('to_string'))) {
        const contextStart = Math.max(0, index - 3);
        const context = lines.slice(contextStart, index + 3).join('\n');

        if (!context.includes('lossy') && !context.includes('valid') && 
            !context.includes('check')) {
          findings.push({
            id: `SOL061-${findings.length + 1}`,
            pattern: 'Data Validation Issue',
            severity: 'medium',
            title: 'String conversion without validation',
            description: 'Converting bytes to string without checking validity.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Use from_utf8_lossy or validate UTF-8 before conversion.',
          });
        }
      }

      // Pattern 3: Enum from integer without bounds
      if (line.includes('as ') && (line.includes('enum') || line.includes('Enum'))) {
        findings.push({
          id: `SOL061-${findings.length + 1}`,
          pattern: 'Data Validation Issue',
          severity: 'high',
          title: 'Enum cast from integer without validation',
          description: 'Casting integer to enum may create invalid variant.',
          location: { file: file.path, line: lineNum },
          suggestion: 'Use TryFrom or match to validate enum values.',
        });
      }
    });
  }

  return findings;
}
