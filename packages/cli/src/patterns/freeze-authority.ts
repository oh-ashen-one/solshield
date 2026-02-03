import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL017: Missing Freeze Authority Check
 * Token operations should verify freeze authority and frozen status.
 */
export function checkFreezeAuthority(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (!input.rust || !input.rust.files) return findings;

  for (const file of input.rust.files) {
    const lines = file.lines;

    lines.forEach((line, index) => {
      const lineNum = index + 1;

      // Token operations without freeze check
      if (line.includes('token::transfer') ||
          line.includes('token::mint_to') ||
          line.includes('token::burn') ||
          line.match(/Transfer\s*\{/) ||
          line.match(/MintTo\s*\{/) ||
          line.match(/Burn\s*\{/)) {

        const contextStart = Math.max(0, index - 15);
        const contextEnd = Math.min(lines.length, index + 5);
        const context = lines.slice(contextStart, contextEnd).join('\n');

        const hasCheck = context.includes('freeze_authority') ||
                        context.includes('is_frozen') ||
                        context.includes('frozen');

        if (!hasCheck) {
          findings.push({
            id: `SOL017-${findings.length + 1}`,
            pattern: 'Missing Freeze Authority Check',
            severity: 'medium',
            title: 'Token operation without freeze validation',
            description: 'Token transfer/mint/burn without checking if account is frozen or validating freeze authority.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Check is_frozen status and freeze_authority before token operations.',
          });
        }
      }

      // Freeze/thaw without authority check
      if (line.includes('FreezeAccount') || line.includes('ThawAccount')) {
        const contextStart = Math.max(0, index - 10);
        const context = lines.slice(contextStart, index + 1).join('\n');

        if (!context.includes('freeze_authority') && !context.includes('authority.key')) {
          findings.push({
            id: `SOL017-${findings.length + 1}`,
            pattern: 'Missing Freeze Authority Check',
            severity: 'high',
            title: 'Freeze/thaw without authority validation',
            description: 'Freeze or thaw operation without verifying freeze authority.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Validate freeze_authority before freeze/thaw operations.',
          });
        }
      }
    });
  }

  return findings;
}
