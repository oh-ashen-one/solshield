import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL016: Bump Seed Canonicalization
 * PDAs should use canonical bump seeds from find_program_address.
 */
export function checkBumpSeed(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (!input.rust || !input.rust.files) return findings;

  for (const file of input.rust.files) {
    const lines = file.lines;

    lines.forEach((line, index) => {
      const lineNum = index + 1;

      // Pattern 1: create_program_address (should usually be find_program_address)
      if (line.includes('create_program_address') && !line.includes('find_program_address')) {
        if (line.includes('bump') || line.includes('ctx.accounts') || line.includes('args.')) {
          findings.push({
            id: `SOL016-${findings.length + 1}`,
            pattern: 'Bump Seed Canonicalization',
            severity: 'high',
            title: 'Non-canonical bump seed usage',
            description: `create_program_address with potentially user-controlled bump. Using non-canonical bumps allows attackers to create multiple valid PDAs for the same seeds.`,
            location: { file: file.path, line: lineNum },
            suggestion: 'Use find_program_address to derive the canonical bump, or validate the bump is canonical.',
          });
        }
      }

      // Pattern 2: Bump from user input without validation
      if ((line.includes('bump:') || line.includes('bump =')) &&
          (line.includes('ctx.accounts') || line.includes('args.') || line.includes('params.'))) {
        const contextStart = Math.max(0, index - 5);
        const contextEnd = Math.min(lines.length, index + 5);
        const context = lines.slice(contextStart, contextEnd).join('\n');

        if (!context.includes('find_program_address') && !context.includes('canonical')) {
          findings.push({
            id: `SOL016-${findings.length + 1}`,
            pattern: 'Bump Seed Canonicalization',
            severity: 'high',
            title: 'Unvalidated bump from user input',
            description: 'Bump seed appears to come from user input without canonical validation.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Derive bump using find_program_address or validate against canonical bump.',
          });
        }
      }
    });
  }

  return findings;
}
