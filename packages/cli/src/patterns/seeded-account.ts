import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL026: Seeded Account Vulnerabilities
 * Issues with PDA derivation and seed management.
 */
export function checkSeededAccount(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (!input.rust || !input.rust.files) return findings;

  for (const file of input.rust.files) {
    const lines = file.lines;

    lines.forEach((line, index) => {
      const lineNum = index + 1;

      // Pattern 1: User-controlled seed without length validation
      if (line.includes('seeds =') || line.includes('seeds:')) {
        const contextStart = Math.max(0, index - 3);
        const contextEnd = Math.min(lines.length, index + 3);
        const context = lines.slice(contextStart, contextEnd).join('\n');

        if ((context.includes('.as_bytes()') || context.includes('as_ref()')) &&
            !context.includes('.len()') && !context.includes('MAX_')) {
          findings.push({
            id: `SOL026-${findings.length + 1}`,
            pattern: 'Seeded Account Vulnerability',
            severity: 'medium',
            title: 'Variable-length seed without size validation',
            description: 'PDA seed from user input without length check. Could cause unexpected seed collisions or exceed seed limits.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Validate seed length: max 32 bytes per seed, max 16 seeds total. Use fixed-size seeds when possible.',
          });
        }
      }

      // Pattern 2: Predictable seeds enabling front-running
      if (line.includes('find_program_address') || line.includes('create_program_address')) {
        const contextStart = Math.max(0, index - 10);
        const context = lines.slice(contextStart, index + 1).join('\n');

        // Check if seeds are entirely public/predictable
        const hasSecretSeed = context.includes('secret') || context.includes('nonce') || 
                              context.includes('random') || context.includes('hash');
        const isInitOrCreate = context.includes('init') || context.includes('create');

        if (isInitOrCreate && !hasSecretSeed && 
            (context.includes('mint.key') || context.includes('user.key'))) {
          findings.push({
            id: `SOL026-${findings.length + 1}`,
            pattern: 'Seeded Account Vulnerability',
            severity: 'low',
            title: 'Predictable PDA seeds may enable front-running',
            description: 'PDA creation with entirely predictable seeds. An attacker could front-run and create the PDA first.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Consider adding commitment schemes or using less predictable initialization patterns.',
          });
        }
      }

      // Pattern 3: Missing constraint on seeds match
      if (line.includes('#[account(') && line.includes('seeds =')) {
        const contextEnd = Math.min(lines.length, index + 5);
        const constraint = lines.slice(index, contextEnd).join(' ');

        if (!constraint.includes('bump') && !constraint.includes('bump =')) {
          findings.push({
            id: `SOL026-${findings.length + 1}`,
            pattern: 'Seeded Account Vulnerability',
            severity: 'medium',
            title: 'PDA seeds without bump constraint',
            description: 'Account with seeds constraint but no bump. Anchor may not verify PDA derivation correctly.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Add bump constraint: #[account(seeds = [...], bump)]',
          });
        }
      }
    });
  }

  return findings;
}
