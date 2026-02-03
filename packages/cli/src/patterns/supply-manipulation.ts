import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL065: Supply Manipulation
 * Token supply manipulation vulnerabilities.
 */
export function checkSupplyManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (!input.rust || !input.rust.files) return findings;

  for (const file of input.rust.files) {
    const lines = file.lines;
    const content = file.content;

    lines.forEach((line, index) => {
      const lineNum = index + 1;

      // Pattern 1: Mint without cap
      if (line.includes('mint_to') || line.includes('MintTo')) {
        const contextStart = Math.max(0, index - 15);
        const context = lines.slice(contextStart, index + 10).join('\n');

        if (!context.includes('max_supply') && !context.includes('cap') && 
            !context.includes('MAX') && !context.includes('limit')) {
          findings.push({
            id: `SOL065-${findings.length + 1}`,
            pattern: 'Supply Manipulation',
            severity: 'high',
            title: 'Mint without supply cap',
            description: 'Tokens can be minted indefinitely. Could cause inflation.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Add supply cap: require!(supply + amount <= MAX_SUPPLY)',
          });
        }
      }

      // Pattern 2: Burn callable by non-owner
      if (line.includes('burn') || line.includes('Burn')) {
        const contextStart = Math.max(0, index - 10);
        const context = lines.slice(contextStart, index + 5).join('\n');

        if (!context.includes('owner') && !context.includes('authority') && 
            !context.includes('holder')) {
          findings.push({
            id: `SOL065-${findings.length + 1}`,
            pattern: 'Supply Manipulation',
            severity: 'high',
            title: 'Burn without ownership check',
            description: 'Anyone might be able to burn tokens from any account.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Verify: token account owner or delegated authority.',
          });
        }
      }

      // Pattern 3: Rebasing without accounting update
      if (line.includes('rebase') || line.includes('elastic')) {
        const fnEnd = Math.min(lines.length, index + 20);
        const fnBody = lines.slice(index, fnEnd).join('\n');

        if (!fnBody.includes('total') && !fnBody.includes('share') && 
            !fnBody.includes('ratio')) {
          findings.push({
            id: `SOL065-${findings.length + 1}`,
            pattern: 'Supply Manipulation',
            severity: 'critical',
            title: 'Rebase without proper accounting',
            description: 'Rebasing supply without updating share ratios.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Update all dependent calculations: shares, ratios, balances.',
          });
        }
      }

      // Pattern 4: Emission schedule manipulation
      if (line.includes('emission') || line.includes('schedule')) {
        const contextStart = Math.max(0, index - 5);
        const context = lines.slice(contextStart, index + 5).join('\n');

        if (context.includes('set') || context.includes('=')) {
          if (!context.includes('timelock') && !context.includes('governance')) {
            findings.push({
              id: `SOL065-${findings.length + 1}`,
              pattern: 'Supply Manipulation',
              severity: 'medium',
              title: 'Emission schedule changeable without timelock',
              description: 'Token emission can be changed immediately.',
              location: { file: file.path, line: lineNum },
              suggestion: 'Add timelock for emission schedule changes.',
            });
          }
        }
      }
    });
  }

  return findings;
}
