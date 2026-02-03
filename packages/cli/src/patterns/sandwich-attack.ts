import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL064: Sandwich Attack Vulnerability
 * Operations vulnerable to MEV sandwich attacks.
 */
export function checkSandwichAttack(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (!input.rust || !input.rust.files) return findings;

  for (const file of input.rust.files) {
    const lines = file.lines;
    const content = file.content;

    // Skip if no swap/trade operations
    if (!content.includes('swap') && !content.includes('trade') && !content.includes('exchange')) {
      continue;
    }

    lines.forEach((line, index) => {
      const lineNum = index + 1;

      // Pattern 1: Price-impacting operation without deadline
      if (line.includes('swap') || line.includes('trade')) {
        const fnEnd = Math.min(lines.length, index + 25);
        const fnBody = lines.slice(index, fnEnd).join('\n');

        if (!fnBody.includes('deadline') && !fnBody.includes('expir') && 
            !fnBody.includes('valid_until')) {
          findings.push({
            id: `SOL064-${findings.length + 1}`,
            pattern: 'Sandwich Attack Vulnerability',
            severity: 'high',
            title: 'Swap without deadline',
            description: 'No transaction deadline. Attacker can delay and sandwich.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Add deadline: require!(Clock::get()?.unix_timestamp <= deadline)',
          });
        }
      }

      // Pattern 2: Large trade without price impact check
      if ((line.includes('amount') || line.includes('size')) && 
          content.includes('swap')) {
        const contextStart = Math.max(0, index - 10);
        const context = lines.slice(contextStart, index + 10).join('\n');

        if (!context.includes('impact') && !context.includes('max_') && 
            !context.includes('limit') && context.includes('pool')) {
          findings.push({
            id: `SOL064-${findings.length + 1}`,
            pattern: 'Sandwich Attack Vulnerability',
            severity: 'medium',
            title: 'Trade without price impact limit',
            description: 'Large trades without max price impact could be exploited.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Add max price impact: require!(impact <= MAX_IMPACT_BPS)',
          });
        }
      }

      // Pattern 3: Using spot price for valuation
      if (line.includes('price') && !line.includes('twap') && !line.includes('oracle')) {
        const contextStart = Math.max(0, index - 5);
        const context = lines.slice(contextStart, index + 5).join('\n');

        if (context.includes('value') || context.includes('worth') || context.includes('collateral')) {
          findings.push({
            id: `SOL064-${findings.length + 1}`,
            pattern: 'Sandwich Attack Vulnerability',
            severity: 'high',
            title: 'Spot price used for valuation',
            description: 'Using spot price for collateral/value. Can be manipulated.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Use TWAP or oracle price for valuations.',
          });
        }
      }
    });
  }

  return findings;
}
