import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL019: Flash Loan Vulnerability
 * State checks vulnerable to same-transaction manipulation.
 */
export function checkFlashLoan(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (!input.rust || !input.rust.files) return findings;

  const sensitivePatterns = [
    { pattern: /collateral.*ratio|ratio.*collateral/i, desc: 'collateral ratio check' },
    { pattern: /borrow|lending|loan/i, desc: 'lending operation' },
    { pattern: /liquidat/i, desc: 'liquidation logic' },
    { pattern: /get_price.*swap|swap.*price/i, desc: 'price-dependent swap' },
  ];

  for (const file of input.rust.files) {
    const lines = file.lines;

    lines.forEach((line, index) => {
      const lineNum = index + 1;

      for (const { pattern, desc } of sensitivePatterns) {
        if (pattern.test(line)) {
          const contextStart = Math.max(0, index - 30);
          const contextEnd = Math.min(lines.length, index + 30);
          const context = lines.slice(contextStart, contextEnd).join('\n').toLowerCase();

          const hasProtection =
            (context.includes('slot') && context.includes('last_update')) ||
            context.includes('reentrancy') ||
            context.includes('locked') ||
            (context.includes('commit') && context.includes('reveal')) ||
            context.includes('cooldown');

          if (!hasProtection) {
            findings.push({
              id: `SOL019-${findings.length + 1}`,
              pattern: 'Flash Loan Vulnerability',
              severity: 'critical',
              title: `${desc} may be flash-loan exploitable`,
              description: `The ${desc} could be manipulated via flash loan attack where an attacker borrows funds, manipulates state, and repays in the same transaction.`,
              location: { file: file.path, line: lineNum },
              suggestion: 'Implement slot-based checks, commit-reveal patterns, or cooldown periods to prevent same-transaction manipulation.',
            });
            return; // Only one finding per sensitive pattern per file
          }
        }
      }
    });
  }

  return findings;
}
