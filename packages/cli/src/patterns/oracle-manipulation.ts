import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL018: Oracle Manipulation Risk
 * Price oracles can be manipulated - use TWAPs, multiple sources, staleness checks.
 */
export function checkOracleManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (!input.rust || !input.rust.files) return findings;

  const oracleKeywords = ['oracle', 'price_feed', 'pyth', 'switchboard', 'chainlink', 'get_price', 'PriceFeed'];

  for (const file of input.rust.files) {
    const lines = file.lines;
    const reportedBlocks = new Set<number>();

    lines.forEach((line, index) => {
      const lineNum = index + 1;
      const lineLower = line.toLowerCase();

      const usesOracle = oracleKeywords.some(kw => lineLower.includes(kw.toLowerCase()));

      if (usesOracle) {
        const block = Math.floor(index / 15);
        if (reportedBlocks.has(block)) return;

        const contextStart = Math.max(0, index - 20);
        const contextEnd = Math.min(lines.length, index + 20);
        const context = lines.slice(contextStart, contextEnd).join('\n').toLowerCase();

        const issues: string[] = [];

        // Staleness check
        if (!context.includes('stale') && !context.includes('timestamp') &&
            !context.includes('last_update') && !context.includes('valid_slot')) {
          issues.push('missing staleness check');
        }

        // TWAP or multiple sources
        if (!context.includes('twap') && !context.includes('average')) {
          issues.push('no TWAP/averaging (single price point)');
        }

        // Confidence (Pyth)
        if (context.includes('pyth') && !context.includes('conf')) {
          issues.push('Pyth without confidence interval check');
        }

        if (issues.length > 0) {
          reportedBlocks.add(block);
          findings.push({
            id: `SOL018-${findings.length + 1}`,
            pattern: 'Oracle Manipulation Risk',
            severity: 'high',
            title: 'Oracle usage without manipulation protections',
            description: `Oracle data used without adequate protections: ${issues.join(', ')}.`,
            location: { file: file.path, line: lineNum },
            suggestion: 'Add staleness checks, use TWAP/multiple oracles, and validate confidence intervals.',
          });
        }
      }
    });
  }

  return findings;
}
