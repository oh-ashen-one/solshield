import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL062: Compute Budget Issues
 * Operations that may exceed compute limits.
 */
export function checkComputeBudget(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (!input.rust || !input.rust.files) return findings;

  for (const file of input.rust.files) {
    const lines = file.lines;

    lines.forEach((line, index) => {
      const lineNum = index + 1;

      // Pattern 1: Nested loops
      if (line.includes('for ') || line.includes('while ')) {
        const fnStart = Math.max(0, index - 20);
        const preceding = lines.slice(fnStart, index).join('\n');

        if (preceding.includes('for ') || preceding.includes('while ')) {
          findings.push({
            id: `SOL062-${findings.length + 1}`,
            pattern: 'Compute Budget Issue',
            severity: 'high',
            title: 'Nested loops detected',
            description: 'Nested loops multiply compute cost. May exceed budget.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Flatten loops or add strict iteration limits.',
          });
        }
      }

      // Pattern 2: Heavy cryptographic operations
      if (line.includes('verify') || line.includes('hash') || line.includes('sign')) {
        const contextStart = Math.max(0, index - 10);
        const context = lines.slice(contextStart, index + 5).join('\n');

        if (context.includes('for') || context.includes('while') || context.includes('iter')) {
          findings.push({
            id: `SOL062-${findings.length + 1}`,
            pattern: 'Compute Budget Issue',
            severity: 'high',
            title: 'Cryptographic operation in loop',
            description: 'Crypto ops are expensive. Multiple in loop may exceed compute.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Batch verify or limit iterations.',
          });
        }
      }

      // Pattern 3: Large memory allocation
      if (line.includes('vec![') || line.includes('Vec::with_capacity')) {
        const sizeMatch = line.match(/with_capacity\s*\(\s*(\d+)/);
        if (sizeMatch && parseInt(sizeMatch[1]) > 10000) {
          findings.push({
            id: `SOL062-${findings.length + 1}`,
            pattern: 'Compute Budget Issue',
            severity: 'medium',
            title: 'Large vector allocation',
            description: 'Large memory allocation increases compute cost.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Process in smaller batches if possible.',
          });
        }
      }
    });
  }

  return findings;
}
