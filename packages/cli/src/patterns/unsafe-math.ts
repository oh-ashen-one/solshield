import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL020: Unsafe Arithmetic Operations
 * Division by zero, lossy casts, precision loss in financial math.
 */
export function checkUnsafeMath(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (!input.rust || !input.rust.files) return findings;

  for (const file of input.rust.files) {
    const lines = file.lines;

    lines.forEach((line, index) => {
      const lineNum = index + 1;

      // Division without zero check
      if ((line.includes(' / ') || line.includes('/=')) && !line.includes('checked_div')) {
        const contextStart = Math.max(0, index - 5);
        const context = lines.slice(contextStart, index + 1).join('\n');

        if (!context.includes('!= 0') && !context.includes('> 0') && !context.includes('require!')) {
          findings.push({
            id: `SOL020-${findings.length + 1}`,
            pattern: 'Unsafe Arithmetic',
            severity: 'high',
            title: 'Division without zero-check',
            description: 'Division operation without validating divisor is non-zero.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Use checked_div or validate divisor != 0 before division.',
          });
        }
      }

      // Lossy casts to smaller types
      const lossyCasts = [/as u8(?!\d)/, /as u16(?!\d)/, /as u32(?!\d)/, /as i8(?!\d)/, /as i16(?!\d)/];
      for (const castPattern of lossyCasts) {
        if (castPattern.test(line)) {
          const contextStart = Math.max(0, index - 3);
          const context = lines.slice(contextStart, index + 1).join('\n');

          if (!context.includes('try_into') && !context.includes('try_from') &&
              !context.includes('min(') && !context.includes('clamp(')) {
            findings.push({
              id: `SOL020-${findings.length + 1}`,
              pattern: 'Unsafe Arithmetic',
              severity: 'medium',
              title: 'Potentially lossy integer cast',
              description: 'Casting to smaller integer type may truncate value silently.',
              location: { file: file.path, line: lineNum },
              suggestion: 'Use try_into() with error handling or clamp values before casting.',
            });
            break;
          }
        }
      }

      // Precision loss: division before multiplication
      if ((line.includes('/ 100') || line.includes('/ 10000')) && !line.includes('* ')) {
        findings.push({
          id: `SOL020-${findings.length + 1}`,
          pattern: 'Unsafe Arithmetic',
          severity: 'medium',
          title: 'Precision loss in calculation',
          description: 'Division before multiplication causes precision loss. In integer math, (a/100)*b != (a*b)/100.',
          location: { file: file.path, line: lineNum },
          suggestion: 'Multiply first, then divide to preserve precision.',
        });
      }

      // Unchecked pow
      if (line.includes('.pow(') && !line.includes('checked_pow') && !line.includes('saturating_pow')) {
        findings.push({
          id: `SOL020-${findings.length + 1}`,
          pattern: 'Unsafe Arithmetic',
          severity: 'high',
          title: 'Unchecked exponentiation',
          description: 'pow() can overflow silently. Use checked_pow or saturating_pow.',
          location: { file: file.path, line: lineNum },
          suggestion: 'Replace .pow() with .checked_pow() or .saturating_pow().',
        });
      }
    });
  }

  return findings;
}
