import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL027: Inadequate Error Handling
 * Missing or improper error handling in critical paths.
 */
export function checkErrorHandling(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (!input.rust || !input.rust.files) return findings;

  for (const file of input.rust.files) {
    const lines = file.lines;

    lines.forEach((line, index) => {
      const lineNum = index + 1;

      // Pattern 1: Unwrap on fallible operations
      if (line.includes('.unwrap()')) {
        // Check if it's in production code (not tests)
        if (!file.path.includes('test') && !line.includes('// test') && !line.includes('#[test]')) {
          findings.push({
            id: `SOL027-${findings.length + 1}`,
            pattern: 'Inadequate Error Handling',
            severity: 'medium',
            title: 'Using unwrap() in production code',
            description: 'unwrap() will panic on None/Err, potentially causing program failure.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Use proper error handling with ? operator or ok_or/ok_or_else for meaningful errors.',
          });
        }
      }

      // Pattern 2: expect() with unhelpful message
      if (line.includes('.expect(')) {
        const expectMatch = line.match(/\.expect\s*\(\s*["']([^"']*)/);
        if (expectMatch) {
          const message = expectMatch[1].toLowerCase();
          if (message.length < 10 || message === 'error' || message === 'failed' || 
              message === 'should not fail') {
            findings.push({
              id: `SOL027-${findings.length + 1}`,
              pattern: 'Inadequate Error Handling',
              severity: 'low',
              title: 'Unhelpful expect() message',
              description: 'expect() message should describe what went wrong and help debugging.',
              location: { file: file.path, line: lineNum },
              suggestion: 'Use descriptive error messages like "User token account must exist for withdrawal".',
            });
          }
        }
      }

      // Pattern 3: Swallowing errors with ok() or ignoring Result
      if (line.includes('.ok()') && !line.includes('.ok_or')) {
        const contextEnd = Math.min(lines.length, index + 3);
        const after = lines.slice(index, contextEnd).join('\n');
        
        if (after.includes(';') && !after.includes('if') && !after.includes('match')) {
          findings.push({
            id: `SOL027-${findings.length + 1}`,
            pattern: 'Inadequate Error Handling',
            severity: 'medium',
            title: 'Error swallowed with .ok()',
            description: 'Converting Result to Option discards error information. Silent failures are hard to debug.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Log the error before discarding, or propagate it with ? operator.',
          });
        }
      }

      // Pattern 4: Empty error variants
      if (line.includes('#[error_code]') || line.includes('#[error(')) {
        const contextEnd = Math.min(lines.length, index + 20);
        const errorBlock = lines.slice(index, contextEnd).join('\n');
        
        if (errorBlock.includes('GenericError') || errorBlock.includes('UnknownError')) {
          findings.push({
            id: `SOL027-${findings.length + 1}`,
            pattern: 'Inadequate Error Handling',
            severity: 'low',
            title: 'Generic error variant detected',
            description: 'Generic error codes make debugging difficult. Use specific error variants.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Replace generic errors with specific variants that describe what failed.',
          });
        }
      }
    });
  }

  return findings;
}
