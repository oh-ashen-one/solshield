import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL116: Account Data Matching
 * Detects mismatches between expected and actual account data
 */
export function checkAccountDataMatch(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;

  if (!rust || !rust.content) return findings;

  // Check for data length assumptions
  if (rust.content.includes('.data') && rust.content.includes('len()')) {
    if (!rust.content.includes('>=') && !rust.content.includes('==')) {
      findings.push({
        id: 'SOL116',
        severity: 'medium',
        title: 'Data Length Not Validated',
        description: 'Accessing data length without comparison to expected size',
        location: input.path,
        recommendation: 'Verify data.len() >= expected_size before accessing',
      });
    }
  }

  // Check for slice access without bounds
  const sliceAccess = /data\[(\d+)\.\.(\d+)?\]/;
  if (sliceAccess.test(rust.content) && !rust.content.includes('.get(')) {
    findings.push({
      id: 'SOL116',
      severity: 'high',
      title: 'Unbounded Slice Access',
      description: 'Slicing data without bounds checking may panic',
      location: input.path,
      recommendation: 'Use .get(start..end) for safe slice access',
    });
  }

  return findings;
}
