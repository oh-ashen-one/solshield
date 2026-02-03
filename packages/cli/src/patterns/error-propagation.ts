import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL105: Error Propagation
 * Detects issues with error handling and propagation
 */
export function checkErrorPropagation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;

  if (!rust || !rust.content) return findings;

  // Check for unwrap() usage
  const unwrapCount = (rust.content.match(/\.unwrap\(\)/g) || []).length;
  if (unwrapCount > 3) {
    findings.push({
      id: 'SOL105',
      severity: 'medium',
      title: 'Excessive unwrap() Usage',
      description: `${unwrapCount} unwrap() calls - panics on None/Err`,
      location: input.path,
      recommendation: 'Use ok_or(), map_err(), or ? operator instead',
    });
  }

  // Check for expect() with poor messages
  const expectPoor = /\.expect\s*\(\s*""\s*\)|\.expect\s*\(\s*"error"\s*\)/i;
  if (expectPoor.test(rust.content)) {
    findings.push({
      id: 'SOL105',
      severity: 'low',
      title: 'Poor Error Message in expect()',
      description: 'expect() with empty or generic message',
      location: input.path,
      recommendation: 'Use descriptive error messages for debugging',
    });
  }

  // Check for swallowed errors
  const swallowed = /if\s+let\s+Err\s*\(\s*_\s*\)\s*=|\.ok\(\s*\)\s*;/;
  if (swallowed.test(rust.content)) {
    findings.push({
      id: 'SOL105',
      severity: 'high',
      title: 'Swallowed Error',
      description: 'Error result discarded without handling or logging',
      location: input.path,
      recommendation: 'Log or handle errors explicitly, or propagate with ?',
    });
  }

  return findings;
}
