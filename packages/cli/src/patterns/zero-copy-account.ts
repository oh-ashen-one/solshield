import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL118: Zero-Copy Account Handling
 * Detects issues with zero-copy account patterns
 */
export function checkZeroCopyAccount(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;

  if (!rust || !rust.content) return findings;

  if (!rust.content.includes('zero_copy') && !rust.content.includes('AccountLoader')) {
    return findings;
  }

  // Check for zero_copy without repr(C)
  if (rust.content.includes('#[account(zero_copy') && !rust.content.includes('#[repr(C)]')) {
    findings.push({
      id: 'SOL118',
      severity: 'high',
      title: 'Zero-Copy Without repr(C)',
      description: 'Zero-copy account requires #[repr(C)] for stable memory layout',
      location: input.path,
      recommendation: 'Add #[repr(C)] attribute to zero-copy account struct',
    });
  }

  // Check for load vs load_mut usage
  if (rust.content.includes('.load()') && rust.content.includes('.load_mut()')) {
    findings.push({
      id: 'SOL118',
      severity: 'low',
      title: 'Mixed Zero-Copy Load Methods',
      description: 'Using both load() and load_mut() - verify mutability requirements',
      location: input.path,
      recommendation: 'Use load_mut() only when modification is needed',
    });
  }

  return findings;
}
