import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL089: Account Type Safety
 * Detects type confusion and unsafe account casting
 */
export function checkAccountTypeSafety(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;

  if (!rust || !rust.content) return findings;

  // Check for AccountInfo without type constraints
  const rawAccountInfo = /AccountInfo<'info>\s*,?\s*(?:\/\/|$)/;
  if (rawAccountInfo.test(rust.content)) {
    // Check if it's being used unsafely
    if (rust.content.includes('.data') || rust.content.includes('.lamports')) {
      findings.push({
        id: 'SOL089',
        severity: 'high',
        title: 'Raw AccountInfo Usage',
        description: 'Using raw AccountInfo without type constraints - vulnerable to type confusion',
        location: input.path,
        recommendation: 'Use typed Account<T> wrappers or add explicit type checks',
      });
    }
  }

  // Check for unsafe transmute/casting
  if (rust.content.includes('transmute') || rust.content.includes('as *const') || 
      rust.content.includes('as *mut')) {
    findings.push({
      id: 'SOL089',
      severity: 'critical',
      title: 'Unsafe Memory Transmute',
      description: 'Using unsafe transmute/pointer casting - can cause memory corruption',
      location: input.path,
      recommendation: 'Use safe deserialization methods instead of transmute',
    });
  }

  // Check for from_account_info without checks
  if (rust.content.includes('from_account_info')) {
    if (!rust.content.includes('discriminator') && !rust.content.includes('AccountDeserialize')) {
      findings.push({
        id: 'SOL089',
        severity: 'high',
        title: 'Unchecked from_account_info',
        description: 'Deserializing account without type discriminator check',
        location: input.path,
        recommendation: 'Use Anchor Account<T> which validates discriminator automatically',
      });
    }
  }

  // Check for multiple account types with same structure
  const accountStructs = rust.content.match(/#\[account\]\s*pub\s+struct\s+\w+/g) || [];
  if (accountStructs.length >= 2) {
    // Check if any have similar field patterns
    findings.push({
      id: 'SOL089',
      severity: 'low',
      title: 'Multiple Account Types',
      description: 'Multiple account structs - ensure discriminators prevent type confusion',
      location: input.path,
      recommendation: 'Anchor auto-generates unique discriminators per struct name',
    });
  }

  // Check for UncheckedAccount usage
  if (rust.content.includes('UncheckedAccount') || rust.content.includes('/// CHECK:')) {
    const uncheckedCount = (rust.content.match(/UncheckedAccount|\/\/\/ CHECK:/g) || []).length;
    if (uncheckedCount > 2) {
      findings.push({
        id: 'SOL089',
        severity: 'medium',
        title: 'Multiple Unchecked Accounts',
        description: `${uncheckedCount} unchecked accounts - increases attack surface`,
        location: input.path,
        recommendation: 'Minimize UncheckedAccount usage; add explicit validation for each',
      });
    }
  }

  // Check for Box<Account> patterns
  if (rust.content.includes('Box<Account')) {
    if (!rust.content.includes('zero_copy')) {
      findings.push({
        id: 'SOL089',
        severity: 'low',
        title: 'Boxed Account Not Zero-Copy',
        description: 'Using Box<Account> without zero_copy may cause unnecessary copies',
        location: input.path,
        recommendation: 'Consider #[account(zero_copy)] for large accounts',
      });
    }
  }

  // Check for loader patterns
  if (rust.content.includes('AccountLoader') || rust.content.includes('Loader')) {
    if (!rust.content.includes('load_mut') && rust.content.includes('load()')) {
      // Using load() when modification might be needed
      if (rust.content.includes('fn ') && rust.content.includes('mut')) {
        findings.push({
          id: 'SOL089',
          severity: 'medium',
          title: 'AccountLoader Loaded Immutably in Mutable Context',
          description: 'Using load() but context suggests mutation may be needed',
          location: input.path,
          recommendation: 'Use load_mut() if the account will be modified',
        });
      }
    }
  }

  return findings;
}
