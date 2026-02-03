import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL067: Remaining Accounts Security
 * Detects unsafe handling of remaining_accounts in Anchor
 */
export function checkRemainingAccounts(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;

  if (!rust || !rust.content) return findings;

  const hasRemainingAccounts = rust.content.includes('remaining_accounts') || 
                               rust.content.includes('ctx.remaining_accounts');

  if (!hasRemainingAccounts) return findings;

  // Check for unchecked iteration over remaining accounts
  if (rust.content.includes('remaining_accounts') && 
      !rust.content.includes('remaining_accounts.is_empty()') &&
      !rust.content.includes('remaining_accounts.len()')) {
    
    // Check if there's validation on remaining accounts
    const hasValidation = /remaining_accounts[\s\S]*?(key\s*==|owner\s*==|is_signer|is_writable)/;
    if (!hasValidation.test(rust.content)) {
      findings.push({
        id: 'SOL067',
        severity: 'critical',
        title: 'Unvalidated Remaining Accounts',
        description: 'Remaining accounts are used without validation of owner, key, or permissions',
        location: input.path,
        recommendation: 'Validate each remaining account\'s key, owner, and permissions before use',
      });
    }
  }

  // Check for direct trust of remaining accounts in CPI
  const cpiWithRemaining = /invoke[\s\S]*?remaining_accounts|remaining_accounts[\s\S]*?invoke/;
  if (cpiWithRemaining.test(rust.content)) {
    findings.push({
      id: 'SOL067',
      severity: 'high',
      title: 'Remaining Accounts in CPI',
      description: 'Remaining accounts passed to CPI without explicit validation',
      location: input.path,
      recommendation: 'Validate remaining accounts before passing to cross-program invocations',
    });
  }

  // Check for unsafe indexing into remaining accounts
  const unsafeIndex = /remaining_accounts\[\d+\]/;
  if (unsafeIndex.test(rust.content)) {
    if (!rust.content.includes('remaining_accounts.get(')) {
      findings.push({
        id: 'SOL067',
        severity: 'medium',
        title: 'Unsafe Remaining Accounts Indexing',
        description: 'Direct indexing into remaining_accounts can panic if index is out of bounds',
        location: input.path,
        recommendation: 'Use .get() method with proper error handling instead of direct indexing',
      });
    }
  }

  // Check for missing length check before access
  const accessWithoutLengthCheck = /remaining_accounts\[[\s\S]*?\]/;
  const hasLengthCheck = /remaining_accounts\.len\(\)\s*[><=]/;
  if (accessWithoutLengthCheck.test(rust.content) && !hasLengthCheck.test(rust.content)) {
    findings.push({
      id: 'SOL067',
      severity: 'medium',
      title: 'Missing Remaining Accounts Length Check',
      description: 'Accessing remaining_accounts without verifying expected length',
      location: input.path,
      recommendation: 'Check remaining_accounts.len() matches expected count before access',
    });
  }

  return findings;
}
