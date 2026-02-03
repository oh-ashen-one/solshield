import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL075: Account Revival Attack
 * Detects vulnerabilities where closed accounts can be revived maliciously
 */
export function checkAccountRevival(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;

  if (!rust || !rust.content) return findings;

  // Check for account closing patterns
  const hasClosing = rust.content.includes('close') ||
                     rust.content.includes('set_lamports(0)') ||
                     rust.content.includes('sub_lamports');

  if (!hasClosing) return findings;

  // Check for close without data zeroing
  if (rust.content.includes('lamports') && rust.content.includes('0')) {
    const closesAccount = /(?:set_lamports\s*\(\s*0\s*\)|lamports\s*=\s*0|\*\*lamports[^;]*=\s*0)/;
    if (closesAccount.test(rust.content)) {
      // Check if data is zeroed
      if (!rust.content.includes('data.fill(0)') && 
          !rust.content.includes('data.borrow_mut().fill(0)') &&
          !rust.content.includes('realloc(0')) {
        findings.push({
          id: 'SOL075',
          severity: 'critical',
          title: 'Account Closed Without Data Zeroing',
          description: 'Account lamports zeroed but data remains - vulnerable to revival with same data',
          location: input.path,
          recommendation: 'Zero account data before closing: account.data.borrow_mut().fill(0)',
        });
      }

      // Check if account is reassigned to system program
      if (!rust.content.includes('assign') && 
          !rust.content.includes('system_program') &&
          !rust.content.includes('SystemProgram')) {
        findings.push({
          id: 'SOL075',
          severity: 'high',
          title: 'Account Closed Without Reassignment',
          description: 'Closed account not reassigned to system program - can be revived by same program',
          location: input.path,
          recommendation: 'Assign account to system_program::ID after closing',
        });
      }
    }
  }

  // Check for Anchor close constraint usage
  if (rust.content.includes('#[account(') && rust.content.includes('close')) {
    // Anchor's close constraint handles this properly, but check for manual close alongside
    if (rust.content.includes('lamports().borrow_mut()') || 
        rust.content.includes('set_lamports')) {
      findings.push({
        id: 'SOL075',
        severity: 'medium',
        title: 'Mixed Anchor Close and Manual Lamport Manipulation',
        description: 'Using both Anchor close constraint and manual lamport manipulation',
        location: input.path,
        recommendation: 'Use Anchor close constraint exclusively or manual approach exclusively',
      });
    }
  }

  // Check for reinitialization guards after close
  if (rust.content.includes('is_initialized') || rust.content.includes('initialized')) {
    // Look for close without setting initialized = false
    const closeWithoutFlag = /close|lamports\s*=\s*0[\s\S]*?(?!initialized\s*=\s*false)/;
    if (closeWithoutFlag.test(rust.content)) {
      if (!rust.content.includes('discriminator') && !rust.content.includes('AccountDiscriminator')) {
        findings.push({
          id: 'SOL075',
          severity: 'high',
          title: 'Close Without Resetting Initialized Flag',
          description: 'Account closed but initialized flag not explicitly cleared in data',
          location: input.path,
          recommendation: 'Set initialized = false or zero data before closing',
        });
      }
    }
  }

  // Check for same-slot revival vulnerability
  if (rust.content.includes('close') && rust.content.includes('init')) {
    // Same instruction/transaction could close and reinit
    findings.push({
      id: 'SOL075',
      severity: 'medium',
      title: 'Potential Same-Transaction Revival',
      description: 'Program has both close and init functionality - ensure atomic safety',
      location: input.path,
      recommendation: 'Ensure closed accounts cannot be reinitialized in same transaction',
    });
  }

  // Check for PDAs that could be recreated
  if (rust.content.includes('close') && rust.content.includes('find_program_address')) {
    if (!rust.content.includes('nonce') && !rust.content.includes('sequence')) {
      findings.push({
        id: 'SOL075',
        severity: 'medium',
        title: 'Closeable PDA Without Uniqueness',
        description: 'PDA can be closed and recreated with same seeds',
        location: input.path,
        recommendation: 'Include unique nonce/sequence in PDA seeds to prevent recreation',
      });
    }
  }

  // Check for rent reclaim patterns
  if (rust.content.includes('sub_lamports') && !rust.content.includes('minimum_balance')) {
    findings.push({
      id: 'SOL075',
      severity: 'medium',
      title: 'Lamport Withdrawal Without Rent Check',
      description: 'Withdrawing lamports may leave account in weird state (not closed, not rent-exempt)',
      location: input.path,
      recommendation: 'Either keep rent-exempt or fully close the account',
    });
  }

  return findings;
}
