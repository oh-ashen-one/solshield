import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL069: Rent Drain Attack
 * Detects vulnerabilities where attackers can drain lamports via rent manipulation
 */
export function checkRentDrain(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;

  if (!rust || !rust.content) return findings;

  // Check for lamport transfer without rent-exemption check
  const lamportTransfer = /\.sub_lamports\s*\(|lamports\(\)\.borrow_mut\(\)[\s\S]*?-=/;
  if (lamportTransfer.test(rust.content)) {
    if (!rust.content.includes('rent') && !rust.content.includes('minimum_balance')) {
      findings.push({
        id: 'SOL069',
        severity: 'high',
        title: 'Lamport Transfer Without Rent Check',
        description: 'Lamports transferred without ensuring rent-exemption is maintained',
        location: input.path,
        recommendation: 'Check remaining lamports >= Rent::get()?.minimum_balance(data_len) after transfer',
      });
    }
  }

  // Check for account closing patterns that may leave dust
  const closePattern = /lamports\s*=\s*0|set_lamports\(0\)|sub_lamports.*lamports\(\)/;
  if (closePattern.test(rust.content)) {
    // Check if data is also zeroed
    if (!rust.content.includes('data.fill(0)') && 
        !rust.content.includes('assign(&system_program') &&
        !rust.content.includes('realloc(0')) {
      findings.push({
        id: 'SOL069',
        severity: 'high',
        title: 'Incomplete Account Closure',
        description: 'Account lamports zeroed but data not cleared - vulnerable to revival attacks',
        location: input.path,
        recommendation: 'Zero account data and transfer ownership to system program when closing',
      });
    }
  }

  // Check for withdrawal functions without minimum balance
  const withdrawFn = /fn\s+withdraw[\s\S]*?sub_lamports|fn\s+claim[\s\S]*?sub_lamports/;
  if (withdrawFn.test(rust.content)) {
    if (!rust.content.includes('checked_sub') && !rust.content.includes('minimum_balance')) {
      findings.push({
        id: 'SOL069',
        severity: 'medium',
        title: 'Withdrawal Without Minimum Balance',
        description: 'Withdrawal function may drain account below rent-exemption threshold',
        location: input.path,
        recommendation: 'Implement minimum_balance check or use checked_sub with explicit rent handling',
      });
    }
  }

  // Check for rent exemption calculation issues
  if (rust.content.includes('minimum_balance')) {
    // Check if using hardcoded data length
    const hardcodedRent = /minimum_balance\s*\(\s*\d+\s*\)/;
    if (hardcodedRent.test(rust.content)) {
      findings.push({
        id: 'SOL069',
        severity: 'low',
        title: 'Hardcoded Rent Calculation',
        description: 'Rent minimum balance calculated with hardcoded data length',
        location: input.path,
        recommendation: 'Use actual account data length: account.data_len() for accurate rent calculation',
      });
    }
  }

  // Check for realloc that could reduce rent exemption
  if (rust.content.includes('realloc')) {
    const unsafeRealloc = /realloc\s*\([^)]*,\s*false\s*\)/;
    if (unsafeRealloc.test(rust.content)) {
      if (!rust.content.includes('add_lamports') && !rust.content.includes('payer')) {
        findings.push({
          id: 'SOL069',
          severity: 'medium',
          title: 'Realloc Without Rent Adjustment',
          description: 'Account reallocation may require additional lamports for rent exemption',
          location: input.path,
          recommendation: 'Ensure sufficient lamports are added when increasing account size',
        });
      }
    }
  }

  return findings;
}
