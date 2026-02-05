import type { Finding } from '../commands/audit.js';
import type { ParsedRust } from '../parsers/rust.js';

/**
 * Rounding Direction Attack
 * Based on: Neodyme's SPL Lending $2.6B vulnerability
 * 
 * Rounding errors in lending protocols can be exploited by:
 * 1. Depositing small amounts that round up
 * 2. Withdrawing amounts that round up
 * 3. Accumulating small gains through repeated operations
 * 
 * Rule: Always round in favor of the protocol, not the user.
 * - Deposits: round DOWN (user gets less shares)
 * - Withdrawals: round DOWN (user gets less tokens)
 * - Interest: round DOWN for borrower (borrower pays less - safer to under-collect)
 * - Collateral: round DOWN (user has less collateral)
 * - Debt: round UP (user owes more)
 */
export function checkRoundingDirectionAttack(parsed: ParsedRust): Finding[] {
  const findings: Finding[] = [];
  const content = parsed.content;

  // Detect rounding in financial operations
  const roundingPatterns = [
    { pattern: /\.round\(\)/g, name: 'round()' },
    { pattern: /as\s+u\d+/g, name: 'integer truncation' },
    { pattern: /\/.*?as.*?u\d+/g, name: 'division with cast' },
  ];

  for (const { pattern, name } of roundingPatterns) {
    const matches = content.match(pattern);
    if (matches) {
      // Check context for deposit/withdraw/interest operations
      const isFinancialContext = /deposit|withdraw|interest|collateral|debt|borrow|lend|share|mint|redeem/i.test(content);
      if (isFinancialContext) {
        findings.push({
          severity: 'high',
          category: 'rounding',
          title: `Potential Rounding Attack via ${name}`,
          description: `Found ${name} in financial context. Rounding errors can be exploited ` +
            'when attacker can choose amounts that maximize rounding in their favor.',
          recommendation: 'Use explicit floor/ceil based on direction: ' +
            'Protocol should always round in its own favor (floor for outgoing, ceil for incoming).',
          location: parsed.path,
        });
        break;
      }
    }
  }

  // Check for share calculation (deposit/mint)
  if (/shares?\s*=.*?amount.*?\/|mint.*?shares/i.test(content)) {
    const hasFloor = /floor|checked_div|\.saturating_div/i.test(content);
    if (!hasFloor) {
      findings.push({
        severity: 'high',
        category: 'rounding',
        title: 'Share Calculation May Round in User Favor',
        description: 'Share calculation on deposit should round DOWN (floor). ' +
          'User receives fewer shares, protecting the protocol.',
        recommendation: 'Use floor division: shares = (amount * total_shares) / total_assets (rounds down naturally). ' +
          'For explicit safety: amount.checked_div(price).unwrap_or(0)',
        location: parsed.path,
      });
    }
  }

  // Check for redemption calculation (withdraw/burn)
  if (/amount\s*=.*?shares?.*?\/|redeem.*?amount/i.test(content)) {
    const hasFloor = /floor|checked_div|\.saturating_div/i.test(content);
    if (!hasFloor) {
      findings.push({
        severity: 'high',
        category: 'rounding',
        title: 'Redemption Calculation May Round in User Favor',
        description: 'Redemption amount calculation should round DOWN (floor). ' +
          'User receives fewer tokens, protecting the protocol.',
        recommendation: 'Use floor division: amount = (shares * total_assets) / total_shares (rounds down naturally).',
        location: parsed.path,
      });
    }
  }

  // Check for interest calculation
  if (/interest|accrued|rate.*?\*/i.test(content)) {
    const hasRoundingControl = /floor|ceil|round_down|round_up/i.test(content);
    if (!hasRoundingControl) {
      findings.push({
        severity: 'medium',
        category: 'rounding',
        title: 'Interest Calculation Rounding Not Explicit',
        description: 'Interest calculations should explicitly control rounding direction. ' +
          'Interest owed by borrowers should round UP, interest earned by depositors round DOWN.',
        recommendation: 'Make rounding direction explicit and favor the protocol.',
        location: parsed.path,
      });
    }
  }

  // Check for small amount handling
  if (/amount\s*>\s*0|amount\s*!=\s*0|minimum/i.test(content)) {
    // Good - has amount checks
  } else if (/deposit|withdraw|mint|redeem|borrow/i.test(content)) {
    findings.push({
      severity: 'medium',
      category: 'rounding',
      title: 'Missing Minimum Amount Check',
      description: 'Financial operations without minimum amount validation. ' +
        'Very small amounts can be exploited for rounding attacks.',
      recommendation: 'Implement minimum deposit/withdraw amounts: ' +
        'require!(amount >= MIN_AMOUNT, ErrorCode::AmountTooSmall)',
      location: parsed.path,
    });
  }

  // Detect division before multiplication (precision loss)
  const divBeforeMul = /\/.*?\*|divided.*?multiply/i;
  if (divBeforeMul.test(content)) {
    findings.push({
      severity: 'high',
      category: 'rounding',
      title: 'Division Before Multiplication (Precision Loss)',
      description: 'Division before multiplication causes precision loss. ' +
        'Example: (a / b) * c loses precision; (a * c) / b is more accurate.',
      recommendation: 'Reorder to multiply before divide. ' +
        'Use u128 for intermediate calculations to prevent overflow: ' +
        '(a as u128 * c as u128 / b as u128) as u64',
      location: parsed.path,
    });
  }

  return findings;
}
