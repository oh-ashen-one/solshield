import type { Finding } from '../commands/audit.js';
import type { ParsedRust } from '../parsers/rust.js';

/**
 * Kudelski-Style Ownership and Data Validation
 * Based on: Kudelski Security's Solana Program Security blog series
 * 
 * Two fundamental checks that must always be performed:
 * 1. Owner check - verify account is owned by expected program
 * 2. Data validation - verify account data matches expected format
 * 
 * Without these, attackers can pass arbitrary accounts.
 */
export function checkKudelskiOwnershipCheck(parsed: ParsedRust): Finding[] {
  const findings: Finding[] = [];
  const content = parsed.content;

  // Check for AccountInfo without owner verification
  const accountInfoUsage = /AccountInfo<'info>\s*,?\s*(?!.*constraint.*owner)/g;
  if (accountInfoUsage.test(content)) {
    const hasExplicitOwnerCheck = /\.owner\s*==|owner\.eq\(|require!.*owner/i.test(content);
    if (!hasExplicitOwnerCheck) {
      findings.push({
        severity: 'critical',
        category: 'ownership-check',
        title: 'AccountInfo Without Owner Verification',
        description: 'AccountInfo used without verifying account owner. ' +
          'Attackers can pass accounts owned by any program, bypassing validation.',
        recommendation: 'Always verify: require!(account.owner == expected_program_id). ' +
          'Or use Anchor\'s Account<T> type which checks owner automatically.',
        location: parsed.path,
      });
    }
  }

  // Check for UncheckedAccount patterns
  if (/UncheckedAccount|\/\/\/\s*CHECK/i.test(content)) {
    // Ensure there's documentation explaining the safety
    const hasCheckComment = /\/\/\/\s*CHECK.*?(safe|valid|verify|owner|signer)/i.test(content);
    if (!hasCheckComment) {
      findings.push({
        severity: 'high',
        category: 'ownership-check',
        title: 'UncheckedAccount Without Safety Documentation',
        description: 'UncheckedAccount requires /// CHECK comment explaining why it\'s safe. ' +
          'Anchor v0.26+ enforces this to prevent accidental unsafe usage.',
        recommendation: 'Add /// CHECK: <reason> comment explaining validation logic.',
        location: parsed.path,
      });
    }
  }

  // Check for data deserialization without owner check
  if (/try_from_slice|deserialize|unpack/i.test(content)) {
    // Check if owner is verified before deserialization
    const hasOwnerBeforeDeser = /owner\s*==.*?try_from_slice|owner\s*==.*?deserialize/s.test(content);
    const hasTypedAccount = /Account<.*?>|Program<|Signer</i.test(content);
    
    if (!hasOwnerBeforeDeser && !hasTypedAccount) {
      findings.push({
        severity: 'high',
        category: 'ownership-check',
        title: 'Data Deserialization Without Owner Check',
        description: 'Account data is deserialized without first verifying owner. ' +
          'Attacker can pass account with matching data layout but different owner.',
        recommendation: 'Check owner BEFORE deserializing: ' +
          'require!(account.owner == expected_program); let data = Account::try_from_slice(...)?',
        location: parsed.path,
      });
    }
  }

  // Check for program ID comparisons
  if (/program.*?id|program_id/i.test(content)) {
    const hasHardcodedCheck = /system_program::id\(\)|spl_token::id\(\)|TOKEN_PROGRAM_ID|SYSTEM_PROGRAM_ID/i.test(content);
    const hasDynamicCheck = /program_id\s*==|\.key\(\)\s*==/i.test(content);
    
    if (!hasHardcodedCheck && !hasDynamicCheck) {
      findings.push({
        severity: 'medium',
        category: 'ownership-check',
        title: 'Program ID Validation May Be Missing',
        description: 'Program ID references found but no explicit validation detected. ' +
          'Ensure all program accounts are verified against expected IDs.',
        recommendation: 'Use hardcoded program IDs: require!(program.key() == spl_token::id())',
        location: parsed.path,
      });
    }
  }

  // Check for signer verification
  if (/authority|admin|owner/i.test(content)) {
    const hasSignerCheck = /is_signer|Signer<|\.signer\s*=\s*true|#\[account\(signer\)\]/i.test(content);
    const hasSignerConstraint = /constraint.*?signer|signer.*?constraint/i.test(content);
    
    if (!hasSignerCheck && !hasSignerConstraint) {
      findings.push({
        severity: 'high',
        category: 'ownership-check',
        title: 'Authority Account May Not Be Verified as Signer',
        description: 'Authority/admin account used without explicit signer verification. ' +
          'Anyone could pass any account as authority.',
        recommendation: 'Use Signer<\'info> type or add constraint: #[account(signer)]',
        location: parsed.path,
      });
    }
  }

  // Check for token account validation
  if (/token.*?account|TokenAccount/i.test(content)) {
    const hasTokenConstraints = /token::mint|token::authority|associated_token/i.test(content);
    if (!hasTokenConstraints) {
      findings.push({
        severity: 'medium',
        category: 'ownership-check',
        title: 'Token Account Constraints May Be Missing',
        description: 'Token account used without apparent mint/authority constraints. ' +
          'Verify token account belongs to expected mint and authority.',
        recommendation: 'Use Anchor constraints: #[account(token::mint = expected_mint, token::authority = owner)]',
        location: parsed.path,
      });
    }
  }

  // Detect is_writable checks
  if (/mut.*?AccountInfo|writable/i.test(content)) {
    const hasWritableCheck = /is_writable|#\[account\(mut\)\]/i.test(content);
    if (!hasWritableCheck) {
      findings.push({
        severity: 'low',
        category: 'ownership-check',
        title: 'Writable Account Verification',
        description: 'Mutable accounts should explicitly verify is_writable flag. ' +
          'Prevents unexpected behavior if client sends non-writable.',
        recommendation: 'Verify: require!(account.is_writable) or use #[account(mut)]',
        location: parsed.path,
      });
    }
  }

  return findings;
}
