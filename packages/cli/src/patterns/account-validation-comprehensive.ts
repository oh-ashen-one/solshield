import type { Finding } from '../commands/audit.js';
import type { ParsedRust } from '../parsers/rust.js';

/**
 * Comprehensive Account Validation Patterns
 * 
 * Deep account validation checks based on common Solana vulnerabilities.
 * Covers all aspects of account validation that are commonly missed.
 * 
 * Detects:
 * - Missing account type checks
 * - PDA derivation errors
 * - Authority chain validation gaps
 * - Account data integrity issues
 */

export function checkAccountValidationComprehensive(parsed: ParsedRust): Finding[] {
  const findings: Finding[] = [];
  const content = parsed.content;

  // Pattern 1: Account owner not checked against program
  if (/Account.*Info|account.*info/i.test(content)) {
    if (!/owner.*==.*program|check.*owner|owner\.eq/i.test(content)) {
      findings.push({
        id: 'ACCOUNT_OWNER_UNCHECKED',
        severity: 'critical',
        title: 'Account Owner Not Validated',
        description: 'Account passed without checking owner equals expected program. Attacker can pass fake accounts.',
        location: parsed.path,
        recommendation: 'Always verify account.owner == expected_program_id. Use Anchor constraints.'
      });
    }
  }

  // Pattern 2: PDA derivation not verified
  if (/find_program_address|create_program_address|pda/i.test(content)) {
    if (!/verify.*pda|check.*derived|expected.*pda|canonical.*bump/i.test(content)) {
      findings.push({
        id: 'PDA_DERIVATION_NOT_VERIFIED',
        severity: 'high',
        title: 'PDA Derivation Not Verified On-Chain',
        description: 'PDA passed without re-deriving to verify. Attacker could pass incorrect address.',
        location: parsed.path,
        recommendation: 'Re-derive PDA on-chain and compare with passed account. Use canonical bump.'
      });
    }
  }

  // Pattern 3: Seeds used in PDA not validated
  if (/seeds|pda.*seeds|derive.*address/i.test(content)) {
    if (!/validate.*seed|check.*seed.*match|seed.*from.*input/i.test(content)) {
      findings.push({
        id: 'PDA_SEEDS_NOT_VALIDATED',
        severity: 'high',
        title: 'PDA Seeds Not Properly Validated',
        description: 'Seeds used for PDA derivation may not be validated. Seed injection attacks possible.',
        location: parsed.path,
        recommendation: 'Validate all seeds match expected values. Hash variable-length seeds. Check seed lengths.'
      });
    }
  }

  // Pattern 4: Authority signer not verified
  if (/authority|admin|owner/i.test(content) && /signer|signed/i.test(content)) {
    if (!/is_signer|\.signer|Signer<|#\[account\(.*signer/i.test(content)) {
      findings.push({
        id: 'AUTHORITY_NOT_SIGNER',
        severity: 'critical',
        title: 'Authority Not Verified as Transaction Signer',
        description: 'Authority account not checked as signer. Anyone can impersonate authority.',
        location: parsed.path,
        recommendation: 'Verify authority.is_signer == true. Use Anchor Signer type.'
      });
    }
  }

  // Pattern 5: Token account mint not verified
  if (/token.*account|TokenAccount/i.test(content)) {
    if (!/mint.*==|check.*mint|validate.*mint|#\[account\(.*mint/i.test(content)) {
      findings.push({
        id: 'TOKEN_ACCOUNT_MINT_UNCHECKED',
        severity: 'critical',
        title: 'Token Account Mint Not Verified',
        description: 'Token account accepted without verifying mint matches expected. Wrong tokens could be used.',
        location: parsed.path,
        recommendation: 'Verify token_account.mint == expected_mint. Use Anchor token constraints.'
      });
    }
  }

  // Pattern 6: Token account owner not verified
  if (/token.*account|TokenAccount/i.test(content) && /owner|authority/i.test(content)) {
    if (!/token.*owner.*==|authority.*match|#\[account\(.*token::authority/i.test(content)) {
      findings.push({
        id: 'TOKEN_ACCOUNT_OWNER_UNCHECKED',
        severity: 'high',
        title: 'Token Account Owner/Authority Not Verified',
        description: 'Token account owner not verified. Wrong user could have tokens moved.',
        location: parsed.path,
        recommendation: 'Verify token account authority matches expected. Use Anchor token::authority constraint.'
      });
    }
  }

  // Pattern 7: Account discriminator not checked
  if (/AccountInfo|account.*data/i.test(content) && !/discriminator|#\[account\]/i.test(content)) {
    findings.push({
      id: 'ACCOUNT_DISCRIMINATOR_MISSING',
      severity: 'high',
      title: 'Account Discriminator May Not Be Checked',
      description: 'Raw AccountInfo used without discriminator check. Type confusion attacks possible.',
      location: parsed.path,
      recommendation: 'Use Anchor accounts with automatic discriminator checks. Or manually verify discriminator bytes.'
    });
  }

  // Pattern 8: Remaining accounts not validated
  if (/remaining_accounts|ctx\.remaining/i.test(content)) {
    if (!/validate.*remaining|check.*each|for.*remaining/i.test(content)) {
      findings.push({
        id: 'REMAINING_ACCOUNTS_NOT_VALIDATED',
        severity: 'high',
        title: 'Remaining Accounts Not Individually Validated',
        description: 'Remaining accounts used without validation. Attacker can inject malicious accounts.',
        location: parsed.path,
        recommendation: 'Validate each remaining account individually. Check owner, type, and expected addresses.'
      });
    }
  }

  // Pattern 9: Program ID not verified for CPI
  if (/invoke|invoke_signed|cpi/i.test(content)) {
    if (!/program.*id.*==|check.*program|verify.*program/i.test(content)) {
      findings.push({
        id: 'CPI_PROGRAM_ID_NOT_VERIFIED',
        severity: 'critical',
        title: 'CPI Target Program ID Not Verified',
        description: 'Cross-program invocation without verifying target program. Malicious program could be called.',
        location: parsed.path,
        recommendation: 'Verify program ID matches expected before CPI. Use Anchor CpiContext with known programs.'
      });
    }
  }

  // Pattern 10: System account not verified
  if (/system.*program|System.*Program/i.test(content)) {
    if (!/system_program::id|system_program::ID|System.*Program.*check/i.test(content)) {
      findings.push({
        id: 'SYSTEM_PROGRAM_NOT_VERIFIED',
        severity: 'high',
        title: 'System Program ID Not Verified',
        description: 'System program account not verified. Fake system program could be passed.',
        location: parsed.path,
        recommendation: 'Verify system_program.key() == system_program::ID. Use Anchor Program<System>.'
      });
    }
  }

  // Pattern 11: Account data length not checked
  if (/data\[|try_borrow_data|data_len/i.test(content)) {
    if (!/data\.len\(\)|data_len.*check|ensure.*length/i.test(content)) {
      findings.push({
        id: 'ACCOUNT_DATA_LENGTH_UNCHECKED',
        severity: 'medium',
        title: 'Account Data Length Not Verified',
        description: 'Account data accessed without length check. Could cause panic or read garbage.',
        location: parsed.path,
        recommendation: 'Check data length before accessing. Handle short data gracefully.'
      });
    }
  }

  // Pattern 12: Writable account not required to be writable
  if (/mut.*account|modify.*account|write.*to/i.test(content)) {
    if (!/is_writable|#\[account\(mut/i.test(content)) {
      findings.push({
        id: 'WRITABLE_ACCOUNT_NOT_ENFORCED',
        severity: 'medium',
        title: 'Writable Account Not Enforced',
        description: 'Account modified but writability not enforced. Transaction could fail unexpectedly.',
        location: parsed.path,
        recommendation: 'Verify account.is_writable for accounts you modify. Use Anchor #[account(mut)].'
      });
    }
  }

  // Pattern 13: Rent exemption not verified
  if (/create.*account|init.*account|allocate/i.test(content)) {
    if (!/rent.*exempt|minimum.*balance|rent\.minimum_balance/i.test(content)) {
      findings.push({
        id: 'RENT_EXEMPTION_NOT_CHECKED',
        severity: 'medium',
        title: 'Rent Exemption Not Verified',
        description: 'Account created without ensuring rent exemption. Account could be reaped.',
        location: parsed.path,
        recommendation: 'Ensure new accounts have rent-exempt minimum balance. Use Anchor init with proper space.'
      });
    }
  }

  return findings;
}
