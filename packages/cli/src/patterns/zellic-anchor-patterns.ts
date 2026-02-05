import type { Finding } from '../commands/audit.js';
import type { ParsedRust } from '../parsers/rust.js';

/**
 * Zellic Anchor Vulnerability Patterns
 * Based on: Zellic's "The Vulnerabilities You'll Write with Anchor"
 * 
 * Common vulnerabilities found in Anchor programs:
 * 1. init_if_needed reentrancy
 * 2. Arbitrary CPI signer
 * 3. Missing signer checks
 * 4. Type confusion
 * 5. Closing account revival
 */
export function checkZellicAnchorPatterns(parsed: ParsedRust): Finding[] {
  const findings: Finding[] = [];
  const content = parsed.content;

  // Check for init_if_needed without reentrancy protection
  if (/init_if_needed/i.test(content)) {
    const hasReentrancyGuard = /reentrancy|reentry|guard|mutex/i.test(content);
    if (!hasReentrancyGuard) {
      findings.push({
        severity: 'critical',
        category: 'zellic-anchor',
        title: 'init_if_needed Without Reentrancy Protection',
        description: 'init_if_needed can be exploited via reentrancy. ' +
          'Attacker calls instruction, triggers CPI, CPI re-enters with uninitialized account, ' +
          'account gets initialized mid-execution with attacker-controlled data.',
        recommendation: 'Avoid init_if_needed. If required, add reentrancy guards. ' +
          'Consider using separate init instruction with proper checks.',
        location: parsed.path,
      });
    }
  }

  // Check for arbitrary CPI with signer seeds
  if (/invoke_signed|CpiContext.*?with_signer/i.test(content)) {
    // Check if invoked program is validated
    const hasHardcodedProgram = /program_id\s*==|TOKEN_PROGRAM_ID|SYSTEM_PROGRAM_ID|spl_token::id/i.test(content);
    const usesAnchorProgram = /Program<.*?'info.*?,.*?>/i.test(content);
    
    if (!hasHardcodedProgram && !usesAnchorProgram) {
      findings.push({
        severity: 'critical',
        category: 'zellic-anchor',
        title: 'CPI with Signer Seeds to Unvalidated Program',
        description: 'CPI with signer seeds (PDA authority) to potentially arbitrary program. ' +
          'Attacker can substitute malicious program to steal PDA-controlled assets.',
        recommendation: 'Always validate program ID before CPI: require!(ctx.accounts.program.key() == expected_id). ' +
          'Or use Anchor\'s Program<T> type.',
        location: parsed.path,
      });
    }
  }

  // Check for missing signer on authority accounts
  const authorityPattern = /pub\s+(authority|admin|owner|payer|user)\s*:/i;
  if (authorityPattern.test(content)) {
    const hasSignerCheck = /#\[account\([^)]*signer[^)]*\)\]|Signer<'info>/i.test(content);
    if (!hasSignerCheck) {
      findings.push({
        severity: 'high',
        category: 'zellic-anchor',
        title: 'Authority Account May Not Be Validated as Signer',
        description: 'Authority-like account (authority/admin/owner/payer) without explicit signer constraint. ' +
          'Anyone can pass any account as the authority.',
        recommendation: 'Add signer constraint: #[account(signer)] or use Signer<\'info> type.',
        location: parsed.path,
      });
    }
  }

  // Check for type confusion with Account<T>
  if (/Account<'info,\s*\w+>/i.test(content)) {
    // Check if discriminator is properly checked (Anchor does this, but worth noting for custom deserialization)
    const hasCustomDeser = /try_from_slice|borsh::deserialize|from_bytes/i.test(content);
    if (hasCustomDeser) {
      findings.push({
        severity: 'high',
        category: 'zellic-anchor',
        title: 'Custom Deserialization May Bypass Type Checks',
        description: 'Custom deserialization alongside Anchor Account<T>. ' +
          'Custom deserialization might not check discriminator, allowing type confusion.',
        recommendation: 'Rely on Anchor\'s Account<T> for deserialization which checks discriminator. ' +
          'If custom deser needed, manually verify discriminator prefix.',
        location: parsed.path,
      });
    }
  }

  // Check for account closure without data zeroing
  if (/close\s*=|close_account|\.close\(/i.test(content)) {
    const hasZeroData = /zero|memset|fill\(0\)|overwrite/i.test(content);
    if (!hasZeroData) {
      findings.push({
        severity: 'high',
        category: 'zellic-anchor',
        title: 'Account Closure May Not Zero Data',
        description: 'Account closed without zeroing data. ' +
          'Account can be revived in same transaction with original data intact.',
        recommendation: 'Use Anchor\'s close constraint which zeros data, or manually zero: ' +
          'account.data.borrow_mut().fill(0)',
        location: parsed.path,
      });
    }
  }

  // Check for remaining_accounts without validation
  if (/remaining_accounts|ctx\.remaining_accounts/i.test(content)) {
    const hasValidation = /remaining.*?iter.*?verify|validate.*?remaining|check.*?remaining/i.test(content);
    if (!hasValidation) {
      findings.push({
        severity: 'high',
        category: 'zellic-anchor',
        title: 'remaining_accounts Without Validation',
        description: 'remaining_accounts used without apparent validation. ' +
          'These accounts bypass Anchor\'s normal constraint checking.',
        recommendation: 'Validate each remaining account: check owner, check data format, ' +
          'verify it matches expected accounts.',
        location: parsed.path,
      });
    }
  }

  // Check for seeds without proper PDA derivation check
  if (/seeds\s*=/i.test(content)) {
    const hasBump = /bump\s*=|bump\.into\(\)|canonical.*?bump/i.test(content);
    if (!hasBump) {
      findings.push({
        severity: 'medium',
        category: 'zellic-anchor',
        title: 'PDA Seeds Without Bump Constraint',
        description: 'PDA seeds constraint without bump specification. ' +
          'Non-canonical bump could be used.',
        recommendation: 'Add bump constraint: seeds = [...], bump = expected_bump, ' +
          'or bump (for canonical bump). Store bump in account for future verification.',
        location: parsed.path,
      });
    }
  }

  // Check for mut without payer on init
  if (/init\s*,/i.test(content)) {
    const hasPayer = /payer\s*=/i.test(content);
    if (!hasPayer) {
      findings.push({
        severity: 'low',
        category: 'zellic-anchor',
        title: 'Init Without Explicit Payer',
        description: 'Account initialization without explicit payer constraint. ' +
          'Payer should be explicitly specified for clarity.',
        recommendation: 'Add payer constraint: #[account(init, payer = authority, ...)]',
        location: parsed.path,
      });
    }
  }

  return findings;
}
