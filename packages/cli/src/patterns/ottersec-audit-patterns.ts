import type { Finding } from '../commands/audit.js';
import type { ParsedRust } from '../parsers/rust.js';

/**
 * OtterSec Audit Methodology Patterns
 * Based on: OtterSec's "Solana from an Auditor's Perspective"
 * 
 * Bottoms-up approach to Solana security:
 * 1. Understand execution model
 * 2. Verify all accounts
 * 3. Check all math
 * 4. Validate all CPIs
 * 5. Review state transitions
 */
export function checkOttersecAuditPatterns(parsed: ParsedRust): Finding[] {
  const findings: Finding[] = [];
  const content = parsed.content;

  // ===== Account Model Security =====

  // Check for proper account lifecycle handling
  if (/create.*?account|init.*?account|AccountInfo/i.test(content)) {
    // Check if rent-exempt status is verified
    const hasRentCheck = /rent.*?exempt|lamports.*?>=.*?rent|Rent::get/i.test(content);
    if (!hasRentCheck) {
      findings.push({
        severity: 'medium',
        category: 'ottersec-audit',
        title: 'Rent-Exempt Status Not Verified',
        description: 'Account creation without rent-exemption verification. ' +
          'Non-rent-exempt accounts can be garbage collected.',
        recommendation: 'Verify: lamports >= rent.minimum_balance(data_len). ' +
          'Use Rent::get()?.minimum_balance(data_len) for calculation.',
        location: parsed.path,
      });
    }
  }

  // Check for executable account handling
  if (/executable|program|cpi/i.test(content)) {
    const checksExecutable = /is_executable|\.executable/i.test(content);
    if (!checksExecutable && /invoke/i.test(content)) {
      findings.push({
        severity: 'medium',
        category: 'ottersec-audit',
        title: 'Executable Status Not Verified Before CPI',
        description: 'CPI performed without verifying target is executable. ' +
          'While Solana enforces this, explicit checks add defense in depth.',
        recommendation: 'Verify program.executable before CPI (optional but good practice).',
        location: parsed.path,
      });
    }
  }

  // ===== Instruction Processing Security =====

  // Check for instruction data parsing
  if (/instruction.*?data|deserialize.*?instruction/i.test(content)) {
    const hasBoundsCheck = /len\(\)\s*[<>=]|slice\(.*?\.\.|checked_slice/i.test(content);
    if (!hasBoundsCheck) {
      findings.push({
        severity: 'medium',
        category: 'ottersec-audit',
        title: 'Instruction Data Length Not Validated',
        description: 'Instruction data parsed without length validation. ' +
          'Malformed instructions could cause panics or unexpected behavior.',
        recommendation: 'Validate instruction data length before parsing: ' +
          'require!(data.len() >= expected_len, ErrorCode::InvalidInstruction)',
        location: parsed.path,
      });
    }
  }

  // Check for instruction introspection security
  if (/get_instruction_relative|load_instruction_at/i.test(content)) {
    findings.push({
      severity: 'medium',
      category: 'ottersec-audit',
      title: 'Review Instruction Introspection Usage',
      description: 'Instruction introspection used. This can be powerful but also risky ' +
        'if not carefully validated.',
      recommendation: 'Ensure: 1. Correct instruction index, 2. Expected program ID, ' +
        '3. Expected instruction discriminator. Don\'t trust instruction data blindly.',
      location: parsed.path,
    });
  }

  // ===== Cross-Program Invocation Security =====

  // Check for CPI account permissions
  if (/invoke|cpi/i.test(content)) {
    const checksMutable = /is_writable|\.writable/i.test(content);
    const checksSigner = /is_signer|\.signer/i.test(content);
    
    if (!checksMutable || !checksSigner) {
      findings.push({
        severity: 'medium',
        category: 'ottersec-audit',
        title: 'CPI Account Permissions Not Fully Verified',
        description: 'CPI performed without checking account writable/signer status. ' +
          'Ensure permissions match what the invoked program expects.',
        recommendation: 'Verify account.is_writable and account.is_signer for CPI accounts.',
        location: parsed.path,
      });
    }
  }

  // ===== State Transition Security =====

  // Check for state machine patterns
  if (/state|status|phase/i.test(content) && /enum\s+\w+State|State\s*\{/i.test(content)) {
    const hasTransitionCheck = /match.*?state|state\s*==|valid.*?transition/i.test(content);
    if (!hasTransitionCheck) {
      findings.push({
        severity: 'medium',
        category: 'ottersec-audit',
        title: 'State Transitions May Not Be Validated',
        description: 'State enum exists but transitions may not be validated. ' +
          'Invalid state transitions can break protocol invariants.',
        recommendation: 'Implement explicit state machine: validate current state before transition, ' +
          'define allowed transitions.',
        location: parsed.path,
      });
    }
  }

  // ===== Data Validation Security =====

  // Check for string/byte input validation
  if (/String|Vec<u8>|&\[u8\]|str/i.test(content)) {
    const hasLengthLimit = /len\(\)\s*[<>=]|max.*?len|MAX.*?SIZE/i.test(content);
    if (!hasLengthLimit) {
      findings.push({
        severity: 'medium',
        category: 'ottersec-audit',
        title: 'Unbounded String/Bytes Input',
        description: 'String or bytes input without length validation. ' +
          'Could cause DoS through large allocations.',
        recommendation: 'Validate input length: require!(input.len() <= MAX_LENGTH)',
        location: parsed.path,
      });
    }
  }

  // Check for numerical bounds
  if (/amount|value|rate|multiplier/i.test(content)) {
    const hasBounds = /min.*?amount|max.*?amount|amount\s*[<>=]|within.*?range/i.test(content);
    if (!hasBounds) {
      findings.push({
        severity: 'medium',
        category: 'ottersec-audit',
        title: 'Numerical Input Bounds Not Validated',
        description: 'Numerical inputs (amount, value, rate) without bounds checking. ' +
          'Extreme values can cause unexpected behavior.',
        recommendation: 'Validate: MIN_VALUE <= input <= MAX_VALUE',
        location: parsed.path,
      });
    }
  }

  // ===== Error Handling Security =====

  // Check for error message information leakage
  if (/error!|msg!|Error\s*\{/i.test(content)) {
    const leaksInfo = /balance|lamports|authority|address|key/i.test(content) && 
                      /error!.*?\{|msg!.*?\{/i.test(content);
    if (leaksInfo) {
      findings.push({
        severity: 'low',
        category: 'ottersec-audit',
        title: 'Error Messages May Leak Sensitive Information',
        description: 'Error messages include sensitive data (addresses, balances). ' +
          'Could help attackers understand protocol state.',
        recommendation: 'Use generic error messages in production. ' +
          'Log detailed info only in development builds.',
        location: parsed.path,
      });
    }
  }

  return findings;
}
