import type { Finding } from '../commands/audit.js';
import type { ParsedRust } from '../parsers/rust.js';

/**
 * Sec3 Audit Methodology Patterns
 * Based on: Sec3's "How to Audit Solana Smart Contracts" series
 * 
 * Common attack surfaces identified in Sec3 audits:
 * 1. Account validation failures
 * 2. Arithmetic issues
 * 3. Authority management
 * 4. Cross-program invocation risks
 * 5. State management problems
 */
export function checkSec3AuditPatterns(parsed: ParsedRust): Finding[] {
  const findings: Finding[] = [];
  const content = parsed.content;

  // ===== Account Validation Attack Surface =====
  
  // Check for missing discriminator checks
  if (/struct.*?\{|enum.*?\{/i.test(content)) {
    const hasDiscriminator = /discriminator|account_discriminator|DISCRIMINATOR/i.test(content);
    const hasAnchorAccount = /#\[account\]|#\[derive\(.*?Account/i.test(content);
    
    if (!hasDiscriminator && !hasAnchorAccount) {
      findings.push({
        severity: 'high',
        category: 'sec3-audit',
        title: 'Account Type Discrimination Missing',
        description: 'Account structs without discriminator prefix. ' +
          'Different account types could be confused if they have similar layouts.',
        recommendation: 'Add 8-byte discriminator prefix or use Anchor\'s #[account] which adds it automatically.',
        location: parsed.path,
      });
    }
  }

  // Check for PDA validation
  if (/seeds|find_program_address|create_program_address/i.test(content)) {
    const hasBumpCheck = /bump|canonical.*?bump/i.test(content);
    if (!hasBumpCheck) {
      findings.push({
        severity: 'medium',
        category: 'sec3-audit',
        title: 'PDA Bump Seed Not Stored/Verified',
        description: 'PDA derivation without bump seed management. ' +
          'Non-canonical bumps could cause issues.',
        recommendation: 'Store bump seed in account data and use it for verification. ' +
          'Or use Anchor\'s bump constraint.',
        location: parsed.path,
      });
    }
  }

  // ===== Authority Management Attack Surface =====

  // Check for authority transfer patterns
  if (/transfer.*?authority|set.*?authority|update.*?admin/i.test(content)) {
    const hasTwoStep = /pending.*?authority|accept.*?authority|confirm.*?transfer/i.test(content);
    if (!hasTwoStep) {
      findings.push({
        severity: 'medium',
        category: 'sec3-audit',
        title: 'Single-Step Authority Transfer',
        description: 'Authority transfer in single step. ' +
          'If transferred to wrong address, funds/control permanently lost.',
        recommendation: 'Implement two-step transfer: 1. propose_authority, 2. accept_authority. ' +
          'New authority must actively claim before transfer completes.',
        location: parsed.path,
      });
    }
  }

  // Check for missing revocation
  if (/approve|delegate|grant/i.test(content)) {
    const hasRevoke = /revoke|remove.*?delegate|remove.*?approval/i.test(content);
    if (!hasRevoke) {
      findings.push({
        severity: 'medium',
        category: 'sec3-audit',
        title: 'Approval Without Revocation Mechanism',
        description: 'Approval/delegation mechanism without corresponding revocation.',
        recommendation: 'Implement revoke functionality for all approval mechanisms.',
        location: parsed.path,
      });
    }
  }

  // ===== CPI Attack Surface =====

  // Check for CPI with untrusted programs
  if (/invoke\s*\(|invoke_signed\s*\(/i.test(content)) {
    const hasHardcodedProgram = /instruction\s*=.*?Instruction\s*\{.*?program_id:\s*(spl_token::id|system_program::id)/s.test(content);
    const hasAnchorCpi = /CpiContext|cpi::/i.test(content);
    
    if (!hasHardcodedProgram && !hasAnchorCpi) {
      findings.push({
        severity: 'high',
        category: 'sec3-audit',
        title: 'CPI Program ID May Not Be Verified',
        description: 'Cross-program invocation without apparent program ID verification. ' +
          'Attacker could substitute malicious program.',
        recommendation: 'Verify program ID before CPI: require!(program.key() == expected_id). ' +
          'Or use Anchor\'s CpiContext which handles this.',
        location: parsed.path,
      });
    }
  }

  // Check for CPI privilege escalation
  if (/invoke_signed.*?signer_seeds/i.test(content)) {
    findings.push({
      severity: 'medium',
      category: 'sec3-audit',
      title: 'Review CPI Signing Seeds',
      description: 'CPI with signer seeds (PDA signing). ' +
        'Ensure invoked program cannot misuse the PDA signature.',
      recommendation: 'Carefully review what the invoked program can do with PDA authority. ' +
        'Minimize privileges granted through CPI.',
      location: parsed.path,
    });
  }

  // ===== State Management Attack Surface =====

  // Check for race conditions in state updates
  if (/state|balance|amount/i.test(content)) {
    const hasAtomicOps = /checked_add.*?store|update.*?atomic|fetch_add/i.test(content);
    const hasSerialAccess = /mut.*?borrow.*?mut|RefMut/i.test(content);
    
    if (!hasAtomicOps && hasSerialAccess) {
      findings.push({
        severity: 'medium',
        category: 'sec3-audit',
        title: 'State Update May Have Race Conditions',
        description: 'State modifications without apparent atomic guarantees. ' +
          'In single-threaded Solana this is less critical but affects code clarity.',
        recommendation: 'Ensure state reads and writes are properly ordered. ' +
          'Consider using checked arithmetic for balance updates.',
        location: parsed.path,
      });
    }
  }

  // Check for missing state initialization
  if (/struct.*?\{[^}]*is_initialized|initialized:\s*bool/s.test(content)) {
    const hasInitCheck = /!.*?is_initialized|initialized\s*==\s*false/i.test(content);
    if (!hasInitCheck) {
      findings.push({
        severity: 'high',
        category: 'sec3-audit',
        title: 'Initialization Flag Not Checked',
        description: 'State struct has initialized flag but check may be missing. ' +
          'Could allow re-initialization attacks.',
        recommendation: 'Check: require!(!state.is_initialized, ErrorCode::AlreadyInitialized)',
        location: parsed.path,
      });
    }
  }

  // ===== Error Handling Attack Surface =====

  // Check for unwrap/expect in production code
  const unwrapCount = (content.match(/\.unwrap\(\)|\.expect\(/g) || []).length;
  if (unwrapCount > 5) {
    findings.push({
      severity: 'medium',
      category: 'sec3-audit',
      title: 'Excessive Use of unwrap()/expect()',
      description: `Found ${unwrapCount} instances of unwrap/expect. ` +
        'Panics in production can cause DoS or unexpected behavior.',
      recommendation: 'Replace with proper error handling: .ok_or(ErrorCode::X)? or .map_err()?',
      location: parsed.path,
    });
  }

  return findings;
}
