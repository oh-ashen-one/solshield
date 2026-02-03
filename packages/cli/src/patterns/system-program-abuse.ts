import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL073: System Program Abuse
 * Detects vulnerabilities in system program interactions
 */
export function checkSystemProgramAbuse(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;

  if (!rust || !rust.content) return findings;

  // Check for CreateAccount without proper validation
  if (rust.content.includes('CreateAccount') || rust.content.includes('create_account')) {
    // Check if space is validated
    if (!rust.content.includes('space') || rust.content.includes('space: 0')) {
      findings.push({
        id: 'SOL073',
        severity: 'medium',
        title: 'CreateAccount With Zero Space',
        description: 'Creating account with potentially zero space allocation',
        location: input.path,
        recommendation: 'Ensure space is set to appropriate size for account data',
      });
    }

    // Check if owner is validated
    const createWithoutOwnerCheck = /create_account[\s\S]*?(?!owner\s*==)/;
    if (!rust.content.includes('owner:') && createWithoutOwnerCheck.test(rust.content)) {
      findings.push({
        id: 'SOL073',
        severity: 'high',
        title: 'CreateAccount Without Owner Specification',
        description: 'Creating account without explicitly setting owner program',
        location: input.path,
        recommendation: 'Always specify the intended owner program for new accounts',
      });
    }
  }

  // Check for Assign abuse
  if (rust.content.includes('Assign') || rust.content.includes('assign(')) {
    // Assigning to system program can be used to reset accounts
    if (rust.content.includes('system_program::ID') || rust.content.includes('System::ID')) {
      findings.push({
        id: 'SOL073',
        severity: 'medium',
        title: 'Account Assignment to System Program',
        description: 'Assigning account owner to system program - may be intentional reset or vulnerability',
        location: input.path,
        recommendation: 'Verify this is intentional account reset behavior with proper access control',
      });
    }
  }

  // Check for Transfer without balance check
  if (rust.content.includes('system_instruction::transfer') || 
      rust.content.includes('Transfer { lamports')) {
    if (!rust.content.includes('lamports()') && !rust.content.includes('get_lamports')) {
      findings.push({
        id: 'SOL073',
        severity: 'medium',
        title: 'System Transfer Without Balance Check',
        description: 'Transferring lamports without checking source balance',
        location: input.path,
        recommendation: 'Verify source has sufficient lamports before transfer',
      });
    }
  }

  // Check for Allocate instruction usage
  if (rust.content.includes('Allocate') || rust.content.includes('allocate(')) {
    findings.push({
      id: 'SOL073',
      severity: 'low',
      title: 'Direct Allocate Instruction',
      description: 'Using Allocate instruction - ensure proper access control',
      location: input.path,
      recommendation: 'Prefer CreateAccount which handles allocation atomically',
    });
  }

  // Check for system program as passed account without validation
  if (rust.content.includes('system_program') || rust.content.includes('SystemProgram')) {
    if (!rust.content.includes('system_program::ID') && 
        !rust.content.includes('system_program::check_id') &&
        !rust.content.includes('System::id()')) {
      findings.push({
        id: 'SOL073',
        severity: 'critical',
        title: 'System Program Not Validated',
        description: 'System program account used without verifying it is the real system program',
        location: input.path,
        recommendation: 'Verify system_program.key() == system_program::ID',
      });
    }
  }

  // Check for AdvanceNonceAccount risks
  if (rust.content.includes('AdvanceNonce') || rust.content.includes('nonce')) {
    if (!rust.content.includes('nonce_authority')) {
      findings.push({
        id: 'SOL073',
        severity: 'medium',
        title: 'Nonce Account Without Authority Check',
        description: 'Nonce account operations without validating authority',
        location: input.path,
        recommendation: 'Verify nonce authority is authorized for the operation',
      });
    }
  }

  // Check for WithdrawNonceAccount
  if (rust.content.includes('WithdrawNonce')) {
    findings.push({
      id: 'SOL073',
      severity: 'low',
      title: 'Nonce Account Withdrawal',
      description: 'Withdrawing from nonce account - ensure proper access control',
      location: input.path,
      recommendation: 'Implement strict authority checks for nonce withdrawals',
    });
  }

  return findings;
}
