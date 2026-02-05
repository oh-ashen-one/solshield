import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL654: Phishing Account Transfer Attack Pattern
 * 
 * Based on SlowMist research (December 2025) - $3M+ losses
 * Attackers trick users into signing transactions that silently
 * transfer ownership or delegate authority to attacker accounts
 * 
 * Key attack vectors:
 * 1. SetAuthority disguised as benign operations
 * 2. Delegate approvals hidden in transaction bundles
 * 3. Account ownership transfers via malicious dApps
 * 
 * References:
 * - SlowMist: Solana Phishing Attacks (Dec 2025)
 * - CyberPress: Unauthorized Account Transfers
 */

export function checkPhishingAccountTransfer(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  const path = input.path;

  // Pattern 1: Authority changes without explicit user confirmation
  const authChangePatterns = [
    /set_authority.*Authority::AccountOwner/gi,
    /set_authority.*Authority::CloseAccount/gi,
    /AuthorityType::AccountOwner/gi,
    /spl_token::instruction::set_authority/gi,
  ];

  for (const pattern of authChangePatterns) {
    const matches = content.match(pattern);
    if (matches) {
      const hasConfirmation = /confirm|verify_intent|user_consent|require.*signature/i.test(content);
      
      if (!hasConfirmation) {
        findings.push({
          id: 'SOL654',
          severity: 'critical',
          title: 'Authority Transfer Without Explicit User Confirmation',
          description: `SetAuthority operation found that could transfer account ownership. SlowMist documented $3M+ losses from phishing attacks that disguise authority transfers. Users may unknowingly sign transactions that give attackers permanent control.`,
          location: path,
          snippet: matches[0],
          recommendation: 'Require explicit user confirmation for authority changes. Display clear warnings about ownership transfers. Consider adding timelocks to authority changes.',
        });
      }
    }
  }

  // Pattern 2: Delegate operations that could be abused
  const delegatePatterns = [
    /Approve\s*{.*amount\s*:\s*u64::MAX/gi,
    /approve.*MAX|approve.*-1/gi,
    /delegate_amount\s*=\s*u64::MAX/gi,
    /unlimited.*delegate|max.*approval/gi,
  ];

  for (const pattern of delegatePatterns) {
    if (pattern.test(content)) {
      findings.push({
        id: 'SOL654-2',
        severity: 'critical',
        title: 'Unlimited Token Delegation Risk',
        description: `Unlimited token delegation (u64::MAX) detected. Phishing attacks commonly trick users into approving unlimited delegates, allowing attackers to drain wallets at any time.`,
        location: path,
        recommendation: 'Never use unlimited approvals. Request only the amount needed for the operation. Implement approval expiry. Auto-revoke unused delegations.',
      });
    }
  }

  // Pattern 3: Account close operations that send lamports to non-owner
  if (/close_account|CloseAccount/i.test(content)) {
    const checksDest = /destination.*owner|close.*to\s*=\s*ctx\.accounts\.owner/i.test(content);
    
    if (!checksDest) {
      findings.push({
        id: 'SOL654-3',
        severity: 'high',
        title: 'Account Close May Send Lamports to Non-Owner',
        description: `Account close operation without verifying destination is the original owner. Phishing attacks can close accounts and redirect lamports to attacker.`,
        location: path,
        recommendation: 'Always verify close destination is the original account owner or explicitly authorized recipient.',
      });
    }
  }

  // Pattern 4: Hidden operations in composite instructions
  const compositePatterns = [
    /remaining_accounts.*set_authority/gi,
    /invoke_signed.*multiple/gi,
    /batch.*transfer.*authority/gi,
  ];

  for (const pattern of compositePatterns) {
    if (pattern.test(content)) {
      findings.push({
        id: 'SOL654-4',
        severity: 'high',
        title: 'Potentially Hidden Operations in Composite Instruction',
        description: `Complex instruction pattern that could hide malicious operations. Phishing attacks bundle harmful operations with legitimate-looking transactions.`,
        location: path,
        recommendation: 'Clearly separate and label each operation. Provide human-readable transaction summaries. Consider instruction-level access control.',
      });
    }
  }

  // Pattern 5: Missing owner validation before token operations
  if (/transfer|burn|close_account/i.test(content)) {
    const ownerChecked = /constraint\s*=\s*.*owner|has_one\s*=\s*owner|require.*owner/i.test(content);
    
    if (!ownerChecked) {
      findings.push({
        id: 'SOL654-5',
        severity: 'high',
        title: 'Token Operation Without Owner Validation',
        description: `Token operation without explicit owner constraint. Could allow unauthorized transfers if account ownership was silently changed.`,
        location: path,
        recommendation: 'Always validate token account owner matches expected authority before operations.',
      });
    }
  }

  // Pattern 6: Program authority that can be changed
  if (/program_authority|upgrade_authority/i.test(content)) {
    const isImmutable = /set_to_none|revoke|immutable/i.test(content);
    
    if (!isImmutable) {
      findings.push({
        id: 'SOL654-6',
        severity: 'medium',
        title: 'Mutable Program Authority Risk',
        description: `Program authority can be changed. Social engineering attacks target program owners to transfer upgrade authority to attackers.`,
        location: path,
        recommendation: 'Consider revoking upgrade authority for production programs. Use multisig for upgrade authority if mutability required.',
      });
    }
  }

  return findings;
}
