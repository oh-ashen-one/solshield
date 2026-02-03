import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL112: Token Approval/Delegation
 * Detects issues with token delegation and approval patterns
 */
export function checkTokenApproval(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;

  if (!rust || !rust.content) return findings;

  if (!rust.content.includes('Approve') && !rust.content.includes('delegate')) return findings;

  // Check for unlimited approval
  if (rust.content.includes('Approve') && rust.content.includes('u64::MAX')) {
    findings.push({
      id: 'SOL112',
      severity: 'high',
      title: 'Unlimited Token Approval',
      description: 'Approving u64::MAX tokens - user may not understand the risk',
      location: input.path,
      recommendation: 'Approve only the amount needed for the operation',
    });
  }

  // Check for approval without revoke
  if (rust.content.includes('Approve') && !rust.content.includes('Revoke')) {
    findings.push({
      id: 'SOL112',
      severity: 'medium',
      title: 'Approval Without Revoke',
      description: 'Program has approve but no revoke functionality',
      location: input.path,
      recommendation: 'Provide mechanism to revoke token approvals',
    });
  }

  // Check for delegate amount validation
  if (rust.content.includes('delegated_amount') && !rust.content.includes('<=')) {
    findings.push({
      id: 'SOL112',
      severity: 'medium',
      title: 'Delegate Amount Not Validated',
      description: 'Using delegated_amount without checking against balance',
      location: input.path,
      recommendation: 'Verify delegated_amount <= token_account.amount',
    });
  }

  return findings;
}
