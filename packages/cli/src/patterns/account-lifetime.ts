import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL086: Account Lifetime Management
 * Detects issues with account creation, modification, and closure lifecycle
 */
export function checkAccountLifetime(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;

  if (!rust || !rust.content) return findings;

  // Check for accounts that can be modified but never closed
  if (rust.content.includes('#[account(mut') && !rust.content.includes('close')) {
    // Check if there's any close function
    if (!rust.content.includes('fn close') && !rust.content.includes('fn delete')) {
      findings.push({
        id: 'SOL086',
        severity: 'low',
        title: 'No Account Closure Mechanism',
        description: 'Mutable accounts without any close/delete functionality - rent locked forever',
        location: input.path,
        recommendation: 'Consider adding account closure for rent recovery',
      });
    }
  }

  // Check for orphaned account references
  if (rust.content.includes('AccountInfo') && rust.content.includes('close')) {
    const closeWithoutTransfer = /close[\s\S]*?(?!lamports|transfer|sub_lamports)/;
    if (closeWithoutTransfer.test(rust.content)) {
      findings.push({
        id: 'SOL086',
        severity: 'high',
        title: 'Account Close Without Lamport Transfer',
        description: 'Closing account without transferring lamports to destination',
        location: input.path,
        recommendation: 'Transfer lamports before closing: dest.add_lamports(source.lamports())',
      });
    }
  }

  // Check for temporary accounts not cleaned up
  if (rust.content.includes('init') && !rust.content.includes('close')) {
    // Look for patterns that suggest temporary/escrow accounts
    const tempPatterns = /(?:temp|escrow|swap|order|bid|auction)/i;
    if (tempPatterns.test(rust.content)) {
      findings.push({
        id: 'SOL086',
        severity: 'medium',
        title: 'Temporary Account Without Cleanup',
        description: 'Account appears temporary but has no close mechanism',
        location: input.path,
        recommendation: 'Add close constraint or cleanup function for temporary accounts',
      });
    }
  }

  // Check for account state transitions
  if (rust.content.includes('status') || rust.content.includes('state') || rust.content.includes('State')) {
    // Check if there's a terminal state
    if (rust.content.includes('enum') && !rust.content.includes('Completed') && 
        !rust.content.includes('Closed') && !rust.content.includes('Finalized')) {
      findings.push({
        id: 'SOL086',
        severity: 'low',
        title: 'State Machine Without Terminal State',
        description: 'Account state enum may lack proper terminal/completion state',
        location: input.path,
        recommendation: 'Add terminal states (Completed, Closed) for proper lifecycle management',
      });
    }
  }

  // Check for re-initialization after modification
  if (rust.content.includes('#[account(init') && rust.content.includes('#[account(mut')) {
    // Same account type being both init and mut is suspicious
    findings.push({
      id: 'SOL086',
      severity: 'medium',
      title: 'Account Can Be Initialized and Modified',
      description: 'Same account type appears with both init and mut - potential re-init risk',
      location: input.path,
      recommendation: 'Ensure init accounts cannot be passed to modification instructions',
    });
  }

  return findings;
}
