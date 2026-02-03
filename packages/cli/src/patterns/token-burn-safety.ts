import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL107: Token Burn Safety
 * Detects issues with token burning operations
 */
export function checkTokenBurnSafety(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;

  if (!rust || !rust.content) return findings;

  if (!rust.content.includes('Burn') && !rust.content.includes('burn')) return findings;

  // Check for burn without authority validation
  if (rust.content.includes('burn') && !rust.content.includes('authority')) {
    findings.push({
      id: 'SOL107',
      severity: 'critical',
      title: 'Burn Without Authority Check',
      description: 'Token burn operation without explicit authority validation',
      location: input.path,
      recommendation: 'Verify burn authority is token account owner or delegate',
    });
  }

  // Check for burn amount validation
  if (rust.content.includes('Burn') && !rust.content.includes('amount <=') && 
      !rust.content.includes('checked_')) {
    findings.push({
      id: 'SOL107',
      severity: 'medium',
      title: 'Burn Amount Not Validated',
      description: 'Burn amount not checked against balance',
      location: input.path,
      recommendation: 'Verify amount <= token_account.amount before burning',
    });
  }

  // Check for burn in loops
  if (rust.content.includes('for ') && rust.content.includes('burn')) {
    findings.push({
      id: 'SOL107',
      severity: 'medium',
      title: 'Burn in Loop',
      description: 'Token burn in loop - may hit compute limits with many tokens',
      location: input.path,
      recommendation: 'Consider batch limits for loop burns',
    });
  }

  return findings;
}
