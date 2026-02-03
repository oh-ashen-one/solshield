import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL081: Anchor Account Initialization
 * Detects improper account initialization patterns
 */
export function checkAnchorAccountInit(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;

  if (!rust || !rust.content) return findings;

  // Check for init without proper constraints
  if (rust.content.includes('#[account(init')) {
    // Check for init without seeds when it should be a PDA
    if (rust.content.includes('init,') && !rust.content.includes('seeds')) {
      // Check if there's a payer but no seeds
      if (rust.content.includes('payer')) {
        findings.push({
          id: 'SOL081',
          severity: 'medium',
          title: 'Non-PDA Account Initialization',
          description: 'Account initialized without seeds - may be vulnerable to frontrunning',
          location: input.path,
          recommendation: 'Consider using PDA (seeds constraint) for account initialization',
        });
      }
    }

    // Check for init without payer
    if (rust.content.includes('init') && !rust.content.includes('payer')) {
      const initWithoutPayer = /#\[account\(\s*init\s*[^)]*(?!payer)/;
      if (initWithoutPayer.test(rust.content)) {
        findings.push({
          id: 'SOL081',
          severity: 'high',
          title: 'Init Without Payer',
          description: 'Account initialization without specifying payer for rent',
          location: input.path,
          recommendation: 'Add payer = <signer> to init constraint',
        });
      }
    }
  }

  // Check for init_if_needed risks
  if (rust.content.includes('init_if_needed')) {
    findings.push({
      id: 'SOL081',
      severity: 'medium',
      title: 'Using init_if_needed',
      description: 'init_if_needed can be risky - attacker may pre-create accounts with malicious data',
      location: input.path,
      recommendation: 'Prefer init with explicit checks, or ensure discriminator validation',
    });

    // Check if init_if_needed is used on PDAs (safer)
    const initIfNeededNonPDA = /init_if_needed[^)]*(?!seeds)/;
    if (initIfNeededNonPDA.test(rust.content)) {
      findings.push({
        id: 'SOL081',
        severity: 'high',
        title: 'init_if_needed on Non-PDA',
        description: 'Using init_if_needed on non-PDA account is dangerous - attacker controls address',
        location: input.path,
        recommendation: 'Only use init_if_needed with PDAs (seeds constraint)',
      });
    }
  }

  // Check for zero-copy initialization issues
  if (rust.content.includes('zero_copy') && rust.content.includes('init')) {
    if (!rust.content.includes('zero = true')) {
      findings.push({
        id: 'SOL081',
        severity: 'medium',
        title: 'Zero-Copy Init Without Zeroing',
        description: 'Zero-copy account init may have uninitialized memory',
        location: input.path,
        recommendation: 'Use zero = true constraint for zero-copy accounts',
      });
    }
  }

  return findings;
}
