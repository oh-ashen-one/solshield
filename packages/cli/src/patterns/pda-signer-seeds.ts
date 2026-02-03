import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL083: PDA Signer Seeds Mismatch
 * Detects mismatches between PDA derivation and signing seeds
 */
export function checkPdaSignerSeeds(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;

  if (!rust || !rust.content) return findings;

  // Check for invoke_signed
  if (!rust.content.includes('invoke_signed') && !rust.content.includes('CpiContext::new_with_signer')) {
    return findings;
  }

  // Extract seed patterns from find_program_address
  const findPda = /find_program_address\s*\(\s*&?\[([^\]]+)\]/g;
  const derivationSeeds: string[] = [];
  let match;
  while ((match = findPda.exec(rust.content)) !== null) {
    derivationSeeds.push(match[1].trim());
  }

  // Extract signer_seeds patterns
  const signerSeeds = /signer_seeds\s*=|seeds\s*=\s*&?\[&?\[([^\]]+)\]/g;
  const signingSeeds: string[] = [];
  while ((match = signerSeeds.exec(rust.content)) !== null) {
    if (match[1]) {
      signingSeeds.push(match[1].trim());
    }
  }

  // Check for obvious mismatches
  if (derivationSeeds.length > 0 && signingSeeds.length > 0) {
    // Count seed components
    for (let i = 0; i < derivationSeeds.length; i++) {
      const deriveParts = derivationSeeds[i].split(',').length;
      const signParts = signingSeeds[i] ? signingSeeds[i].split(',').length : 0;
      
      if (signParts > 0 && deriveParts !== signParts) {
        findings.push({
          id: 'SOL083',
          severity: 'critical',
          title: 'PDA Seeds Count Mismatch',
          description: `Derivation has ${deriveParts} seeds but signing has ${signParts} seeds`,
          location: input.path,
          recommendation: 'Ensure signer_seeds exactly matches the seeds used in find_program_address',
        });
      }
    }
  }

  // Check for missing bump in signer seeds
  if (rust.content.includes('invoke_signed') || rust.content.includes('CpiContext::new_with_signer')) {
    if (!rust.content.includes('bump')) {
      findings.push({
        id: 'SOL083',
        severity: 'high',
        title: 'Missing Bump in Signer Seeds',
        description: 'invoke_signed/CpiContext without bump byte in signer seeds',
        location: input.path,
        recommendation: 'Include bump byte as last element: &[seed1, seed2, &[bump]]',
      });
    }
  }

  // Check for hardcoded bump
  const hardcodedBump = /&\[\s*\d+u8\s*\]/;
  if (hardcodedBump.test(rust.content)) {
    if (!rust.content.includes('canonical_bump') && !rust.content.includes('.bump')) {
      findings.push({
        id: 'SOL083',
        severity: 'medium',
        title: 'Hardcoded Bump Byte',
        description: 'Using hardcoded bump instead of stored/canonical bump',
        location: input.path,
        recommendation: 'Store and use the canonical bump from find_program_address',
      });
    }
  }

  // Check for dynamic seeds without validation
  const dynamicSeeds = /seeds[\s\S]*?\.key\(\)|seeds[\s\S]*?\.as_ref\(\)/;
  if (dynamicSeeds.test(rust.content)) {
    if (!rust.content.includes('ctx.accounts') && !rust.content.includes('accounts.')) {
      findings.push({
        id: 'SOL083',
        severity: 'medium',
        title: 'Dynamic Seeds May Be Unvalidated',
        description: 'Seeds derived from potentially unvalidated input',
        location: input.path,
        recommendation: 'Ensure all seed components are from validated account fields',
      });
    }
  }

  return findings;
}
