import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL119: Program Upgrade Security
 * Detects issues with upgradeable program patterns
 */
export function checkProgramUpgrade(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;

  if (!rust || !rust.content) return findings;

  // Check for upgrade functionality
  if (rust.content.includes('upgrade') || rust.content.includes('Upgrade')) {
    if (!rust.content.includes('authority') && !rust.content.includes('admin')) {
      findings.push({
        id: 'SOL119',
        severity: 'critical',
        title: 'Upgrade Without Authority',
        description: 'Upgrade functionality without explicit authority check',
        location: input.path,
        recommendation: 'Restrict upgrades to verified authority/multisig',
      });
    }
  }

  // Check for immutable program handling
  if (rust.content.includes('immutable') || rust.content.includes('non_upgradeable')) {
    findings.push({
      id: 'SOL119',
      severity: 'low',
      title: 'Immutable Program Reference',
      description: 'Program references immutability - ensure this is intentional',
      location: input.path,
      recommendation: 'Document why program is non-upgradeable',
    });
  }

  return findings;
}
