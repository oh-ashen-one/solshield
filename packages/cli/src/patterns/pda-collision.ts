import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL070: PDA Seed Collision
 * Detects vulnerabilities where PDA seeds may collide across different contexts
 */
export function checkPdaCollision(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;

  if (!rust || !rust.content) return findings;

  // Find all PDA derivations
  const pdaDerivations = rust.content.match(/find_program_address\s*\(\s*&?\[([^\]]+)\]/g) || [];
  const seedPatterns: string[] = [];

  for (const pda of pdaDerivations) {
    const seedMatch = pda.match(/\[([^\]]+)\]/);
    if (seedMatch) {
      seedPatterns.push(seedMatch[1].trim());
    }
  }

  // Check for same seed prefix across different PDAs
  const seenPrefixes: Map<string, string[]> = new Map();
  for (const pattern of seedPatterns) {
    const parts = pattern.split(',').map(p => p.trim());
    if (parts.length > 0) {
      const prefix = parts[0];
      if (!seenPrefixes.has(prefix)) {
        seenPrefixes.set(prefix, []);
      }
      seenPrefixes.get(prefix)!.push(pattern);
    }
  }

  // Check for potential collisions
  for (const [prefix, patterns] of seenPrefixes) {
    if (patterns.length > 1) {
      // Check if they could collide (same seed count, similar structure)
      const uniquePatterns = new Set(patterns.map(p => p.split(',').length));
      if (uniquePatterns.size < patterns.length) {
        findings.push({
          id: 'SOL070',
          severity: 'high',
          title: 'Potential PDA Seed Collision',
          description: `Multiple PDAs use prefix '${prefix}' with same seed count - potential collision`,
          location: input.path,
          recommendation: 'Use unique string prefixes/discriminators for each PDA type',
        });
      }
    }
  }

  // Check for user-controlled seeds without discriminator
  const userControlledSeed = /find_program_address[\s\S]*?user\s*\.|\.key\(\)|pubkey/i;
  if (userControlledSeed.test(rust.content)) {
    // Check if there's a string literal discriminator
    const hasDiscriminator = /find_program_address\s*\(\s*&?\[\s*b"/;
    if (!hasDiscriminator.test(rust.content)) {
      findings.push({
        id: 'SOL070',
        severity: 'high',
        title: 'User-Controlled Seeds Without Discriminator',
        description: 'PDA derived from user input without a unique string discriminator',
        location: input.path,
        recommendation: 'Include a unique byte string prefix: [b"my_pda_type", user.key().as_ref()]',
      });
    }
  }

  // Check for variable-length seed without separator
  const variableSeed = /\.as_bytes\(\)|\.to_le_bytes\(\)|\.as_ref\(\)/;
  if (variableSeed.test(rust.content) && rust.content.includes('find_program_address')) {
    const multipleVarSeeds = (rust.content.match(/\.as_bytes\(\)|\.to_le_bytes\(\)/g) || []).length;
    if (multipleVarSeeds >= 2) {
      findings.push({
        id: 'SOL070',
        severity: 'medium',
        title: 'Multiple Variable-Length Seeds',
        description: 'Multiple variable-length seeds may create collision opportunities',
        location: input.path,
        recommendation: 'Use fixed-length seeds or add separator bytes between variable seeds',
      });
    }
  }

  // Check for cross-program PDA collision risk
  if (rust.content.includes('find_program_address') && 
      (rust.content.includes('invoke_signed') || rust.content.includes('CpiContext'))) {
    // Check if using another program's ID for PDA
    const crossProgram = /find_program_address[\s\S]*?(?:token_program|other_program|external)/i;
    if (crossProgram.test(rust.content)) {
      findings.push({
        id: 'SOL070',
        severity: 'medium',
        title: 'Cross-Program PDA Derivation',
        description: 'PDA derived using external program ID - ensure seed uniqueness',
        location: input.path,
        recommendation: 'Include your program ID or unique discriminator to prevent collision with other programs',
      });
    }
  }

  return findings;
}
