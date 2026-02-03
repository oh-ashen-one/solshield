import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL084: Account Constraints Order
 * Detects problematic constraint ordering that may cause unexpected behavior
 */
export function checkConstraintOrder(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;

  if (!rust || !rust.content) return findings;

  // Check for mut before init (init implies mut)
  const mutBeforeInit = /#\[account\([^)]*mut\s*,\s*init/;
  if (mutBeforeInit.test(rust.content)) {
    findings.push({
      id: 'SOL084',
      severity: 'low',
      title: 'Redundant mut with init',
      description: 'mut constraint is redundant when init is used - init implies mutability',
      location: input.path,
      recommendation: 'Remove mut when using init: #[account(init, ...)]',
    });
  }

  // Check for constraint evaluation order issues
  if (rust.content.includes('#[account(')) {
    // has_one before seeds can cause issues if the account doesn't exist yet
    const hasOneBeforeSeeds = /#\[account\([^)]*has_one[^)]*seeds/;
    if (hasOneBeforeSeeds.test(rust.content) && rust.content.includes('init')) {
      findings.push({
        id: 'SOL084',
        severity: 'medium',
        title: 'has_one Before seeds With init',
        description: 'has_one evaluated before account initialization may fail unexpectedly',
        location: input.path,
        recommendation: 'Order constraints: init, payer, space, seeds, bump, then has_one',
      });
    }
  }

  // Check for constraint after close
  const constraintAfterClose = /#\[account\([^)]*close\s*=[^)]*,\s*(?:mut|has_one|constraint)/;
  if (constraintAfterClose.test(rust.content)) {
    findings.push({
      id: 'SOL084',
      severity: 'low',
      title: 'Constraints After close',
      description: 'Constraints after close may not be evaluated - close should be last',
      location: input.path,
      recommendation: 'Put close = <destination> as the last constraint',
    });
  }

  // Check for realloc without proper ordering
  if (rust.content.includes('realloc')) {
    const reallocOrder = /#\[account\([^)]*realloc[^)]*(?:payer|zero)/;
    if (!reallocOrder.test(rust.content)) {
      findings.push({
        id: 'SOL084',
        severity: 'medium',
        title: 'Realloc Without Full Constraints',
        description: 'Realloc should include payer and zero constraints',
        location: input.path,
        recommendation: 'Use realloc = <size>, realloc::payer = <payer>, realloc::zero = true/false',
      });
    }
  }

  // Check for seeds_constraint order
  if (rust.content.includes('seeds::program')) {
    // seeds::program should come after seeds
    const seedsProgramFirst = /seeds::program[^)]*seeds\s*=/;
    if (seedsProgramFirst.test(rust.content)) {
      findings.push({
        id: 'SOL084',
        severity: 'low',
        title: 'seeds::program Before seeds',
        description: 'seeds should be defined before seeds::program for clarity',
        location: input.path,
        recommendation: 'Define seeds = [...] before seeds::program',
      });
    }
  }

  // Check for executable without owner check
  if (rust.content.includes('executable')) {
    if (!rust.content.includes('owner') && !rust.content.includes('program_id')) {
      findings.push({
        id: 'SOL084',
        severity: 'high',
        title: 'Executable Without Owner Check',
        description: 'Checking executable flag without verifying program owner',
        location: input.path,
        recommendation: 'Also verify the program owner/ID when checking executable',
      });
    }
  }

  return findings;
}
