import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL114: Instruction Sysvar Usage
 * Detects issues with instruction sysvar access
 */
export function checkInstructionSysvar(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;

  if (!rust || !rust.content) return findings;

  if (!rust.content.includes('Instructions') && !rust.content.includes('sysvar::instructions')) {
    return findings;
  }

  // Check for instruction introspection
  if (rust.content.includes('load_instruction_at') || rust.content.includes('get_instruction_relative')) {
    findings.push({
      id: 'SOL114',
      severity: 'medium',
      title: 'Instruction Introspection',
      description: 'Program inspects other instructions - ensure this is necessary',
      location: input.path,
      recommendation: 'Validate instruction introspection is for legitimate purposes (e.g., atomic swaps)',
    });
  }

  // Check for instruction sysvar without validation
  if (rust.content.includes('Instructions::id()') && !rust.content.includes('key ==')) {
    findings.push({
      id: 'SOL114',
      severity: 'high',
      title: 'Instruction Sysvar Not Validated',
      description: 'Using instruction sysvar without verifying account is actually the sysvar',
      location: input.path,
      recommendation: 'Verify account.key == sysvar::instructions::ID',
    });
  }

  return findings;
}
