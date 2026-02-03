import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL102: Instruction Data Handling
 * Detects issues with instruction data parsing and validation
 */
export function checkInstructionData(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;

  if (!rust || !rust.content) return findings;

  // Check for raw instruction_data access
  if (rust.content.includes('instruction_data') && !rust.content.includes('#[derive(')) {
    if (!rust.content.includes('borsh') && !rust.content.includes('AnchorDeserialize')) {
      findings.push({
        id: 'SOL102',
        severity: 'high',
        title: 'Raw Instruction Data Parsing',
        description: 'Parsing instruction_data without structured deserialization',
        location: input.path,
        recommendation: 'Use Borsh or Anchor deserialize for type-safe parsing',
      });
    }
  }

  // Check for instruction data length validation
  if (rust.content.includes('instruction_data') || rust.content.includes('data.len()')) {
    if (!rust.content.includes('len()') || !rust.content.includes('>=')) {
      findings.push({
        id: 'SOL102',
        severity: 'medium',
        title: 'No Instruction Data Length Check',
        description: 'Instruction data accessed without length validation',
        location: input.path,
        recommendation: 'Verify data.len() >= expected_size before parsing',
      });
    }
  }

  return findings;
}
