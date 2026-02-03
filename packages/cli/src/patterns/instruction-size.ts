import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL127: Instruction Size Limits
 * Detects potential instruction size issues
 */
export function checkInstructionSize(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;

  if (!rust || !rust.content) return findings;

  // Check for large structs in instruction data
  const structMatches = rust.content.match(/#\[derive[\s\S]*?struct\s+\w+[\s\S]*?\}/g) || [];
  for (const struct of structMatches) {
    const fieldCount = (struct.match(/pub\s+\w+\s*:/g) || []).length;
    if (fieldCount > 20) {
      findings.push({
        id: 'SOL127',
        severity: 'medium',
        title: 'Large Instruction Struct',
        description: `Struct with ${fieldCount} fields may exceed transaction limits`,
        location: input.path,
        recommendation: 'Consider splitting into multiple instructions',
      });
      break;
    }
  }

  return findings;
}
