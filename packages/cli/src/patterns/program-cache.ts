import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL101: Program Cache Considerations
 * Detects issues related to program caching and JIT
 */
export function checkProgramCache(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;

  if (!rust || !rust.content) return findings;

  // Check for large instruction handlers
  const fnBlocks = rust.content.match(/pub\s+fn\s+\w+[^}]+\{[\s\S]*?\n\}/g) || [];
  for (const fn of fnBlocks) {
    if (fn.length > 3000) {
      findings.push({
        id: 'SOL101',
        severity: 'low',
        title: 'Large Instruction Handler',
        description: 'Very large function may impact JIT compilation and caching',
        location: input.path,
        recommendation: 'Consider breaking into smaller helper functions',
      });
      break;
    }
  }

  // Check for excessive branching
  const branchCount = (rust.content.match(/if\s+|match\s+|else\s+if/g) || []).length;
  if (branchCount > 30) {
    findings.push({
      id: 'SOL101',
      severity: 'low',
      title: 'High Branch Complexity',
      description: `${branchCount} branches may slow JIT optimization`,
      location: input.path,
      recommendation: 'Consider lookup tables or dispatch patterns',
    });
  }

  return findings;
}
