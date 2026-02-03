import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL115: State Transition Validation
 * Detects issues with state machine transitions
 */
export function checkStateTransition(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;

  if (!rust || !rust.content) return findings;

  // Check for state enum without transition validation
  if (rust.content.includes('enum') && 
      (rust.content.includes('State') || rust.content.includes('Status'))) {
    if (!rust.content.includes('match') || !rust.content.includes('=>')) {
      findings.push({
        id: 'SOL115',
        severity: 'medium',
        title: 'State Enum Without Match',
        description: 'State enum defined but no match expression for transitions',
        location: input.path,
        recommendation: 'Use match expressions to validate state transitions',
      });
    }
  }

  // Check for direct state assignment without validation
  const directAssign = /state\s*=\s*State::|status\s*=\s*Status::/;
  if (directAssign.test(rust.content)) {
    if (!rust.content.includes('current_state') && !rust.content.includes('old_state')) {
      findings.push({
        id: 'SOL115',
        severity: 'high',
        title: 'State Assignment Without Transition Check',
        description: 'State changed without validating current state allows transition',
        location: input.path,
        recommendation: 'Check current state before allowing transition to new state',
      });
    }
  }

  return findings;
}
