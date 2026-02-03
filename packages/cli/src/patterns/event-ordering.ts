import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL088: Event Ordering and Emission
 * Detects issues with event emission timing and completeness
 */
export function checkEventOrdering(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;

  if (!rust || !rust.content) return findings;

  const hasEvents = rust.content.includes('emit!') || 
                    rust.content.includes('#[event]') ||
                    rust.content.includes('Event');

  if (!hasEvents) return findings;

  // Check for events emitted before state changes complete
  const eventBeforeState = /emit![\s\S]*?(?:account|state|data)\s*\./;
  if (eventBeforeState.test(rust.content)) {
    // Check if emit comes before the final state mutation
    const emitThenMutate = /emit![\s\S]{0,200}(?:\.try_borrow_mut|mut\s+\w+\s*=)/;
    if (emitThenMutate.test(rust.content)) {
      findings.push({
        id: 'SOL088',
        severity: 'medium',
        title: 'Event Before State Finalization',
        description: 'Event emitted before state changes are complete - may emit incorrect values',
        location: input.path,
        recommendation: 'Emit events after all state modifications are complete',
      });
    }
  }

  // Check for missing events on critical operations
  const criticalOps = ['transfer', 'mint', 'burn', 'close', 'initialize', 'withdraw', 'deposit'];
  for (const op of criticalOps) {
    const hasOp = new RegExp(`fn\\s+${op}|${op}\\s*\\(`, 'i').test(rust.content);
    if (hasOp && !rust.content.includes('emit!')) {
      findings.push({
        id: 'SOL088',
        severity: 'low',
        title: `No Event for ${op} Operation`,
        description: `Critical operation '${op}' does not emit an event for indexing`,
        location: input.path,
        recommendation: `Add emit!(${op.charAt(0).toUpperCase() + op.slice(1)}Event { ... }) for indexers`,
      });
      break; // Only report once
    }
  }

  // Check for events in error paths
  if (rust.content.includes('emit!') && rust.content.includes('Err(')) {
    const emitAfterError = /Err\([^)]*\)[\s\S]{0,50}emit!/;
    if (emitAfterError.test(rust.content)) {
      findings.push({
        id: 'SOL088',
        severity: 'medium',
        title: 'Event After Error Return',
        description: 'Event emit may be unreachable after error return',
        location: input.path,
        recommendation: 'Emit events before returning errors, or remove unreachable emits',
      });
    }
  }

  // Check for event with insufficient data
  if (rust.content.includes('emit!')) {
    const sparseEvent = /emit!\s*\(\s*\w+\s*{\s*}\s*\)/;
    if (sparseEvent.test(rust.content)) {
      findings.push({
        id: 'SOL088',
        severity: 'low',
        title: 'Empty Event Emission',
        description: 'Event emitted with no data fields',
        location: input.path,
        recommendation: 'Include relevant data in events for indexer usefulness',
      });
    }
  }

  // Check for events without timestamp/slot
  if (rust.content.includes('#[event]') && rust.content.includes('pub struct')) {
    if (!rust.content.includes('timestamp') && !rust.content.includes('slot')) {
      findings.push({
        id: 'SOL088',
        severity: 'low',
        title: 'Event Without Timing Information',
        description: 'Event struct lacks timestamp or slot field for ordering',
        location: input.path,
        recommendation: 'Add timestamp: i64 or slot: u64 to event for temporal ordering',
      });
    }
  }

  // Check for conditional event emission
  if (rust.content.includes('emit!') && rust.content.includes('if ')) {
    const conditionalEmit = /if\s+[^{]*{[\s\S]*?emit!/;
    if (conditionalEmit.test(rust.content)) {
      findings.push({
        id: 'SOL088',
        severity: 'low',
        title: 'Conditional Event Emission',
        description: 'Event only emitted conditionally - may miss indexing some operations',
        location: input.path,
        recommendation: 'Ensure all code paths emit appropriate events for consistency',
      });
    }
  }

  return findings;
}
