import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL028: Event Emission Issues
 * Missing or improperly structured event emissions for indexing.
 */
export function checkEventEmission(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (!input.rust || !input.rust.files) return findings;

  for (const file of input.rust.files) {
    const lines = file.lines;
    const content = file.content;

    // Track if this file has state-changing operations
    const stateChangingOps = ['transfer', 'mint', 'burn', 'swap', 'deposit', 'withdraw', 
                              'stake', 'unstake', 'claim', 'initialize'];
    
    const hasStateChange = stateChangingOps.some(op => 
      content.toLowerCase().includes(op) && content.includes('pub fn'));
    
    const hasEmit = content.includes('emit!') || content.includes('emit_cpi!') || 
                    content.includes('msg!') || content.includes('sol_log');

    // Check for state-changing functions without events
    if (hasStateChange && !hasEmit) {
      lines.forEach((line, index) => {
        const lineNum = index + 1;

        if (line.includes('pub fn')) {
          const fnNameMatch = line.match(/pub fn\s+(\w+)/);
          if (fnNameMatch) {
            const fnName = fnNameMatch[1].toLowerCase();
            if (stateChangingOps.some(op => fnName.includes(op))) {
              findings.push({
                id: `SOL028-${findings.length + 1}`,
                pattern: 'Event Emission Issues',
                severity: 'low',
                title: `State-changing function '${fnNameMatch[1]}' without event emission`,
                description: 'State-changing operations should emit events for off-chain indexing and monitoring.',
                location: { file: file.path, line: lineNum },
                suggestion: 'Add emit! macro with relevant event data for indexers and frontends.',
              });
            }
          }
        }
      });
    }

    // Check for events with missing critical fields
    lines.forEach((line, index) => {
      const lineNum = index + 1;

      if (line.includes('#[event]') || line.includes('#[derive(') && line.includes('Event')) {
        const contextEnd = Math.min(lines.length, index + 15);
        const eventStruct = lines.slice(index, contextEnd).join('\n');
        
        // Check for common missing fields
        const hasTimestamp = eventStruct.includes('timestamp') || eventStruct.includes('slot');
        const hasUser = eventStruct.includes('user') || eventStruct.includes('authority') || 
                        eventStruct.includes('owner') || eventStruct.includes('signer');

        if (!hasTimestamp && !hasUser) {
          findings.push({
            id: `SOL028-${findings.length + 1}`,
            pattern: 'Event Emission Issues',
            severity: 'info',
            title: 'Event may be missing important fields',
            description: 'Events typically need timestamp/slot and user/authority for proper indexing.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Consider adding timestamp (or slot) and user pubkey fields to events.',
          });
        }
      }
    });
  }

  return findings;
}
