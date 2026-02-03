import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL029: Instruction Introspection Issues
 * Improper use of instruction introspection.
 */
export function checkInstructionIntrospection(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (!input.rust || !input.rust.files) return findings;

  for (const file of input.rust.files) {
    const lines = file.lines;
    const content = file.content;

    lines.forEach((line, index) => {
      const lineNum = index + 1;

      // Pattern 1: Using instruction sysvar without validation
      if (line.includes('Instructions') || line.includes('get_instruction_relative')) {
        const contextStart = Math.max(0, index - 5);
        const contextEnd = Math.min(lines.length, index + 10);
        const context = lines.slice(contextStart, contextEnd).join('\n');

        if (!context.includes('check_id') && !context.includes('program_id') && 
            !context.includes('sysvar::instructions')) {
          findings.push({
            id: `SOL029-${findings.length + 1}`,
            pattern: 'Instruction Introspection Issues',
            severity: 'high',
            title: 'Instruction introspection without validation',
            description: 'Using instruction sysvar without validating the account is actually the Instructions sysvar.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Validate sysvar::instructions::check_id(&account.key) before introspection.',
          });
        }
      }

      // Pattern 2: Hardcoded instruction indices
      if (line.includes('get_instruction_relative') || line.includes('load_instruction_at')) {
        if (line.match(/\(\s*-?\d+\s*[,)]/)) {
          findings.push({
            id: `SOL029-${findings.length + 1}`,
            pattern: 'Instruction Introspection Issues',
            severity: 'medium',
            title: 'Hardcoded instruction index',
            description: 'Using fixed instruction index. Transaction structure could change, breaking assumptions.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Iterate through instructions to find the expected one, or validate transaction structure.',
          });
        }
      }

      // Pattern 3: Checking only program_id without data validation
      if (content.includes('get_instruction') && line.includes('program_id')) {
        const contextEnd = Math.min(lines.length, index + 10);
        const afterContext = lines.slice(index, contextEnd).join('\n');

        if (!afterContext.includes('data') && !afterContext.includes('deserialize') &&
            afterContext.includes('==')) {
          findings.push({
            id: `SOL029-${findings.length + 1}`,
            pattern: 'Instruction Introspection Issues',
            severity: 'medium',
            title: 'Instruction program_id check without data validation',
            description: 'Verifying only program_id. Attacker could call with different instruction data.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Also validate instruction data/discriminator matches expected instruction.',
          });
        }
      }

      // Pattern 4: Reentrancy via instruction introspection bypass
      if (line.includes('current_index') || line.includes('instruction_at_verified')) {
        const contextStart = Math.max(0, index - 15);
        const context = lines.slice(contextStart, index + 5).join('\n').toLowerCase();

        if ((context.includes('transfer') || context.includes('invoke')) &&
            !context.includes('lock') && !context.includes('reentrancy')) {
          findings.push({
            id: `SOL029-${findings.length + 1}`,
            pattern: 'Instruction Introspection Issues',
            severity: 'high',
            title: 'Potential reentrancy via instruction manipulation',
            description: 'CPI with instruction introspection. Attacker could craft transaction to bypass checks.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Ensure instruction introspection checks cannot be bypassed via CPI manipulation.',
          });
        }
      }
    });
  }

  return findings;
}
