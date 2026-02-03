import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL030: Anchor Macro Misuse
 * Common mistakes when using Anchor macros.
 */
export function checkAnchorMacros(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (!input.rust || !input.rust.files) return findings;

  for (const file of input.rust.files) {
    const lines = file.lines;
    const content = file.content;

    // Skip if not an Anchor program
    if (!content.includes('use anchor_lang') && !content.includes('anchor_lang::')) {
      continue;
    }

    lines.forEach((line, index) => {
      const lineNum = index + 1;

      // Pattern 1: #[account(init)] without payer
      if (line.includes('#[account(') && line.includes('init')) {
        const constraintEnd = line.includes(')]') ? index : Math.min(lines.length, index + 3);
        const constraint = lines.slice(index, constraintEnd + 1).join(' ');

        if (!constraint.includes('payer')) {
          findings.push({
            id: `SOL030-${findings.length + 1}`,
            pattern: 'Anchor Macro Misuse',
            severity: 'high',
            title: 'init constraint without payer',
            description: 'Account initialization requires a payer. This will cause a compile error or unexpected behavior.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Add payer: #[account(init, payer = authority, space = 8 + ...)]',
          });
        }

        if (!constraint.includes('space')) {
          findings.push({
            id: `SOL030-${findings.length + 1}`,
            pattern: 'Anchor Macro Misuse',
            severity: 'medium',
            title: 'init constraint without explicit space',
            description: 'Account initialization without explicit space calculation.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Add space: #[account(init, payer = x, space = 8 + DataStruct::SIZE)]',
          });
        }
      }

      // Pattern 2: has_one without @ error
      if (line.includes('has_one =') && !line.includes('@')) {
        findings.push({
          id: `SOL030-${findings.length + 1}`,
          pattern: 'Anchor Macro Misuse',
          severity: 'low',
          title: 'has_one without custom error',
          description: 'has_one constraint without custom error code gives generic error messages.',
          location: { file: file.path, line: lineNum },
          suggestion: 'Add custom error: has_one = authority @ MyError::Unauthorized',
        });
      }

      // Pattern 3: constraint without @ error
      if (line.includes('constraint =') && line.includes('==') && !line.includes('@')) {
        findings.push({
          id: `SOL030-${findings.length + 1}`,
          pattern: 'Anchor Macro Misuse',
          severity: 'low',
          title: 'constraint without custom error',
          description: 'Custom constraints should have custom error codes for clarity.',
          location: { file: file.path, line: lineNum },
          suggestion: 'Add error: constraint = condition @ MyError::ConstraintFailed',
        });
      }

      // Pattern 4: Using Account<> for token accounts instead of InterfaceAccount
      if (line.includes("Account<'info, TokenAccount>") && !line.includes('Interface')) {
        findings.push({
          id: `SOL030-${findings.length + 1}`,
          pattern: 'Anchor Macro Misuse',
          severity: 'low',
          title: 'Using Account instead of InterfaceAccount for tokens',
          description: 'For Token-2022 compatibility, use InterfaceAccount instead of Account for token accounts.',
          location: { file: file.path, line: lineNum },
          suggestion: "Change to InterfaceAccount<'info, TokenAccount> for Token-2022 support.",
        });
      }

      // Pattern 5: close without proper zeroing
      if (line.includes('close =')) {
        const contextStart = Math.max(0, index - 5);
        const context = lines.slice(contextStart, index + 1).join('\n');

        if (context.includes('mut') && !context.includes('zero')) {
          // This is actually handled by Anchor, but worth noting for manual close patterns
          findings.push({
            id: `SOL030-${findings.length + 1}`,
            pattern: 'Anchor Macro Misuse',
            severity: 'info',
            title: 'Account closure detected',
            description: 'Anchor close attribute zeroes account data automatically. Ensure no references remain.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Verify account cannot be resurrected by sending lamports before transaction ends.',
          });
        }
      }
    });
  }

  return findings;
}
