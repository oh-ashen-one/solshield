import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL010: Account Closing Vulnerabilities
 * 
 * Detects issues with account closure:
 * - Closing accounts without zeroing data (revival attack)
 * - Missing rent refund
 * - Closing to wrong recipient
 */
export function checkClosingVulnerabilities(input: PatternInput): Finding[] {
  const rust = input.rust;
  const findings: Finding[] = [];
  
  if (!rust?.files) return findings;
  
  let counter = 1;
  
  for (const file of rust.files) {
    const lines = file.content.split('\n');
    const content = file.content;
    
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const lineNum = i + 1;
      
      // Pattern 1: Manual lamport transfer without zeroing data
      // (closing account by transferring all lamports)
      if (/lamports.*=\s*0|\.sub\(.*lamports\)|transfer.*lamports/.test(line)) {
        const context = lines.slice(i, Math.min(lines.length, i + 10)).join('\n');
        
        // Check if data is zeroed
        if (!/(realloc|data.*=.*\[0|zero|clear|close\s*=)/.test(context)) {
          findings.push({
            id: `SOL010-${counter++}`,
            pattern: 'closing-without-zeroing',
            severity: 'critical',
            title: 'Account closed without zeroing data',
            description: 'Lamports are being removed from an account (closing it) but the data is not being zeroed. An attacker can "revive" the account by sending lamports back before the runtime garbage collects it, potentially reusing stale data for exploits.',
            location: {
              file: file.path,
              line: lineNum,
            },
            code: line.trim(),
            suggestion: `Zero the account data before closing:
// Zero the data
account.data.borrow_mut().fill(0);

// Or use Anchor's close constraint:
#[account(mut, close = recipient)]
pub account_to_close: Account<'info, MyData>,`,
          });
        }
      }
      
      // Pattern 2: close constraint without specifying recipient
      if (/#\[account\([^)]*close\s*[,\)]/.test(line) && !/#\[account\([^)]*close\s*=/.test(line)) {
        findings.push({
          id: `SOL010-${counter++}`,
          pattern: 'close-missing-recipient',
          severity: 'medium',
          title: 'Account close without explicit recipient',
          description: 'The close constraint is used but no recipient is specified for the rent refund. This could lead to funds being sent to an unintended address.',
          location: {
            file: file.path,
            line: lineNum,
          },
          code: line.trim(),
          suggestion: `Specify the recipient for the rent refund:
#[account(mut, close = authority)]
pub account_to_close: Account<'info, MyData>,`,
        });
      }
      
      // Pattern 3: Closing to unchecked account
      if (/#\[account\([^)]*close\s*=\s*(\w+)/.test(line)) {
        const match = line.match(/close\s*=\s*(\w+)/);
        if (match) {
          const recipient = match[1];
          
          // Check if recipient is validated
          const recipientPattern = new RegExp(`${recipient}.*Signer|${recipient}.*authority|has_one.*${recipient}`, 'i');
          if (!recipientPattern.test(content)) {
            findings.push({
              id: `SOL010-${counter++}`,
              pattern: 'close-to-unvalidated',
              severity: 'high',
              title: `Account closes to unvalidated recipient '${recipient}'`,
              description: `The account is closed with rent sent to '${recipient}', but this recipient doesn't appear to be validated. An attacker might be able to specify their own address to receive the rent.`,
              location: {
                file: file.path,
                line: lineNum,
              },
              code: line.trim(),
              suggestion: `Ensure the close recipient is validated:
#[account(
    mut,
    close = authority,
    has_one = authority  // Validate authority owns this account
)]
pub account_to_close: Account<'info, MyData>,

pub authority: Signer<'info>,  // Must sign`,
            });
          }
        }
      }
      
      // Pattern 4: Realloc to zero without proper handling
      if (/realloc\s*\(\s*0/.test(line)) {
        const context = lines.slice(Math.max(0, i - 5), Math.min(lines.length, i + 5)).join('\n');
        
        if (!/close|lamports/.test(context)) {
          findings.push({
            id: `SOL010-${counter++}`,
            pattern: 'realloc-zero-incomplete',
            severity: 'medium',
            title: 'Account reallocated to zero size',
            description: 'The account is reallocated to zero size but may not be properly closed. The account will still exist with zero data but non-zero lamports, which could cause confusion.',
            location: {
              file: file.path,
              line: lineNum,
            },
            code: line.trim(),
            suggestion: `Use Anchor's close constraint for proper account closure:
#[account(mut, close = recipient)]

Or manually transfer all lamports after realloc.`,
          });
        }
      }
    }
  }
  
  return findings;
}
