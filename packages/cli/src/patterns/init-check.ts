import type { Finding } from '../commands/audit.js';
import type { ParsedRust } from '../parsers/rust.js';
import type { PatternInput } from './index.js';

/**
 * SOL006: Missing Initialization Check
 * 
 * Detects accounts that may be used without verifying they've been initialized.
 * The famous Wormhole hack ($320M) was caused by this vulnerability.
 */
export function checkMissingInitCheck(input: PatternInput): Finding[] {
  const rust = input.rust;
  const findings: Finding[] = [];
  
  if (!rust?.files) return findings;
  
  let counter = 1;
  
  for (const file of rust.files) {
    const lines = file.content.split('\n');
    
    // Track account structs and their initialization checks
    let inAccountStruct = false;
    let structName = '';
    let accounts: { name: string; line: number; hasInitCheck: boolean; hasInitConstraint: boolean }[] = [];
    
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const lineNum = i + 1;
      
      // Detect #[derive(Accounts)] struct
      if (line.includes('#[derive(Accounts)]')) {
        inAccountStruct = true;
        accounts = [];
        continue;
      }
      
      // Get struct name
      if (inAccountStruct && line.includes('struct')) {
        const match = line.match(/struct\s+(\w+)/);
        if (match) {
          structName = match[1];
        }
        continue;
      }
      
      // Track accounts in the struct
      if (inAccountStruct) {
        // Check for init constraint (this is safe)
        const hasInitConstraint = /\binit\b/.test(lines.slice(Math.max(0, i - 3), i + 1).join('\n'));
        
        // Check for init_if_needed constraint
        const hasInitIfNeeded = /init_if_needed/.test(lines.slice(Math.max(0, i - 3), i + 1).join('\n'));
        
        // Detect account field
        const accountMatch = line.match(/pub\s+(\w+):\s*Account<'info,\s*(\w+)>/);
        if (accountMatch) {
          const [, accountName, accountType] = accountMatch;
          
          // Check if there's an "initialized" or "is_initialized" check nearby
          const context = lines.slice(Math.max(0, i - 5), Math.min(lines.length, i + 5)).join('\n');
          const hasInitCheck = /is_initialized|initialized\s*==\s*true|\.initialized/.test(context);
          
          accounts.push({
            name: accountName,
            line: lineNum,
            hasInitCheck: hasInitCheck || hasInitConstraint,
            hasInitConstraint: hasInitConstraint || hasInitIfNeeded,
          });
        }
        
        // End of struct
        if (line.includes('}') && !line.includes('{')) {
          // Report accounts without init checks (that aren't being initialized)
          for (const account of accounts) {
            if (!account.hasInitCheck && !account.hasInitConstraint) {
              // Check if this account is used later without initialization check
              const laterContent = lines.slice(i).join('\n');
              const usedWithoutCheck = new RegExp(`${account.name}\\s*\\.`).test(laterContent) &&
                                       !new RegExp(`${account.name}.*is_initialized`).test(laterContent);
              
              if (usedWithoutCheck) {
                findings.push({
                  id: `SOL006-${counter++}`,
                  pattern: 'missing-init-check',
                  severity: 'critical',
                  title: `Account '${account.name}' may lack initialization verification`,
                  description: `The account '${account.name}' in '${structName}' is used without verifying it has been initialized. An attacker could pass an uninitialized account with arbitrary data, potentially leading to undefined behavior or exploits. This is the same vulnerability class that caused the $320M Wormhole hack.`,
                  location: {
                    file: file.path,
                    line: account.line,
                  },
                  code: `pub ${account.name}: Account<'info, ...>`,
                  suggestion: `Add initialization verification:

Option 1 - Add is_initialized field to your account struct:
#[account]
pub struct YourAccount {
    pub is_initialized: bool,
    // ... other fields
}

Then check it:
require!(ctx.accounts.${account.name}.is_initialized, ErrorCode::NotInitialized);

Option 2 - Use Anchor's init constraint for new accounts:
#[account(init, payer = user, space = 8 + size)]
pub ${account.name}: Account<'info, YourAccount>,`,
                });
              }
            }
          }
          
          inAccountStruct = false;
          accounts = [];
        }
      }
      
      // Also detect direct UncheckedAccount usage (always risky)
      if (line.includes('UncheckedAccount') && !line.includes('/// CHECK:')) {
        // Look for CHECK comment above
        const prevLines = lines.slice(Math.max(0, i - 3), i).join('\n');
        if (!prevLines.includes('/// CHECK:') && !prevLines.includes('// CHECK:')) {
          findings.push({
            id: `SOL006-${counter++}`,
            pattern: 'unchecked-account',
            severity: 'high',
            title: 'UncheckedAccount without safety documentation',
            description: 'UncheckedAccount is used without a /// CHECK: comment explaining why it\'s safe. While sometimes necessary, unchecked accounts are a common source of vulnerabilities and should be documented.',
            location: {
              file: file.path,
              line: lineNum,
            },
            code: line.trim(),
            suggestion: `Add a CHECK comment explaining why this account is safe:
/// CHECK: This account is safe because [your reason here]
pub my_account: UncheckedAccount<'info>,

Or use a typed Account with appropriate constraints if possible.`,
          });
        }
      }
    }
  }
  
  return findings;
}
