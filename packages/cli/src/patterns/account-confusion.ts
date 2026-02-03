import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL009: Account Type Confusion
 * 
 * Detects when accounts might be confused for each other:
 * - Similar account names without type discrimination
 * - Missing account type validation
 * - Accounts that could be swapped by attacker
 */
export function checkAccountConfusion(input: PatternInput): Finding[] {
  const rust = input.rust;
  const findings: Finding[] = [];
  
  if (!rust?.files) return findings;
  
  let counter = 1;
  
  for (const file of rust.files) {
    const lines = file.content.split('\n');
    const content = file.content;
    
    // Find all account declarations in Accounts structs
    const accountPattern = /pub\s+(\w+):\s*(Account|AccountInfo|UncheckedAccount)<'info(?:,\s*(\w+))?>/g;
    const accounts: { name: string; type: string; dataType?: string; line: number }[] = [];
    
    let match;
    while ((match = accountPattern.exec(content)) !== null) {
      const lineNum = content.substring(0, match.index).split('\n').length;
      accounts.push({
        name: match[1],
        type: match[2],
        dataType: match[3],
        line: lineNum,
      });
    }
    
    // Check for potentially confusable accounts
    for (let i = 0; i < accounts.length; i++) {
      for (let j = i + 1; j < accounts.length; j++) {
        const a = accounts[i];
        const b = accounts[j];
        
        // Same underlying data type but different names (could be swapped)
        if (a.dataType && a.dataType === b.dataType && a.type === 'Account') {
          // Check if there's discrimination logic
          const hasDiscrimination = new RegExp(
            `(${a.name}|${b.name}).*!=.*(${a.name}|${b.name})|` +
            `require.*${a.name}.*${b.name}|` +
            `constraint.*${a.name}.*!=.*${b.name}`
          ).test(content);
          
          if (!hasDiscrimination) {
            findings.push({
              id: `SOL009-${counter++}`,
              pattern: 'account-confusion',
              severity: 'high',
              title: `Accounts '${a.name}' and '${b.name}' may be confusable`,
              description: `Both '${a.name}' and '${b.name}' are of type ${a.dataType}. An attacker might pass the same account for both, or swap them, leading to unexpected behavior. This is especially dangerous in transfer/swap operations.`,
              location: {
                file: file.path,
                line: a.line,
              },
              suggestion: `Add constraints to ensure accounts are different:
#[account(
    constraint = ${a.name}.key() != ${b.name}.key() @ ErrorCode::SameAccount
)]

Or use different account types/discriminators for different purposes.`,
            });
          }
        }
      }
    }
    
    // Check for AccountInfo used where typed Account would be safer
    for (const account of accounts) {
      if (account.type === 'AccountInfo' || account.type === 'UncheckedAccount') {
        // Skip known safe patterns
        if (/system_program|rent|clock|token_program|^_/.test(account.name)) continue;
        
        // Check if there's a CHECK comment
        const lineContent = lines[account.line - 1] || '';
        const prevLines = lines.slice(Math.max(0, account.line - 4), account.line).join('\n');
        
        if (!prevLines.includes('CHECK:')) {
          // Check if data is read from this account
          const usagePattern = new RegExp(`${account.name}\\s*\\.\\s*(data|try_borrow_data|deserialize)`);
          if (usagePattern.test(content)) {
            findings.push({
              id: `SOL009-${counter++}`,
              pattern: 'untyped-account-data-access',
              severity: 'high',
              title: `Untyped account '${account.name}' has data accessed`,
              description: `The account '${account.name}' is declared as ${account.type} but its data is accessed. Without type validation, an attacker could pass any account with arbitrary data, potentially bypassing security checks.`,
              location: {
                file: file.path,
                line: account.line,
              },
              code: lineContent.trim(),
              suggestion: `Use a typed Account instead:
pub ${account.name}: Account<'info, YourDataType>,

Or manually validate the account discriminator:
let data = ${account.name}.try_borrow_data()?;
require!(data[..8] == YourDataType::DISCRIMINATOR, ErrorCode::InvalidAccount);`,
            });
          }
        }
      }
    }
  }
  
  return findings;
}
