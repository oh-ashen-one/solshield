import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL007: Cross-Program Invocation (CPI) Vulnerabilities
 * 
 * Detects risky CPI patterns including:
 * - invoke() without proper account validation
 * - Missing program ID verification before CPI
 * - invoke_signed() with potentially incorrect seeds
 */
export function checkCpiVulnerabilities(input: PatternInput): Finding[] {
  const rust = input.rust;
  const findings: Finding[] = [];
  
  if (!rust?.files) return findings;
  
  let counter = 1;
  
  for (const file of rust.files) {
    const lines = file.content.split('\n');
    
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const lineNum = i + 1;
      
      // Check for invoke() without program ID verification
      if (/\binvoke\s*\(/.test(line) && !line.includes('invoke_signed')) {
        // Look for program_id verification in surrounding context
        const context = lines.slice(Math.max(0, i - 10), Math.min(lines.length, i + 5)).join('\n');
        
        if (!/(program_id|program\.key\(\)).*==|require.*program/.test(context)) {
          findings.push({
            id: `SOL007-${counter++}`,
            pattern: 'cpi-vulnerability',
            severity: 'high',
            title: 'CPI invoke() without program ID verification',
            description: 'Cross-program invocation (invoke) is called without verifying the target program ID. An attacker could substitute a malicious program with the same interface, leading to arbitrary code execution with your program\'s privileges.',
            location: {
              file: file.path,
              line: lineNum,
            },
            code: line.trim(),
            suggestion: `Verify the program ID before CPI:
require_keys_eq!(target_program.key(), expected_program::ID, ErrorCode::InvalidProgram);
invoke(&instruction, &account_infos)?;`,
          });
        }
      }
      
      // Check for invoke_signed with hardcoded seeds (potential issue)
      if (/invoke_signed\s*\(/.test(line)) {
        const context = lines.slice(i, Math.min(lines.length, i + 10)).join('\n');
        
        // Look for seeds that don't include dynamic components
        if (/seeds\s*=\s*\[\s*b"[^"]+"\s*\]/.test(context) && !context.includes('.key()') && !context.includes('.as_ref()')) {
          findings.push({
            id: `SOL007-${counter++}`,
            pattern: 'cpi-static-seeds',
            severity: 'medium',
            title: 'invoke_signed() with static-only seeds',
            description: 'The PDA seeds for invoke_signed appear to contain only static values without any dynamic components (like user pubkey). This could lead to a single global PDA that any user can interact with, potentially causing unauthorized access.',
            location: {
              file: file.path,
              line: lineNum,
            },
            code: line.trim(),
            suggestion: `Include dynamic seeds to create user-specific PDAs:
let seeds = &[
    b"prefix",
    user.key().as_ref(),
    &[bump],
];`,
          });
        }
      }
      
      // Check for CPI to unchecked program
      if (/AccountInfo.*program/.test(line) && !/Program<'info/.test(line)) {
        const context = lines.slice(Math.max(0, i - 5), Math.min(lines.length, i + 10)).join('\n');
        
        if (/invoke/.test(context) && !/(executable|key\(\)\s*==|CHECK:)/.test(context)) {
          findings.push({
            id: `SOL007-${counter++}`,
            pattern: 'cpi-unchecked-program',
            severity: 'critical',
            title: 'CPI to unverified program account',
            description: 'A program account is passed as AccountInfo and used for CPI without verification. The account might not be executable or could be a different program than expected. Use Anchor\'s Program<> type or manually verify the executable flag and program ID.',
            location: {
              file: file.path,
              line: lineNum,
            },
            code: line.trim(),
            suggestion: `Use Anchor's Program type for automatic verification:
pub token_program: Program<'info, Token>,

Or manually verify:
require!(program_account.executable, ErrorCode::NotExecutable);
require_keys_eq!(program_account.key(), expected::ID, ErrorCode::InvalidProgram);`,
          });
        }
      }
    }
  }
  
  return findings;
}
