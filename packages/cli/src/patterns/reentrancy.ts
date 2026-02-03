import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL011: Cross-Program Reentrancy Risk
 * 
 * While Solana's single-threaded runtime prevents traditional reentrancy,
 * cross-program invocations can still lead to reentrancy-like bugs:
 * - State changes after CPI calls
 * - Reading state that CPI might have modified
 */
export function checkReentrancyRisk(input: PatternInput): Finding[] {
  const rust = input.rust;
  const findings: Finding[] = [];
  
  if (!rust?.files) return findings;
  
  let counter = 1;
  
  for (const file of rust.files) {
    const lines = file.content.split('\n');
    
    // Track function contexts
    let inFunction = false;
    let functionName = '';
    let functionStart = 0;
    let hasCpi = false;
    let cpiLine = 0;
    let stateChangesAfterCpi: { line: number; code: string }[] = [];
    let braceDepth = 0;
    
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const lineNum = i + 1;
      
      // Detect function start
      const fnMatch = line.match(/pub\s+fn\s+(\w+)/);
      if (fnMatch) {
        // Check previous function
        if (inFunction && hasCpi && stateChangesAfterCpi.length > 0) {
          findings.push({
            id: `SOL011-${counter++}`,
            pattern: 'cross-program-reentrancy',
            severity: 'high',
            title: `State modified after CPI in '${functionName}'`,
            description: `The function '${functionName}' modifies state after making a cross-program invocation. If the called program can call back into your program, this could lead to inconsistent state. This is similar to the reentrancy vulnerability in EVM but manifests differently in Solana.`,
            location: {
              file: file.path,
              line: cpiLine,
            },
            code: stateChangesAfterCpi.map(s => s.code).join('\n'),
            suggestion: `Move state changes BEFORE the CPI call (checks-effects-interactions pattern):

// 1. Check conditions
require!(condition, ErrorCode::Failed);

// 2. Update state FIRST
account.value = new_value;

// 3. Make CPI call LAST
invoke(...)?;`,
          });
        }
        
        inFunction = true;
        functionName = fnMatch[1];
        functionStart = lineNum;
        hasCpi = false;
        cpiLine = 0;
        stateChangesAfterCpi = [];
        braceDepth = 0;
      }
      
      // Track brace depth
      braceDepth += (line.match(/{/g) || []).length;
      braceDepth -= (line.match(/}/g) || []).length;
      
      // Detect function end
      if (inFunction && braceDepth <= 0 && line.includes('}')) {
        // Check this function
        if (hasCpi && stateChangesAfterCpi.length > 0) {
          findings.push({
            id: `SOL011-${counter++}`,
            pattern: 'cross-program-reentrancy',
            severity: 'high',
            title: `State modified after CPI in '${functionName}'`,
            description: `The function '${functionName}' modifies state after making a cross-program invocation. If the called program can call back into your program, this could lead to inconsistent state.`,
            location: {
              file: file.path,
              line: cpiLine,
            },
            suggestion: `Apply checks-effects-interactions pattern: update state before CPI calls.`,
          });
        }
        inFunction = false;
      }
      
      if (!inFunction) continue;
      
      // Detect CPI calls
      if (/\binvoke\s*\(|\binvoke_signed\s*\(/.test(line)) {
        hasCpi = true;
        cpiLine = lineNum;
      }
      
      // Detect state changes after CPI
      if (hasCpi) {
        const stateChangePatterns = [
          /\.\s*balance\s*=/, 
          /\.\s*amount\s*=/, 
          /\.\s*total\s*=/, 
          /\.\s*count\s*=/,
          /\.\s*value\s*=/,
          /\.\s*data\s*=/,
          /\.\s*owner\s*=/,
          /\.\s*authority\s*=/,
          /\.\s*state\s*=/,
          /\.\s*status\s*=/,
          /checked_add|checked_sub|checked_mul/, // Arithmetic that changes state
          /\.try_borrow_mut/, // Mutable borrows after CPI
        ];
        
        for (const pattern of stateChangePatterns) {
          if (pattern.test(line)) {
            stateChangesAfterCpi.push({
              line: lineNum,
              code: line.trim(),
            });
            break;
          }
        }
      }
    }
  }
  
  return findings;
}
