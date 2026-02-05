import type { Finding } from '../commands/audit.js';
import type { ParsedRust } from '../parsers/rust.js';

/**
 * Checked Math Requirements
 * Based on: BlockSec integer overflow bug in Solana rBPF
 *           Sec3's arithmetic overflow/underflow research
 * 
 * Direct arithmetic operations (+, -, *, /, %) in Rust can overflow/underflow.
 * Must use checked_ or saturating_ variants for safety.
 */
export function checkCheckedMathRequired(parsed: ParsedRust): Finding[] {
  const findings: Finding[] = [];
  const content = parsed.content;

  // Skip if already using checked math consistently
  const checkedMathUsage = (content.match(/checked_|saturating_/g) || []).length;
  const directMathUsage = (content.match(/[^a-z_][\+\-\*\/]\s*=|=\s*[^=]*[\+\-\*\/][^=]/g) || []).length;

  // Detect specific dangerous patterns
  const dangerousPatterns = [
    {
      pattern: /(\w+)\s*\+\s*(\w+)|(\w+)\s*-\s*(\w+)/g,
      name: 'addition/subtraction',
      safe: /checked_add|checked_sub|saturating_add|saturating_sub/,
    },
    {
      pattern: /(\w+)\s*\*\s*(\w+)/g,
      name: 'multiplication',
      safe: /checked_mul|saturating_mul/,
    },
    {
      pattern: /(\w+)\s*\/\s*(\w+)/g,
      name: 'division',
      safe: /checked_div|checked_rem/,
    },
    {
      pattern: /(\w+)\s*\*\*\s*(\w+)|\.pow\(/g,
      name: 'exponentiation',
      safe: /checked_pow|saturating_pow/,
    },
  ];

  // Check for lamport/token amount calculations without checked math
  const amountPatterns = [
    /lamports?\s*[\+\-\*\/]/gi,
    /amount\s*[\+\-\*\/]/gi,
    /balance\s*[\+\-\*\/]/gi,
    /supply\s*[\+\-\*\/]/gi,
    /fee\s*[\+\-\*\/]/gi,
  ];

  for (const pattern of amountPatterns) {
    const matches = content.match(pattern);
    if (matches) {
      // Check if nearby code uses checked math
      const contextWindow = 200;
      for (const match of matches) {
        const idx = content.indexOf(match);
        const context = content.slice(Math.max(0, idx - contextWindow), Math.min(content.length, idx + contextWindow));
        
        if (!/checked_|saturating_|\.unwrap_or\(0\)/i.test(context)) {
          findings.push({
            severity: 'high',
            category: 'checked-math',
            title: 'Financial Calculation Without Checked Arithmetic',
            description: `Found "${match.trim()}" without checked arithmetic. ` +
              'Financial calculations (lamports, amounts, balances) must use checked_* or saturating_* methods.',
            recommendation: 'Replace with: value.checked_add(other).ok_or(ErrorCode::Overflow)?',
            location: parsed.path,
          });
          break; // One finding per pattern type
        }
      }
    }
  }

  // Check for u64/u128 operations that could overflow
  const largeIntOps = /(u64|u128|i64|i128)\s*[\+\-\*]/g;
  if (largeIntOps.test(content)) {
    if (checkedMathUsage < directMathUsage / 2) {
      findings.push({
        severity: 'medium',
        category: 'checked-math',
        title: 'Large Integer Operations May Need Checked Arithmetic',
        description: 'Operations on u64/u128 types detected. ' +
          'Ensure all operations that could overflow use checked arithmetic.',
        recommendation: 'Audit all arithmetic on large integers. ' +
          'Consider using the checked-math crate: https://github.com/blockworks-foundation/checked-math',
        location: parsed.path,
      });
    }
  }

  // Check for percentage/basis points calculations
  if (/percent|basis.*?point|bps|rate/i.test(content)) {
    const hasSafeCalc = /checked_mul.*?checked_div|\.mul\(.*?\)\.div\(/i.test(content);
    if (!hasSafeCalc) {
      findings.push({
        severity: 'high',
        category: 'checked-math',
        title: 'Percentage Calculation May Overflow',
        description: 'Percentage/basis points calculations can overflow before division. ' +
          'Example: amount * rate / 10000 can overflow on the multiplication.',
        recommendation: 'Use u128 for intermediate calculations or checked_mul before checked_div. ' +
          'Consider: (amount as u128).checked_mul(rate as u128)?.checked_div(10000)?',
        location: parsed.path,
      });
    }
  }

  // Check for division without zero check
  const divisionPattern = /\/\s*(\w+)/g;
  const divisions = content.match(divisionPattern);
  if (divisions) {
    const hasZeroCheck = /==\s*0|!=\s*0|is_zero\(\)|> 0/i.test(content);
    if (!hasZeroCheck) {
      findings.push({
        severity: 'high',
        category: 'checked-math',
        title: 'Division Without Zero Check',
        description: 'Division operations found without apparent zero-denominator check. ' +
          'Division by zero will panic.',
        recommendation: 'Use checked_div which returns None for division by zero, ' +
          'or explicitly check denominator before division.',
        location: parsed.path,
      });
    }
  }

  return findings;
}
