import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL008: Rounding Error Detection
 * 
 * Detects potential rounding issues in financial calculations:
 * - Division before multiplication (loss of precision)
 * - Truncation in token amount calculations
 * - Missing rounding direction specification
 */
export function checkRoundingErrors(input: PatternInput): Finding[] {
  const rust = input.rust;
  const findings: Finding[] = [];
  
  if (!rust?.files) return findings;
  
  let counter = 1;
  
  for (const file of rust.files) {
    const lines = file.content.split('\n');
    
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const lineNum = i + 1;
      
      // Skip comments
      if (line.trim().startsWith('//')) continue;
      
      // Pattern 1: Division followed by multiplication (precision loss)
      // e.g., (amount / total) * shares
      if (/\/.*\*/.test(line) || /\bdiv\s*\(.*\).*mul/.test(line)) {
        // Check if it's not already using checked math with rounding
        if (!/(ceil|floor|round|checked_div.*checked_mul)/.test(line)) {
          findings.push({
            id: `SOL008-${counter++}`,
            pattern: 'rounding-division-first',
            severity: 'medium',
            title: 'Division before multiplication may cause precision loss',
            description: 'Performing division before multiplication can lead to precision loss due to integer truncation. In financial calculations, this can result in users receiving fewer tokens than expected, or protocol fees being under-collected.',
            location: {
              file: file.path,
              line: lineNum,
            },
            code: line.trim(),
            suggestion: `Reorder to multiply before divide:
// Instead of: (amount / total) * shares
// Use: (amount * shares) / total

// Or use fixed-point math:
let result = amount
    .checked_mul(shares)?
    .checked_div(total)?;`,
          });
        }
      }
      
      // Pattern 2: Token amount calculations without decimals consideration
      if (/(amount|balance|tokens?).*\/.*10/.test(line) || /\/ 1_?000_?000/.test(line)) {
        if (!/decimals|DECIMALS|checked_div/.test(line)) {
          findings.push({
            id: `SOL008-${counter++}`,
            pattern: 'rounding-decimal-truncation',
            severity: 'low',
            title: 'Potential decimal truncation in token calculation',
            description: 'Division by powers of 10 (often for decimal conversion) without proper rounding may truncate small amounts. Consider whether rounding up or down is appropriate for your use case.',
            location: {
              file: file.path,
              line: lineNum,
            },
            code: line.trim(),
            suggestion: `Consider explicit rounding direction:
// Round down (default, favors protocol):
let amount = raw_amount / 10u64.pow(decimals);

// Round up (favors user):
let amount = (raw_amount + 10u64.pow(decimals) - 1) / 10u64.pow(decimals);`,
          });
        }
      }
      
      // Pattern 3: Fee calculations that might round to zero
      if (/(fee|commission|tax).*[*\/]/.test(line.toLowerCase())) {
        const context = lines.slice(Math.max(0, i - 2), Math.min(lines.length, i + 3)).join('\n');
        
        // Check if there's no minimum fee enforcement
        if (!/(min|minimum|max|\.max\(|\.min\()/.test(context.toLowerCase())) {
          findings.push({
            id: `SOL008-${counter++}`,
            pattern: 'rounding-zero-fee',
            severity: 'medium',
            title: 'Fee calculation may round to zero',
            description: 'Fee calculations on small amounts may truncate to zero, allowing users to transact without paying fees. Consider enforcing a minimum fee or using ceiling division for fee calculations.',
            location: {
              file: file.path,
              line: lineNum,
            },
            code: line.trim(),
            suggestion: `Enforce minimum fee or use ceiling division:
// Option 1: Minimum fee
let fee = calculated_fee.max(MINIMUM_FEE);

// Option 2: Ceiling division (rounds up)
let fee = (amount * fee_rate + FEE_DENOMINATOR - 1) / FEE_DENOMINATOR;`,
          });
        }
      }
      
      // Pattern 4: Share/LP token calculations
      if (/(shares?|lp_?tokens?|mint_amount).*[=].*[\/]/.test(line.toLowerCase())) {
        if (!/(checked_|ceil|floor|round)/.test(line)) {
          findings.push({
            id: `SOL008-${counter++}`,
            pattern: 'rounding-share-calculation',
            severity: 'medium',
            title: 'Share calculation may have rounding issues',
            description: 'LP token or share calculations using division may lead to rounding exploits. First depositor attacks and share inflation attacks often exploit rounding in these calculations.',
            location: {
              file: file.path,
              line: lineNum,
            },
            code: line.trim(),
            suggestion: `Use safe share calculation patterns:
// For minting (round down to protect protocol):
let shares = if total_supply == 0 {
    deposit_amount
} else {
    deposit_amount
        .checked_mul(total_supply)?
        .checked_div(total_assets)?
};

// Consider minimum share requirements for first deposit`,
          });
        }
      }
    }
  }
  
  return findings;
}
