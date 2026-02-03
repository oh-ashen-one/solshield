import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL087: Arithmetic Precision Issues
 * Detects precision loss and calculation order problems
 */
export function checkArithmeticPrecision(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;

  if (!rust || !rust.content) return findings;

  // Check for division before multiplication
  const divBeforeMul = /\/[\s\S]*?\*/;
  if (divBeforeMul.test(rust.content)) {
    findings.push({
      id: 'SOL087',
      severity: 'high',
      title: 'Division Before Multiplication',
      description: 'Division before multiplication causes precision loss - multiply first',
      location: input.path,
      recommendation: 'Reorder: (a * b) / c instead of (a / c) * b',
    });
  }

  // Check for percentage calculations
  const percentCalc = /(?:percent|fee|rate|basis)[\s\S]*?(?:\/\s*100|\*\s*100)/i;
  if (percentCalc.test(rust.content)) {
    if (!rust.content.includes('checked_') && !rust.content.includes('saturating_')) {
      findings.push({
        id: 'SOL087',
        severity: 'medium',
        title: 'Unchecked Percentage Calculation',
        description: 'Percentage calculation without overflow protection',
        location: input.path,
        recommendation: 'Use checked_mul and checked_div for percentage calculations',
      });
    }
  }

  // Check for basis points (10000)
  if (rust.content.includes('10000') || rust.content.includes('10_000')) {
    // Basis points should use u128 for intermediate calculations
    if (!rust.content.includes('u128') && rust.content.includes('u64')) {
      findings.push({
        id: 'SOL087',
        severity: 'medium',
        title: 'Basis Points Without Extended Precision',
        description: 'Basis point calculations may overflow with u64 intermediate values',
        location: input.path,
        recommendation: 'Use u128 for intermediate calculations: (amount as u128 * bp as u128) / 10000',
      });
    }
  }

  // Check for token amount calculations
  if (rust.content.includes('decimals') || rust.content.includes('DECIMALS')) {
    // Check for power calculations
    if (rust.content.includes('pow(') && !rust.content.includes('checked_pow')) {
      findings.push({
        id: 'SOL087',
        severity: 'medium',
        title: 'Unchecked Power Calculation',
        description: '10^decimals calculation without overflow check',
        location: input.path,
        recommendation: 'Use checked_pow or pre-computed constants for decimal scaling',
      });
    }
  }

  // Check for price calculations without precision
  if (rust.content.includes('price') && rust.content.includes('/')) {
    if (!rust.content.includes('PRECISION') && !rust.content.includes('10_u128.pow')) {
      findings.push({
        id: 'SOL087',
        severity: 'high',
        title: 'Price Calculation Without Precision Factor',
        description: 'Price division without precision scaling loses accuracy',
        location: input.path,
        recommendation: 'Use precision factor: (amount * PRECISION) / price',
      });
    }
  }

  // Check for interest/APY calculations
  if (rust.content.includes('interest') || rust.content.includes('apy') || rust.content.includes('apr')) {
    if (!rust.content.includes('compound') && rust.content.includes('*')) {
      findings.push({
        id: 'SOL087',
        severity: 'medium',
        title: 'Simple Interest Calculation',
        description: 'Interest calculation may need compound interest for accuracy',
        location: input.path,
        recommendation: 'Consider compound interest: principal * (1 + rate)^time',
      });
    }
  }

  // Check for sqrt without proper handling
  if (rust.content.includes('sqrt')) {
    if (!rust.content.includes('checked_') && !rust.content.includes('try_')) {
      findings.push({
        id: 'SOL087',
        severity: 'low',
        title: 'Unchecked Square Root',
        description: 'Square root calculation without error handling',
        location: input.path,
        recommendation: 'Handle sqrt errors - returns None for negative numbers',
      });
    }
  }

  return findings;
}
