import type { Finding } from '../commands/audit.js';
import type { ParsedRust } from '../parsers/rust.js';

/**
 * Drift Protocol Oracle Guardrail Patterns
 * Based on: Drift Protocol's oracle safety implementations
 * 
 * Best practices for oracle safety in DeFi:
 * 1. Price deviation checks (current vs historical)
 * 2. Confidence interval validation
 * 3. Staleness checks
 * 4. Multiple oracle fallback
 * 5. Circuit breakers
 */
export function checkDriftOracleGuardrails(parsed: ParsedRust): Finding[] {
  const findings: Finding[] = [];
  const content = parsed.content;

  // Only check files that use oracles
  if (!/oracle|price.*?feed|pyth|switchboard|chainlink/i.test(content)) {
    return findings;
  }

  // Check for price deviation guards
  const hasDeviationCheck = /deviation|price.*?diff|price.*?change|percent.*?diff/i.test(content);
  if (!hasDeviationCheck) {
    findings.push({
      severity: 'high',
      category: 'oracle-guardrails',
      title: 'Missing Oracle Price Deviation Check',
      description: 'No price deviation check detected. ' +
        'Large sudden price changes could indicate manipulation or oracle failure.',
      recommendation: 'Implement deviation check: |current_price - last_price| / last_price < max_deviation. ' +
        'Typical threshold: 5-10% for volatile assets.',
      location: parsed.path,
    });
  }

  // Check for confidence interval validation (Pyth-specific)
  if (/pyth|price_status|price_update/i.test(content)) {
    const hasConfidence = /confidence|conf|price_conf/i.test(content);
    if (!hasConfidence) {
      findings.push({
        severity: 'medium',
        category: 'oracle-guardrails',
        title: 'Pyth Confidence Interval Not Validated',
        description: 'Pyth oracle used without checking confidence interval. ' +
          'Wide confidence indicates uncertain price.',
        recommendation: 'Check: require!(price.conf * 100 / price.price < max_confidence_pct). ' +
          'Reject prices with confidence > 2-5% of price.',
        location: parsed.path,
      });
    }
  }

  // Check for staleness check
  const hasStalenessCheck = /stale|timestamp|slot.*?diff|age|last_update|valid_slot/i.test(content);
  if (!hasStalenessCheck) {
    findings.push({
      severity: 'high',
      category: 'oracle-guardrails',
      title: 'Missing Oracle Staleness Check',
      description: 'Oracle price staleness not validated. ' +
        'Stale prices can be exploited for arbitrage.',
      recommendation: 'Check: require!(clock.slot - oracle.valid_slot < max_staleness_slots). ' +
        'Typical threshold: 25-100 slots depending on asset volatility.',
      location: parsed.path,
    });
  }

  // Check for circuit breaker
  const hasCircuitBreaker = /circuit.*?breaker|pause|halt|emergency.*?stop|freeze/i.test(content);
  if (!hasCircuitBreaker) {
    findings.push({
      severity: 'medium',
      category: 'oracle-guardrails',
      title: 'Missing Oracle Circuit Breaker',
      description: 'No circuit breaker mechanism for oracle failures. ' +
        'Protocol should be able to pause during oracle anomalies.',
      recommendation: 'Implement circuit breaker that pauses protocol when: ' +
        '1. Price deviation exceeds threshold, 2. Staleness exceeds limit, ' +
        '3. Multiple oracles disagree significantly.',
      location: parsed.path,
    });
  }

  // Check for fallback oracle
  if (/primary.*?oracle|fallback|secondary/i.test(content) || 
      /(oracle_1|oracle_2|backup_oracle)/i.test(content)) {
    // Has fallback mechanism - good
  } else {
    findings.push({
      severity: 'medium',
      category: 'oracle-guardrails',
      title: 'Single Oracle Dependency',
      description: 'Protocol depends on single oracle without fallback. ' +
        'Oracle failure would halt protocol operations.',
      recommendation: 'Implement fallback oracle system: ' +
        '1. Primary oracle (e.g., Pyth), 2. Secondary oracle (e.g., Switchboard), ' +
        '3. Agreement check between oracles.',
      location: parsed.path,
    });
  }

  // Check for TWAP usage
  const usesTWAP = /twap|time.*?weight|cumulative.*?price/i.test(content);
  const usesSpotPrice = /spot.*?price|current.*?price|get_price/i.test(content);
  
  if (usesSpotPrice && !usesTWAP) {
    findings.push({
      severity: 'medium',
      category: 'oracle-guardrails',
      title: 'Using Spot Price Without TWAP',
      description: 'Using spot prices which can be manipulated within a single block. ' +
        'Consider TWAP for manipulation resistance.',
      recommendation: 'For critical operations (liquidations, collateral valuation), ' +
        'use TWAP calculated over multiple blocks/slots.',
      location: parsed.path,
    });
  }

  // Check for negative/zero price handling
  const hasZeroPriceCheck = /price\s*>\s*0|price\s*<=\s*0|price.*?zero|invalid.*?price/i.test(content);
  if (!hasZeroPriceCheck) {
    findings.push({
      severity: 'high',
      category: 'oracle-guardrails',
      title: 'Missing Zero/Negative Price Check',
      description: 'Oracle price not validated for zero or negative values. ' +
        'Invalid prices can cause division by zero or logic errors.',
      recommendation: 'Check: require!(price > 0, ErrorCode::InvalidOraclePrice)',
      location: parsed.path,
    });
  }

  return findings;
}
