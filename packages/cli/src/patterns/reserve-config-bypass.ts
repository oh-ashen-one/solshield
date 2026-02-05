import type { Finding } from '../commands/audit.js';
import type { ParsedRust } from '../parsers/rust.js';

/**
 * Reserve Config Bypass Patterns
 * 
 * Based on Solend exploit (Aug 2021) where attacker bypassed admin checks
 * by creating a new lending market and passing it as an account they owned,
 * enabling unauthorized updates to reserve configurations.
 * 
 * Detects:
 * - Insecure authentication in config update functions
 * - Market/pool ownership validation issues
 * - Parameter manipulation vulnerabilities
 * - Liquidation threshold manipulation risks
 */

export function checkReserveConfigBypass(parsed: ParsedRust): Finding[] {
  const findings: Finding[] = [];
  const content = parsed.content;

  // Pattern 1: Config update without proper market validation
  if (/update.*config|set.*config|modify.*reserve|change.*parameter/i.test(content)) {
    if (!/market\.owner|lending_market\.owner|pool\.authority/i.test(content)) {
      findings.push({
        id: 'CONFIG_UPDATE_NO_MARKET_VALIDATION',
        severity: 'critical',
        title: 'Config Update Without Market Ownership Validation',
        description: 'Configuration update function may not properly validate market ownership. Attackers can create fake markets to bypass admin checks (Solend exploit pattern).',
        location: parsed.path,
        recommendation: 'Validate that the market/pool account is the expected one, not just that the caller owns some market. Use canonical market addresses.'
      });
    }
  }

  // Pattern 2: Reserve/pool parameter changes without constraints
  if (/reserve|pool|vault/.test(content) && /threshold|bonus|ltv|ratio|limit/i.test(content)) {
    if (!/bounds|min.*max|range.*check|sanity.*check/i.test(content)) {
      findings.push({
        id: 'RESERVE_PARAMS_NO_BOUNDS',
        severity: 'high',
        title: 'Reserve Parameters Without Bounds Checking',
        description: 'Reserve parameters (thresholds, LTV, bonuses) can be set without bounds validation. Attackers could set extreme values to trigger mass liquidations.',
        location: parsed.path,
        recommendation: 'Implement strict bounds for all configurable parameters. Add sanity checks to prevent extreme values.'
      });
    }
  }

  // Pattern 3: Liquidation threshold manipulation
  if (/liquidation.*threshold|liquidate.*bonus|collateral.*factor/i.test(content)) {
    if (!/timelock|delay|gradual|staged/i.test(content)) {
      findings.push({
        id: 'LIQUIDATION_THRESHOLD_INSTANT',
        severity: 'high',
        title: 'Liquidation Threshold Can Be Changed Instantly',
        description: 'Liquidation thresholds can be changed without delay, allowing attackers to instantly make positions liquidatable.',
        location: parsed.path,
        recommendation: 'Implement timelock for liquidation parameter changes. Allow users time to adjust positions before changes take effect.'
      });
    }
  }

  // Pattern 4: Admin function with insufficient checks
  if (/#\[access_control|admin|authority|owner/.test(content) && /update|set|modify|change/i.test(content)) {
    if (!/&& market|&& lending_market|&& pool\.key/i.test(content)) {
      findings.push({
        id: 'ADMIN_FUNCTION_WEAK_VALIDATION',
        severity: 'high',
        title: 'Admin Function May Have Weak Validation',
        description: 'Admin function validates authority but may not validate the associated market/pool. Attacker can pass their own market to bypass checks.',
        location: parsed.path,
        recommendation: 'Validate both authority AND the specific market/pool being modified. Use canonical addresses or PDAs derived from known seeds.'
      });
    }
  }

  // Pattern 5: Lending market as mutable account input
  if (/lending_market|market_authority/.test(content) && /Account.*Info|#\[account/.test(content)) {
    if (/mut\s+lending_market|#\[account\(mut/.test(content)) {
      findings.push({
        id: 'LENDING_MARKET_MUTABLE_INPUT',
        severity: 'medium',
        title: 'Lending Market Passed as Mutable Account',
        description: 'Lending market is accepted as mutable input. Consider if attacker could pass a fake market they control.',
        location: parsed.path,
        recommendation: 'Verify lending market address matches expected canonical address. Consider using immutable reference if modification is not needed.'
      });
    }
  }

  // Pattern 6: Interest rate manipulation
  if (/interest.*rate|borrow.*rate|supply.*rate|apy|apr/i.test(content)) {
    if (!/cap|ceiling|maximum|limit/i.test(content)) {
      findings.push({
        id: 'INTEREST_RATE_NO_CAP',
        severity: 'medium',
        title: 'Interest Rate Without Maximum Cap',
        description: 'Interest rates can potentially be set to extreme values without caps, enabling economic attacks.',
        location: parsed.path,
        recommendation: 'Implement maximum caps for interest rates. Add rate change limits per time period.'
      });
    }
  }

  // Pattern 7: Circuit breaker missing
  if (/lending|borrow|liquidat/i.test(content)) {
    if (!/circuit.*breaker|pause|freeze|halt|emergency.*stop/i.test(content)) {
      findings.push({
        id: 'LENDING_NO_CIRCUIT_BREAKER',
        severity: 'medium',
        title: 'Lending Protocol Missing Circuit Breaker',
        description: 'Lending protocol lacks circuit breaker mechanism. Cannot quickly halt operations during an attack.',
        location: parsed.path,
        recommendation: 'Implement circuit breaker that can pause lending operations during anomalous activity.'
      });
    }
  }

  // Pattern 8: Speed bumps for critical operations
  if (/critical|admin|governance|upgrade/i.test(content) && /execute|process|perform/i.test(content)) {
    if (!/delay|cooldown|speed.*bump|wait.*period/i.test(content)) {
      findings.push({
        id: 'CRITICAL_OP_NO_SPEED_BUMP',
        severity: 'medium',
        title: 'Critical Operation Without Speed Bump',
        description: 'Critical operations execute immediately without delay. Speed bumps give time to detect and respond to attacks.',
        location: parsed.path,
        recommendation: 'Add mandatory delays for critical operations. Implement speed bumps to allow attack detection.'
      });
    }
  }

  return findings;
}
