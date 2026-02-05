import type { Finding } from '../commands/audit.js';
import type { ParsedRust } from '../parsers/rust.js';

/**
 * Mango Markets Exploit Patterns
 * Based on: Mango Markets $114M exploit (October 2022)
 * 
 * The exploit involved:
 * 1. Market manipulation via thin liquidity
 * 2. Using manipulated price for perpetual funding
 * 3. Borrowing against unrealized PnL
 * 4. Draining protocol by creating bad debt
 */
export function checkMangoMarketsPatterns(parsed: ParsedRust): Finding[] {
  const findings: Finding[] = [];
  const content = parsed.content;

  // Detect perpetual/margin trading patterns
  const isPerpetualProtocol = /perp|perpetual|margin.*?trading|futures|funding.*?rate/i.test(content);
  if (!isPerpetualProtocol) return findings;

  // Check for unrealized PnL as collateral
  if (/unrealized.*?pnl|open.*?position.*?value|mark.*?price.*?position/i.test(content)) {
    const hasUnrealizedLimit = /unrealized.*?limit|pnl.*?cap|max.*?unrealized|discount.*?unrealized/i.test(content);
    if (!hasUnrealizedLimit) {
      findings.push({
        severity: 'critical',
        category: 'mango-patterns',
        title: 'Unrealized PnL as Collateral Without Limits',
        description: 'Unrealized PnL used for collateral/borrowing without haircut or limits. ' +
          'This was the core vulnerability in Mango Markets - attacker pumped price to create ' +
          'large unrealized gains, then borrowed against them.',
        recommendation: 'Apply significant haircut (50%+) to unrealized PnL for collateral. ' +
          'Consider not counting unrealized PnL as collateral at all for borrowing.',
        location: parsed.path,
      });
    }
  }

  // Check for mark price manipulation resistance
  if (/mark.*?price|index.*?price/i.test(content)) {
    const hasManipulationProtection = /twap|time.*?weight|multiple.*?source|median/i.test(content);
    if (!hasManipulationProtection) {
      findings.push({
        severity: 'high',
        category: 'mango-patterns',
        title: 'Mark Price May Be Manipulatable',
        description: 'Mark price calculation without apparent manipulation resistance. ' +
          'In thin liquidity, single actors can move prices significantly.',
        recommendation: 'Use TWAP for mark price, require significant time/volume to move price. ' +
          'Compare mark price against multiple oracle sources.',
        location: parsed.path,
      });
    }
  }

  // Check for position size limits
  if (/position|exposure|notional/i.test(content)) {
    const hasPositionLimits = /max.*?position|position.*?limit|exposure.*?limit|notional.*?cap/i.test(content);
    if (!hasPositionLimits) {
      findings.push({
        severity: 'high',
        category: 'mango-patterns',
        title: 'Missing Position Size Limits',
        description: 'No apparent position size limits. ' +
          'Large positions in thin markets enable price manipulation.',
        recommendation: 'Implement position limits based on: market liquidity, open interest, ' +
          'and user collateral. Limit max position to % of total open interest.',
        location: parsed.path,
      });
    }
  }

  // Check for open interest limits
  if (/open.*?interest|total.*?positions/i.test(content)) {
    const hasOILimit = /max.*?open.*?interest|oi.*?limit|cap.*?interest/i.test(content);
    if (!hasOILimit) {
      findings.push({
        severity: 'medium',
        category: 'mango-patterns',
        title: 'Missing Open Interest Cap',
        description: 'No maximum open interest limit per market. ' +
          'Unlimited OI can lead to socialized losses.',
        recommendation: 'Cap total open interest relative to insurance fund and liquidity.',
        location: parsed.path,
      });
    }
  }

  // Check for liquidation price manipulation
  if (/liquidat|margin.*?call/i.test(content)) {
    const hasLiquidationProtection = /liquidation.*?price.*?check|oracle.*?liquidation|delay.*?liquidation/i.test(content);
    if (!hasLiquidationProtection) {
      findings.push({
        severity: 'high',
        category: 'mango-patterns',
        title: 'Liquidation May Be Manipulatable',
        description: 'Liquidation mechanism without price manipulation protection. ' +
          'Attackers can trigger liquidations by manipulating mark price.',
        recommendation: 'Use oracle price for liquidation threshold, not mark price. ' +
          'Add liquidation delay or require sustained price below threshold.',
        location: parsed.path,
      });
    }
  }

  // Check for insurance fund adequacy
  if (/insurance.*?fund|backstop|bad.*?debt/i.test(content)) {
    const hasAdequacyCheck = /fund.*?sufficient|coverage|insurance.*?check/i.test(content);
    if (!hasAdequacyCheck) {
      findings.push({
        severity: 'medium',
        category: 'mango-patterns',
        title: 'Insurance Fund Adequacy Not Validated',
        description: 'Operations that could create bad debt without checking insurance fund. ' +
          'Insufficient insurance leads to socialized losses.',
        recommendation: 'Before allowing large positions: check insurance fund can cover potential losses. ' +
          'Implement position limits relative to insurance fund size.',
        location: parsed.path,
      });
    }
  }

  // Check for oracle deviation from spot
  if (/oracle|price.*?feed/i.test(content) && /spot|amm|dex/i.test(content)) {
    findings.push({
      severity: 'medium',
      category: 'mango-patterns',
      title: 'Review Oracle vs Spot Price Deviation',
      description: 'Both oracle and spot prices are used. ' +
        'Large deviation between oracle and spot can create arbitrage opportunities or manipulation vectors.',
      recommendation: 'Monitor and limit oracle/spot deviation. ' +
        'If deviation exceeds threshold, consider pausing affected operations.',
      location: parsed.path,
    });
  }

  return findings;
}
