import type { Finding } from '../commands/audit.js';
import type { ParsedRust } from '../parsers/rust.js';

/**
 * Advanced DeFi Security Patterns
 * 
 * Covers complex DeFi vulnerabilities including perpetuals, options,
 * structured products, and novel financial primitives.
 * 
 * Detects:
 * - Perpetual funding rate manipulation
 * - Options pricing vulnerabilities  
 * - Yield aggregator risks
 * - Leverage cascade effects
 */

export function checkAdvancedDefiPatterns(parsed: ParsedRust): Finding[] {
  const findings: Finding[] = [];
  const content = parsed.content;

  // Pattern 1: Perpetual funding rate manipulation
  if (/funding.*rate|perp|perpetual/i.test(content)) {
    if (!/rate.*cap|max.*funding|funding.*bound/i.test(content)) {
      findings.push({
        id: 'PERP_FUNDING_NO_CAP',
        severity: 'high',
        title: 'Perpetual Funding Rate Without Cap',
        description: 'Funding rates without bounds. Attackers can manipulate price to force extreme funding payments.',
        location: parsed.path,
        recommendation: 'Cap funding rates at reasonable bounds (e.g., 0.1% per hour). Add funding rate smoothing.'
      });
    }
  }

  // Pattern 2: Options pricing without volatility bounds
  if (/option|call|put|strike|expiry/i.test(content) && /price|premium|value/i.test(content)) {
    if (!/implied.*vol|volatility.*cap|vol.*bound/i.test(content)) {
      findings.push({
        id: 'OPTIONS_VOL_UNBOUNDED',
        severity: 'high',
        title: 'Options Pricing Without Volatility Bounds',
        description: 'Implied volatility not bounded. Extreme IV can lead to mispriced options.',
        location: parsed.path,
        recommendation: 'Implement IV bounds based on historical volatility. Add sanity checks on option prices.'
      });
    }
  }

  // Pattern 3: Yield aggregator strategy risk
  if (/yield|strategy|vault|compound/i.test(content) && /auto|aggregate|optimize/i.test(content)) {
    if (!/strategy.*whitelist|approved.*protocol|vet.*strategy/i.test(content)) {
      findings.push({
        id: 'YIELD_STRATEGY_NOT_VETTED',
        severity: 'high',
        title: 'Yield Strategy May Not Be Vetted',
        description: 'Yield strategies without whitelisting. Malicious strategy could drain vault.',
        location: parsed.path,
        recommendation: 'Whitelist approved strategies. Audit all strategies. Add strategy caps and guards.'
      });
    }
  }

  // Pattern 4: Leverage cascade/liquidation spiral
  if (/leverage|margin|borrow/i.test(content) && /liquidat/i.test(content)) {
    if (!/circuit.*breaker|cascade.*prevent|gradual.*liquidat/i.test(content)) {
      findings.push({
        id: 'LEVERAGE_CASCADE_RISK',
        severity: 'high',
        title: 'Leverage Cascade Risk Not Mitigated',
        description: 'Liquidations could cascade in rapid price moves, destabilizing protocol. See Mango exploit.',
        location: parsed.path,
        recommendation: 'Implement circuit breakers. Use gradual liquidations. Add debt ceilings per asset.'
      });
    }
  }

  // Pattern 5: Synthetic asset peg maintenance
  if (/synthetic|synth|mirror|pegged/i.test(content)) {
    if (!/peg.*mechanism|arbitrage.*incentive|stability.*pool/i.test(content)) {
      findings.push({
        id: 'SYNTHETIC_PEG_UNSTABLE',
        severity: 'high',
        title: 'Synthetic Asset Peg Mechanism May Be Weak',
        description: 'Synthetic asset without robust peg maintenance. Could depeg under stress.',
        location: parsed.path,
        recommendation: 'Implement multiple peg mechanisms. Add arbitrage incentives. Use stability pools.'
      });
    }
  }

  // Pattern 6: Interest rate model manipulation
  if (/interest.*model|utilization.*rate|borrow.*rate/i.test(content)) {
    if (!/utilization.*check|rate.*cap|jump.*rate/i.test(content)) {
      findings.push({
        id: 'INTEREST_MODEL_MANIPULABLE',
        severity: 'medium',
        title: 'Interest Rate Model May Be Manipulable',
        description: 'Interest rate model without manipulation protections. Whales can manipulate utilization.',
        location: parsed.path,
        recommendation: 'Use jump rate models. Add rate caps. Consider utilization smoothing.'
      });
    }
  }

  // Pattern 7: Cross-margin position risks
  if (/cross.*margin|shared.*collateral|unified.*margin/i.test(content)) {
    if (!/isolation|contain.*loss|position.*limit/i.test(content)) {
      findings.push({
        id: 'CROSS_MARGIN_CONTAGION',
        severity: 'medium',
        title: 'Cross-Margin Contagion Risk',
        description: 'Cross-margin without isolation. Loss in one position affects all positions.',
        location: parsed.path,
        recommendation: 'Offer isolated margin option. Implement per-position loss limits. Add portfolio-level guards.'
      });
    }
  }

  // Pattern 8: Depeg protection missing
  if (/stablecoin|stable|pegged.*token/i.test(content)) {
    if (!/depeg.*protection|insurance|redeem.*guarantee/i.test(content)) {
      findings.push({
        id: 'STABLECOIN_DEPEG_UNPROTECTED',
        severity: 'high',
        title: 'No Depeg Protection for Stablecoin',
        description: 'Stablecoin without depeg insurance. UST-style collapse possible.',
        location: parsed.path,
        recommendation: 'Implement insurance fund. Add redemption guarantees. Use diverse collateral.'
      });
    }
  }

  // Pattern 9: Bad debt socialization
  if (/bad.*debt|underwater|insolvent/i.test(content)) {
    if (!/insurance.*fund|backstop|socialize.*loss/i.test(content)) {
      findings.push({
        id: 'BAD_DEBT_NO_HANDLING',
        severity: 'high',
        title: 'Bad Debt Handling Not Defined',
        description: 'No mechanism to handle bad debt. Insolvencies could affect all users.',
        location: parsed.path,
        recommendation: 'Build insurance fund from fees. Define bad debt socialization. Implement backstop mechanism.'
      });
    }
  }

  // Pattern 10: Auto-compounding manipulation
  if (/auto.*compound|reinvest|compound.*yield/i.test(content)) {
    if (!/compound.*guard|manipulation.*check|timing.*attack/i.test(content)) {
      findings.push({
        id: 'AUTOCOMPOUND_MANIPULABLE',
        severity: 'medium',
        title: 'Auto-Compound Timing May Be Manipulable',
        description: 'Auto-compound timing without protection. MEV bots can sandwich compound transactions.',
        location: parsed.path,
        recommendation: 'Add compound timing randomization. Use private transactions. Batch compounds.'
      });
    }
  }

  // Pattern 11: Insurance fund adequacy
  if (/insurance.*fund|safety.*fund|reserve/i.test(content)) {
    if (!/adequacy.*check|minimum.*reserve|fund.*ratio/i.test(content)) {
      findings.push({
        id: 'INSURANCE_FUND_ADEQUACY',
        severity: 'medium',
        title: 'Insurance Fund Adequacy Not Verified',
        description: 'Insurance fund without adequacy checks. May be insufficient for tail risk events.',
        location: parsed.path,
        recommendation: 'Implement insurance fund ratio requirements. Stress test fund adequacy. Build reserves during good times.'
      });
    }
  }

  // Pattern 12: Protocol-owned liquidity risks
  if (/protocol.*owned|pol|treasury.*liquidity/i.test(content)) {
    if (!/diversification|risk.*limit|concentration/i.test(content)) {
      findings.push({
        id: 'POL_CONCENTRATION_RISK',
        severity: 'medium',
        title: 'Protocol-Owned Liquidity Concentration Risk',
        description: 'Protocol liquidity may be concentrated. Single pool/asset failure affects protocol.',
        location: parsed.path,
        recommendation: 'Diversify POL across pools/assets. Set concentration limits. Monitor POL health.'
      });
    }
  }

  return findings;
}
