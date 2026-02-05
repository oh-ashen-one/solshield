import type { Finding } from '../commands/audit.js';
import type { ParsedRust } from '../parsers/rust.js';

/**
 * Solend-Style Reserve Configuration Bypass
 * Based on: Solend malicious lending market incident
 * 
 * Lending protocols often allow creating markets with custom configurations.
 * If reserve configurations aren't properly validated, attackers can:
 * 1. Create malicious lending markets
 * 2. Use manipulated oracle configs
 * 3. Set extreme collateral factors
 * 4. Drain protocol through misconfigured markets
 */
export function checkSolendReserveBypass(parsed: ParsedRust): Finding[] {
  const findings: Finding[] = [];
  const content = parsed.content;

  // Detect lending market / reserve initialization
  const lendingPatterns = [
    /init.*?reserve|create.*?market|new.*?lending.*?market/gi,
    /reserve.*?config|market.*?config|lending.*?config/gi,
    /collateral.*?factor|liquidation.*?threshold|loan.*?to.*?value/gi,
  ];

  let isLendingProtocol = false;
  for (const pattern of lendingPatterns) {
    if (pattern.test(content)) {
      isLendingProtocol = true;
      break;
    }
  }

  if (!isLendingProtocol) return findings;

  // Check for market authority validation
  const hasAuthorityCheck = /market.*?authority|lending.*?authority|admin.*?only|owner.*?only/i.test(content);
  if (!hasAuthorityCheck) {
    findings.push({
      severity: 'critical',
      category: 'reserve-bypass',
      title: 'Lending Market Creation Without Authority Check',
      description: 'Lending market or reserve can be created without authority validation. ' +
        'Attackers can create malicious markets to drain protocol (Solend incident).',
      recommendation: 'Require admin/authority signature for market creation. ' +
        'Validate: market_authority.key() == expected_authority',
      location: parsed.path,
    });
  }

  // Check for oracle validation
  if (/oracle|price.*?feed|pyth/i.test(content)) {
    const hasOracleValidation = /oracle.*?==|verify.*?oracle|whitelist.*?oracle|trusted.*?oracle/i.test(content);
    if (!hasOracleValidation) {
      findings.push({
        severity: 'critical',
        category: 'reserve-bypass',
        title: 'Reserve Oracle Not Validated Against Whitelist',
        description: 'Oracle address in reserve configuration is not validated. ' +
          'Attackers can configure malicious oracles to manipulate prices.',
        recommendation: 'Validate oracle addresses against trusted whitelist or hardcoded addresses.',
        location: parsed.path,
      });
    }
  }

  // Check for collateral factor bounds
  if (/collateral.*?factor|ltv|loan.*?to.*?value/i.test(content)) {
    const hasBoundsCheck = /factor\s*[<>=]|ltv\s*[<>=]|max.*?factor|min.*?factor/i.test(content);
    if (!hasBoundsCheck) {
      findings.push({
        severity: 'high',
        category: 'reserve-bypass',
        title: 'Collateral Factor Without Bounds Validation',
        description: 'Collateral factor can be set without bounds checking. ' +
          'Extreme values (e.g., 100% LTV) can enable instant bad debt.',
        recommendation: 'Enforce reasonable bounds: require!(ltv <= MAX_LTV && ltv >= MIN_LTV). ' +
          'Typical safe range: 50-80% for volatile assets.',
        location: parsed.path,
      });
    }
  }

  // Check for reserve token validation
  if (/reserve.*?token|deposit.*?mint|collateral.*?mint/i.test(content)) {
    const hasTokenValidation = /mint.*?==|token.*?whitelist|approved.*?tokens/i.test(content);
    if (!hasTokenValidation) {
      findings.push({
        severity: 'high',
        category: 'reserve-bypass',
        title: 'Reserve Token Not Validated',
        description: 'Reserve/collateral token can be set to arbitrary mints. ' +
          'Attackers could use worthless or manipulable tokens as collateral.',
        recommendation: 'Validate tokens against approved list or require governance approval.',
        location: parsed.path,
      });
    }
  }

  // Check for isolation between markets
  if (/market|pool|reserve/i.test(content)) {
    const hasIsolation = /isolated|cross.*?collateral.*?false|single.*?asset/i.test(content);
    const hasGlobalRisk = /global.*?debt|total.*?borrowed|protocol.*?wide/i.test(content);
    
    if (!hasIsolation && hasGlobalRisk) {
      findings.push({
        severity: 'medium',
        category: 'reserve-bypass',
        title: 'Lending Markets Not Isolated',
        description: 'Multiple lending markets share global state without isolation. ' +
          'Malicious market could affect protocol-wide risk.',
        recommendation: 'Consider isolated markets where each market has independent risk parameters.',
        location: parsed.path,
      });
    }
  }

  // Check for rate model validation
  if (/interest.*?rate|borrow.*?rate|utilization/i.test(content)) {
    const hasRateValidation = /rate\s*[<>=]|max.*?rate|validate.*?rate/i.test(content);
    if (!hasRateValidation) {
      findings.push({
        severity: 'medium',
        category: 'reserve-bypass',
        title: 'Interest Rate Model Not Validated',
        description: 'Interest rate configuration without validation. ' +
          'Extreme rates could harm users or create economic attacks.',
        recommendation: 'Validate rate parameters against reasonable bounds.',
        location: parsed.path,
      });
    }
  }

  return findings;
}
