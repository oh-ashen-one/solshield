import type { Finding } from '../commands/audit.js';
import type { ParsedRust } from '../parsers/rust.js';

/**
 * Root of Trust Chain Vulnerabilities
 * Based on: Cashio $48M exploit
 * 
 * Every account in a program must trace back to a verified root of trust.
 * Cashio was exploited because it verified accounts against each other
 * in a circular manner without anchoring to a true root of trust.
 * 
 * Attack pattern:
 * 1. Create fake account A that "validates" account B
 * 2. Create fake account B that "validates" account A
 * 3. Both accounts pass validation because they reference each other
 * 4. No actual root of trust anchors the validation chain
 */
export function checkRootOfTrustChain(parsed: ParsedRust): Finding[] {
  const findings: Finding[] = [];
  const content = parsed.content;

  // Detect circular validation patterns
  const circularPatterns = [
    /collateral.*?==.*?bank.*?collateral|bank.*?collateral.*?==.*?collateral/i,
    /account_a.*?references.*?account_b.*?references.*?account_a/i,
    /mint.*?==.*?pool.*?mint.*?pool.*?mint.*?==.*?mint/i,
  ];

  for (const pattern of circularPatterns) {
    if (pattern.test(content)) {
      findings.push({
        severity: 'critical',
        category: 'root-of-trust',
        title: 'Circular Account Validation Detected',
        description: 'Accounts validate against each other in a circular pattern. ' +
          'This allows attackers to create fake account chains that validate themselves (Cashio exploit pattern).',
        recommendation: 'Establish a clear root of trust (e.g., program-owned config account or PDA). ' +
          'All validation chains must trace back to this root.',
        location: parsed.path,
      });
    }
  }

  // Detect mint validation without tracing to root
  if (/collateral.*?mint|mint.*?account/i.test(content)) {
    const hasRootValidation = /admin.*?mint|config.*?mint|hardcoded.*?mint|const.*?MINT/i.test(content);
    const hasPDADerivation = /find_program_address.*?mint|seeds.*?mint/i.test(content);

    if (!hasRootValidation && !hasPDADerivation) {
      findings.push({
        severity: 'high',
        category: 'root-of-trust',
        title: 'Mint Account Not Anchored to Root of Trust',
        description: 'Mint account validation does not trace back to a verified root. ' +
          'Attackers can substitute fake mints that appear valid.',
        recommendation: 'Validate mints against: 1. Hardcoded mint addresses, ' +
          '2. Admin-configured mint list in program-owned account, or ' +
          '3. Mints derived via PDA with program as authority.',
        location: parsed.path,
      });
    }
  }

  // Detect token account validation without mint verification
  if (/token.*?account|associated.*?token/i.test(content)) {
    const verifyMint = /token_account.*?mint\s*==|\.mint\s*==.*?expected/i.test(content);
    if (!verifyMint) {
      findings.push({
        severity: 'high',
        category: 'root-of-trust',
        title: 'Token Account Mint Not Verified',
        description: 'Token account is used without verifying its mint matches expected value. ' +
          'Attackers can substitute token accounts with wrong mints.',
        recommendation: 'Always verify: token_account.mint == expected_mint. ' +
          'The expected mint should trace to a root of trust.',
        location: parsed.path,
      });
    }
  }

  // Detect oracle account without publisher validation
  if (/oracle|price.*?feed/i.test(content)) {
    const hasPublisherCheck = /publisher|feed.*?id|oracle.*?address|pyth.*?program/i.test(content);
    if (!hasPublisherCheck) {
      findings.push({
        severity: 'high',
        category: 'root-of-trust',
        title: 'Oracle Account Publisher Not Verified',
        description: 'Oracle/price feed used without verifying the publisher or feed ID. ' +
          'Attackers can substitute malicious price feeds.',
        recommendation: 'Verify oracle accounts against known feed IDs from trusted publishers. ' +
          'For Pyth, verify the price account matches the expected feed ID.',
        location: parsed.path,
      });
    }
  }

  // Detect pool validation patterns
  if (/pool.*?account|liquidity.*?pool/i.test(content)) {
    const hasPoolValidation = /pool.*?seeds|pool.*?authority|amm.*?id|pool_id.*?==|program.*?pool/i.test(content);
    if (!hasPoolValidation) {
      findings.push({
        severity: 'medium',
        category: 'root-of-trust',
        title: 'Pool Account Not Anchored to Program',
        description: 'Pool account validation does not verify program ownership or derivation. ' +
          'Fake pool accounts could be substituted.',
        recommendation: 'Derive pool accounts as PDAs or verify they are owned by the expected AMM program.',
        location: parsed.path,
      });
    }
  }

  // General root of trust check
  const hasAnyValidation = /constraint\s*=|require!|assert|verify/i.test(content);
  if (hasAnyValidation) {
    const hasRootAnchor = /config|admin|authority|program.*?id|const.*?ADDRESS|pubkey!/i.test(content);
    if (!hasRootAnchor) {
      findings.push({
        severity: 'medium',
        category: 'root-of-trust',
        title: 'Validation Without Clear Root of Trust',
        description: 'Account validations exist but no clear root of trust (config, admin, hardcoded address) is established.',
        recommendation: 'Define a clear root of trust: program-owned config PDA, hardcoded addresses, ' +
          'or admin-controlled registry that anchors all validation chains.',
        location: parsed.path,
      });
    }
  }

  return findings;
}
