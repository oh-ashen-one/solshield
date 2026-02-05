import type { Finding } from '../commands/audit.js';
import type { ParsedRust } from '../parsers/rust.js';

/**
 * Collateral Mint Validation Patterns
 * 
 * Based on Cashio exploit (Mar 2022) - $52.8M stolen due to missing
 * validation of the mint field in collateral accounts, allowing
 * attackers to mint tokens using fake collateral.
 * 
 * Also covers root of trust vulnerabilities where account chains
 * are not properly validated back to a known trusted source.
 * 
 * Detects:
 * - Missing mint validation in collateral
 * - Incomplete root of trust chains
 * - Fake LP token attacks
 * - Infinite mint glitches
 */

export function checkCollateralMintValidation(parsed: ParsedRust): Finding[] {
  const findings: Finding[] = [];
  const content = parsed.content;

  // Pattern 1: Collateral without mint validation (Cashio pattern)
  if (/collateral|deposit|stake/i.test(content) && /mint|token/i.test(content)) {
    if (!/collateral\.mint\s*==|mint.*==.*expected|validate.*mint|verify.*mint/i.test(content)) {
      findings.push({
        id: 'COLLATERAL_MINT_NOT_VALIDATED',
        severity: 'critical',
        title: 'Collateral Mint Not Validated',
        description: 'Collateral token mint is not validated against expected mint. Cashio lost $52.8M due to this exact vulnerability - attackers minted tokens using worthless fake collateral.',
        location: parsed.path,
        recommendation: 'Always validate that collateral token mint matches expected mint address. Verify entire chain of trust back to known good mints.'
      });
    }
  }

  // Pattern 2: LP token without pool validation
  if (/lp.*token|liquidity.*provider|pool.*token/i.test(content)) {
    if (!/pool\.key|pool_address|verified.*pool|canonical.*pool/i.test(content)) {
      findings.push({
        id: 'LP_TOKEN_POOL_NOT_VALIDATED',
        severity: 'critical',
        title: 'LP Token Pool Not Validated',
        description: 'LP tokens accepted without validating the underlying pool. Attackers can create fake pools to mint worthless LP tokens.',
        location: parsed.path,
        recommendation: 'Validate that LP token comes from a known, canonical pool address. Check pool program ID and seeds.'
      });
    }
  }

  // Pattern 3: Arrow/wrapper account chain not validated
  if (/arrow|wrapper|crate|saber.*swap/i.test(content)) {
    if (!/arrow\.mint|wrapper\.underlying|crate\.mint.*==|verify.*underlying/i.test(content)) {
      findings.push({
        id: 'WRAPPER_CHAIN_NOT_VALIDATED',
        severity: 'critical',
        title: 'Wrapper/Arrow Account Chain Not Validated',
        description: 'Wrapper or arrow account accepted without validating underlying mint. This was the exact Cashio vulnerability - missing validation of saber_swap.arrow mint field.',
        location: parsed.path,
        recommendation: 'Validate entire chain: arrow -> LP token -> underlying pool -> base tokens. Each step must be verified.'
      });
    }
  }

  // Pattern 4: Root of trust missing
  if (/trusted|canonical|allowed.*mint|whitelist.*token/i.test(content)) {
    if (!/hardcode|const.*=.*Pubkey|CANONICAL_|TRUSTED_|known.*address/i.test(content)) {
      findings.push({
        id: 'ROOT_OF_TRUST_NOT_ESTABLISHED',
        severity: 'high',
        title: 'Root of Trust Not Properly Established',
        description: 'Trust chain does not anchor to hardcoded canonical addresses. Attackers can forge entire account chains.',
        location: parsed.path,
        recommendation: 'Establish root of trust with hardcoded canonical addresses. Validate all accounts back to known trusted sources.'
      });
    }
  }

  // Pattern 5: Infinite mint risk
  if (/mint_to|mint.*tokens|create.*token/i.test(content)) {
    if (!/backed|collateral.*check|supply.*limit|max.*supply/i.test(content)) {
      findings.push({
        id: 'INFINITE_MINT_RISK',
        severity: 'critical',
        title: 'Potential Infinite Mint Vulnerability',
        description: 'Token minting without proper collateral backing checks. Could enable infinite mint glitch like Cashio.',
        location: parsed.path,
        recommendation: 'Verify collateral is properly locked before minting. Implement supply caps and rate limits on minting.'
      });
    }
  }

  // Pattern 6: Stablecoin backing validation
  if (/stablecoin|pegged|backed.*token|synthetic/i.test(content)) {
    if (!/reserves?.*check|backing.*valid|collateral.*ratio/i.test(content)) {
      findings.push({
        id: 'STABLECOIN_BACKING_NOT_CHECKED',
        severity: 'high',
        title: 'Stablecoin Backing Not Validated',
        description: 'Stablecoin operations without verifying backing reserves. Could lead to depegging or infinite mint.',
        location: parsed.path,
        recommendation: 'Always verify stablecoin is properly backed before operations. Check collateralization ratio.'
      });
    }
  }

  // Pattern 7: Cross-program token validation
  if (/cpi|invoke|cross.*program/i.test(content) && /token|mint/i.test(content)) {
    if (!/verify.*mint.*after|check.*returned.*mint|validate.*cpi.*result/i.test(content)) {
      findings.push({
        id: 'CPI_TOKEN_NOT_VALIDATED',
        severity: 'high',
        title: 'Token Mint Not Validated After CPI',
        description: 'Cross-program invocation involving tokens without validating mint after call. CPI can return unexpected token types.',
        location: parsed.path,
        recommendation: 'Validate token mint both before and after CPI calls. Do not trust token identity across program boundaries.'
      });
    }
  }

  // Pattern 8: Collateral price vs quantity mismatch
  if (/collateral.*value|calculate.*worth|price.*collateral/i.test(content)) {
    if (!/decimals|precision|normalize/i.test(content)) {
      findings.push({
        id: 'COLLATERAL_VALUE_PRECISION',
        severity: 'medium',
        title: 'Collateral Value Calculation May Lack Precision Handling',
        description: 'Collateral value calculations should account for decimal differences between tokens to prevent manipulation.',
        location: parsed.path,
        recommendation: 'Normalize token amounts based on decimals before value calculations. Handle precision carefully.'
      });
    }
  }

  // Pattern 9: Missing audit for mint operations
  if (/pub\s+fn\s+mint|mint.*instruction|MintTo/i.test(content)) {
    if (!/audit|log.*mint|emit.*mint.*event/i.test(content)) {
      findings.push({
        id: 'MINT_OPERATION_NOT_AUDITED',
        severity: 'low',
        title: 'Mint Operations Not Audited/Logged',
        description: 'Mint operations should emit events for monitoring. Helps detect infinite mint attacks early.',
        location: parsed.path,
        recommendation: 'Emit events for all mint operations. Include amount, recipient, and collateral details.'
      });
    }
  }

  return findings;
}
