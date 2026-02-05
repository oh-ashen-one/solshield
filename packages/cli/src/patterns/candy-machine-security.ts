import type { Finding } from '../commands/audit.js';
import type { ParsedRust } from '../parsers/rust.js';

/**
 * Candy Machine / NFT Minting Security
 * Based on: Solens "Smashing the Candy Machine" exploit
 * 
 * Common candy machine vulnerabilities:
 * 1. Bot circumvention - bypassing captcha/rate limits
 * 2. Whitelist manipulation - forging whitelist proofs
 * 3. Price manipulation - minting at wrong price
 * 4. Initialization front-running - hijacking uninitialized machines
 */
export function checkCandyMachineSecurity(parsed: ParsedRust): Finding[] {
  const findings: Finding[] = [];
  const content = parsed.content;

  // Detect candy machine / NFT minting patterns
  const mintingPatterns = [
    /candy.*?machine|nft.*?mint|collection.*?mint/gi,
    /mint_one|mint_nft|create_nft/gi,
    /whitelist.*?mint|presale/gi,
  ];

  let isMintingProgram = false;
  for (const pattern of mintingPatterns) {
    if (pattern.test(content)) {
      isMintingProgram = true;
      break;
    }
  }

  if (!isMintingProgram) return findings;

  // Check for bot protection
  const hasBotProtection = /rate.*?limit|cooldown|throttle|captcha|gatekeeper/i.test(content);
  const hasTimeLock = /start_time|end_time|go_live|launch_date/i.test(content);
  
  if (!hasBotProtection) {
    findings.push({
      severity: 'medium',
      category: 'candy-machine',
      title: 'NFT Minting Without Bot Protection',
      description: 'NFT minting program lacks rate limiting or gatekeeper integration. ' +
        'Bots can rapidly mint entire collections.',
      recommendation: 'Integrate Civic Pass or similar gatekeeper for bot protection. ' +
        'Implement per-wallet mint limits and cooldown periods.',
      location: parsed.path,
    });
  }

  // Check for proper initialization
  if (/init|initialize/i.test(content)) {
    const hasZeroCheck = /#\[account\(zero\)\]|zero.*?constraint|account\(init/i.test(content);
    if (!hasZeroCheck) {
      findings.push({
        severity: 'critical',
        category: 'candy-machine',
        title: 'Candy Machine Missing Zero Constraint',
        description: 'Initialization without #[account(zero)] allows re-initialization attacks. ' +
          'This was the exact vulnerability in the Candy Machine smashing exploit.',
        recommendation: 'Use #[account(zero)] for initialization or #[account(init)] in Anchor. ' +
          'Never use #[account(zero)] when you mean #[account(init)].',
        location: parsed.path,
      });
    }
  }

  // Check whitelist verification
  if (/whitelist|allowlist|presale/i.test(content)) {
    const hasProofVerification = /merkle.*?verify|proof.*?verify|verify.*?proof/i.test(content);
    const hasSignatureVerification = /ed25519.*?verify|signature.*?whitelist/i.test(content);

    if (!hasProofVerification && !hasSignatureVerification) {
      findings.push({
        severity: 'high',
        category: 'candy-machine',
        title: 'Whitelist Without Cryptographic Verification',
        description: 'Whitelist implementation without merkle proof or signature verification. ' +
          'Attackers can forge whitelist entries.',
        recommendation: 'Use merkle tree proofs for large whitelists or Ed25519 signatures from trusted authority.',
        location: parsed.path,
      });
    }
  }

  // Check price validation
  if (/price|cost|payment|lamports/i.test(content)) {
    const hasPriceCheck = /price\s*[<>=]|lamports\s*[<>=]|transfer.*?amount\s*==|payment.*?verify/i.test(content);
    if (!hasPriceCheck) {
      findings.push({
        severity: 'high',
        category: 'candy-machine',
        title: 'Mint Price Not Properly Validated',
        description: 'NFT minting price validation is missing or insufficient. ' +
          'Attackers could mint at incorrect prices.',
        recommendation: 'Verify exact payment amount before minting: ' +
          'require!(payment == expected_price, ErrorCode::InvalidPrice)',
        location: parsed.path,
      });
    }
  }

  // Check supply limits
  if (/supply|max_supply|items_available|total/i.test(content)) {
    const hasSupplyCheck = /items_redeemed\s*<|supply\s*[<>=]|remaining\s*>|sold.*?out/i.test(content);
    if (!hasSupplyCheck) {
      findings.push({
        severity: 'high',
        category: 'candy-machine',
        title: 'Supply Limit Not Enforced',
        description: 'NFT supply limit validation appears missing. ' +
          'Could allow over-minting beyond intended supply.',
        recommendation: 'Check: require!(items_redeemed < max_supply) before each mint.',
        location: parsed.path,
    });
    }
  }

  // Check per-wallet limits
  const hasWalletLimit = /wallet.*?limit|per.*?wallet|max.*?per.*?user|mint.*?count/i.test(content);
  if (!hasWalletLimit) {
    findings.push({
      severity: 'medium',
      category: 'candy-machine',
      title: 'No Per-Wallet Mint Limit',
      description: 'No per-wallet mint limit detected. ' +
        'Single wallets could acquire disproportionate share of collection.',
      recommendation: 'Implement per-wallet mint tracking: store mint count per wallet and enforce limits.',
      location: parsed.path,
    });
  }

  return findings;
}
