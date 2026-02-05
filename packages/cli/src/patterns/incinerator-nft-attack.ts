import type { Finding } from '../commands/audit.js';
import type { ParsedRust } from '../parsers/rust.js';

/**
 * Incinerator NFT Attack Patterns
 * Based on: Schrodinger's NFT / Solens Incinerator exploit
 * 
 * Attack involves chaining multiple small vulnerabilities:
 * 1. Create malicious SPL Token program that allows arbitrary minting
 * 2. Use incinerator to "burn" tokens and receive value
 * 3. Combine with other protocol vulnerabilities
 * 
 * Key insight: Attackers chain seemingly minor issues into major exploits.
 */
export function checkIncineratorNftAttack(parsed: ParsedRust): Finding[] {
  const findings: Finding[] = [];
  const content = parsed.content;

  // Detect burn-for-value patterns
  const burnForValue = [
    /burn.*?receive|burn.*?claim|burn.*?redeem/gi,
    /incinerator|incinerate|destroy.*?token/gi,
    /token.*?burn.*?payout|burn.*?reward/gi,
  ];

  for (const pattern of burnForValue) {
    const matches = content.match(pattern);
    if (matches) {
      // Check if token program is verified
      const hasTokenProgramCheck = /token_program.*?==.*?spl_token|spl_token::id\(\)|TOKEN_PROGRAM_ID/i.test(content);
      if (!hasTokenProgramCheck) {
        findings.push({
          severity: 'critical',
          category: 'incinerator-attack',
          title: 'Burn-for-Value Without Token Program Verification',
          description: `Pattern "${matches[0]}" burns tokens for value but doesn't verify the token program. ` +
            'Attackers can use fake token programs that allow minting burned tokens back.',
          recommendation: 'Always verify token_program.key() == spl_token::id(). ' +
            'Consider using Anchor\'s Program<Token> type for automatic verification.',
          location: parsed.path,
        });
      }
    }
  }

  // Detect NFT verification gaps
  if (/nft|non.*?fungible|metadata/i.test(content)) {
    const hasCollectionCheck = /collection.*?verified|verified.*?collection|collection_mint/i.test(content);
    const hasMetaplexCheck = /metaplex|mpl_token_metadata/i.test(content);

    if (!hasCollectionCheck && !hasMetaplexCheck) {
      findings.push({
        severity: 'high',
        category: 'incinerator-attack',
        title: 'NFT Without Collection Verification',
        description: 'NFT operations without verifying collection membership. ' +
          'Attackers can mint fake NFTs that pass validation.',
        recommendation: 'Verify NFT belongs to expected collection: check metadata.collection.verified == true ' +
          'and metadata.collection.key == expected_collection.',
        location: parsed.path,
      });
    }
  }

  // Detect CPI to token program without ID check
  if (/invoke.*?burn|burn.*?cpi|CpiContext.*?burn/i.test(content)) {
    const hardcodedProgram = /spl_token::id\(\)|TOKEN_PROGRAM_ID|token_program\.key\(\)\s*==|anchor_spl::token/i.test(content);
    if (!hardcodedProgram) {
      findings.push({
        severity: 'high',
        category: 'incinerator-attack',
        title: 'Token Burn CPI Without Program Verification',
        description: 'CPI to burn tokens without verifying the token program ID. ' +
          'Malicious programs could be substituted.',
        recommendation: 'Verify token program ID before CPI: ' +
          'require!(token_program.key() == spl_token::id(), ErrorCode::InvalidTokenProgram)',
        location: parsed.path,
      });
    }
  }

  // Detect exploit chaining potential
  const chainableVulns = [];
  
  if (/UncheckedAccount|AccountInfo/i.test(content)) {
    chainableVulns.push('unchecked accounts');
  }
  if (/remaining_accounts/i.test(content) && !/verify.*?remaining/i.test(content)) {
    chainableVulns.push('unverified remaining accounts');
  }
  if (/init_if_needed/i.test(content)) {
    chainableVulns.push('init_if_needed');
  }

  if (chainableVulns.length >= 2) {
    findings.push({
      severity: 'high',
      category: 'incinerator-attack',
      title: 'Multiple Chainable Vulnerabilities Detected',
      description: `Found multiple patterns that could be chained: ${chainableVulns.join(', ')}. ` +
        'Attackers often combine minor issues into critical exploits.',
      recommendation: 'Review each vulnerability individually and consider how they could be combined. ' +
        'The Schrodinger\'s NFT attack combined multiple small issues into $1.26M exploit.',
      location: parsed.path,
    });
  }

  return findings;
}
