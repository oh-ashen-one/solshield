import type { Finding } from '../commands/audit.js';
import type { ParsedRust } from '../parsers/rust.js';

/**
 * Rug Pull Detection Patterns
 * 
 * Detects common indicators of potential rug pulls and scam tokens.
 * Based on analysis of Solana rug pulls and common scam patterns.
 * 
 * Detects:
 * - Hidden mint authority
 * - Honeypot mechanisms  
 * - Liquidity withdrawal risks
 * - Backdoor admin functions
 */

export function checkRugPullDetection(parsed: ParsedRust): Finding[] {
  const findings: Finding[] = [];
  const content = parsed.content;

  // Pattern 1: Mint authority not renounced
  if (/mint.*authority|minting.*rights/i.test(content)) {
    if (!/renounce|disable.*mint|set.*none|remove.*authority/i.test(content)) {
      findings.push({
        id: 'MINT_AUTHORITY_NOT_RENOUNCED',
        severity: 'high',
        title: 'Mint Authority Not Renounced',
        description: 'Token mint authority can still create tokens. Common rug pull vector - team can infinitely mint.',
        location: parsed.path,
        recommendation: 'For community tokens, renounce mint authority. If needed, use multisig with timelock.'
      });
    }
  }

  // Pattern 2: Admin can pause trading/transfers
  if (/pause.*transfer|freeze.*trading|disable.*swap|blacklist/i.test(content)) {
    if (!/emergency.*only|timelocked|governance/i.test(content)) {
      findings.push({
        id: 'ADMIN_CAN_FREEZE_TRADING',
        severity: 'critical',
        title: 'Admin Can Freeze Trading/Transfers',
        description: 'Admin can pause trading - classic honeypot mechanism. Users buy but cannot sell.',
        location: parsed.path,
        recommendation: 'Remove arbitrary freeze capability. If needed for compliance, require governance approval.'
      });
    }
  }

  // Pattern 3: Hidden fees/taxes
  if (/fee|tax|take.*cut/i.test(content) && /transfer|swap|trade/i.test(content)) {
    if (!/transparent|fixed|immutable|capped/i.test(content)) {
      findings.push({
        id: 'HIDDEN_FEES_POSSIBLE',
        severity: 'high',
        title: 'Transaction Fees May Be Hidden or Variable',
        description: 'Fee structure not transparently defined. Admin could set high hidden fees to drain users.',
        location: parsed.path,
        recommendation: 'Make fee rates immutable or capped. Clearly document all fees. Use governance for changes.'
      });
    }
  }

  // Pattern 4: Liquidity removal without restriction
  if (/remove.*liquidity|withdraw.*lp|pull.*liquidity/i.test(content)) {
    if (!/lock|timelock|minimum.*duration|vesting/i.test(content)) {
      findings.push({
        id: 'LIQUIDITY_CAN_BE_PULLED',
        severity: 'critical',
        title: 'Liquidity Can Be Removed Without Restriction',
        description: 'Team can remove liquidity immediately. Classic rug pull - remove liquidity leaving token worthless.',
        location: parsed.path,
        recommendation: 'Lock liquidity in third-party locker. Use vesting schedules. Burn LP tokens.'
      });
    }
  }

  // Pattern 5: Backdoor admin functions
  if (/admin.*withdraw|owner.*drain|emergency.*admin|backdoor/i.test(content)) {
    findings.push({
      id: 'BACKDOOR_ADMIN_FUNCTION',
      severity: 'critical',
      title: 'Potential Backdoor Admin Function',
      description: 'Admin function that could drain funds. Even "emergency" functions are commonly abused.',
      location: parsed.path,
      recommendation: 'Remove or severely restrict admin withdrawal functions. Require multisig + timelock.'
    });
  }

  // Pattern 6: Unlimited token approval manipulation
  if (/approve|allowance/i.test(content) && /infinite|max|unlimited/i.test(content)) {
    findings.push({
      id: 'UNLIMITED_APPROVAL_RISK',
      severity: 'high',
      title: 'Unlimited Token Approval Pattern',
      description: 'Requests unlimited approval. Compromised contract could drain all approved tokens.',
      location: parsed.path,
      recommendation: 'Request only needed approval amounts. Warn users about unlimited approvals.'
    });
  }

  // Pattern 7: Proxy upgrade without timelock
  if (/upgrade|proxy|implementation/i.test(content) && /set|change|update/i.test(content)) {
    if (!/timelock|delay|governance.*vote/i.test(content)) {
      findings.push({
        id: 'PROXY_INSTANT_UPGRADE',
        severity: 'critical',
        title: 'Contract Can Be Upgraded Instantly',
        description: 'Admin can upgrade contract logic immediately. Could upgrade to malicious implementation.',
        location: parsed.path,
        recommendation: 'Add timelock to upgrades. Use governance for upgrade approval. Consider immutable contracts.'
      });
    }
  }

  // Pattern 8: Whitelist/blacklist manipulation
  if (/whitelist|blacklist|allow.*list|block.*list/i.test(content)) {
    if (!/immutable|governance|transparent/i.test(content)) {
      findings.push({
        id: 'WHITELIST_MANIPULATION',
        severity: 'high',
        title: 'Whitelist/Blacklist Can Be Manipulated',
        description: 'Admin can arbitrarily whitelist/blacklist addresses. Could block user from selling.',
        location: parsed.path,
        recommendation: 'Make lists immutable or governance-controlled. Publish list on-chain for transparency.'
      });
    }
  }

  // Pattern 9: Max wallet/transaction limits that can be changed
  if (/max.*wallet|max.*tx|max.*transaction|max.*buy/i.test(content)) {
    if (!/immutable|fixed|cannot.*change/i.test(content)) {
      findings.push({
        id: 'CHANGEABLE_MAX_LIMITS',
        severity: 'medium',
        title: 'Max Wallet/Transaction Limits Can Be Changed',
        description: 'Admin can modify max limits. Could trap whales by reducing limits after they buy.',
        location: parsed.path,
        recommendation: 'Make limits immutable or only increasable. Use timelock for decreases.'
      });
    }
  }

  // Pattern 10: Anti-bot measures that could be abused
  if (/anti.*bot|anti.*snipe|trading.*delay/i.test(content)) {
    if (!/temporary|time.*limited|disable.*after/i.test(content)) {
      findings.push({
        id: 'ANTIBOT_ABUSE_RISK',
        severity: 'medium',
        title: 'Anti-Bot Measures Could Be Abused',
        description: 'Anti-bot restrictions not time-limited. Could be used to permanently restrict trading.',
        location: parsed.path,
        recommendation: 'Time-limit anti-bot measures. Remove after launch period. Make restrictions transparent.'
      });
    }
  }

  // Pattern 11: Team token allocation without vesting
  if (/team.*token|founder.*alloc|advisor.*token/i.test(content)) {
    if (!/vest|lock|cliff|release.*schedule/i.test(content)) {
      findings.push({
        id: 'TEAM_TOKENS_NO_VESTING',
        severity: 'high',
        title: 'Team Tokens Without Vesting Schedule',
        description: 'Team tokens not vested. Team can dump immediately, crashing price.',
        location: parsed.path,
        recommendation: 'Implement vesting with cliff. Lock team tokens for minimum 1-2 years. Use transparent schedules.'
      });
    }
  }

  // Pattern 12: Hidden wallet exclusions
  if (/exclude|exempt|skip.*fee|no.*tax/i.test(content)) {
    if (!/public|transparent|governance/i.test(content)) {
      findings.push({
        id: 'HIDDEN_WALLET_EXCLUSIONS',
        severity: 'medium',
        title: 'Hidden Fee-Exempt Wallets',
        description: 'Some wallets excluded from fees without transparency. Could hide team wallets selling tax-free.',
        location: parsed.path,
        recommendation: 'Publish all exempt wallets. Require governance to add exclusions. Limit exclusion count.'
      });
    }
  }

  return findings;
}
