import type { Finding } from '../commands/audit.js';
import type { ParsedRust } from '../parsers/rust.js';

/**
 * MEV (Maximal Extractable Value) Protection Patterns
 * 
 * Covers front-running, sandwich attacks, JIT liquidity, and other
 * MEV-related vulnerabilities. Based on Jito DDoS, sandwich attacks
 * on Solana AMMs, and general MEV protection best practices.
 * 
 * Detects:
 * - Front-running vulnerabilities
 * - Sandwich attack vectors
 * - Price slippage exploitation
 * - Transaction ordering manipulation
 */

export function checkMevProtection(parsed: ParsedRust): Finding[] {
  const findings: Finding[] = [];
  const content = parsed.content;

  // Pattern 1: Swap without slippage protection
  if (/swap|exchange|trade/i.test(content) && /amount.*out|output.*amount|receive/i.test(content)) {
    if (!/min.*amount|minimum.*out|slippage/i.test(content)) {
      findings.push({
        id: 'SWAP_NO_SLIPPAGE_PROTECTION',
        severity: 'critical',
        title: 'Swap Without Slippage Protection',
        description: 'Token swap without minimum output check. Sandwich attackers can extract unlimited value.',
        location: parsed.path,
        recommendation: 'Always require minimum output amount. Calculate based on oracle price with small tolerance.'
      });
    }
  }

  // Pattern 2: Large trade without price impact limit
  if (/trade|swap|order/i.test(content) && /size|amount|volume/i.test(content)) {
    if (!/price.*impact|max.*impact|impact.*limit/i.test(content)) {
      findings.push({
        id: 'TRADE_NO_PRICE_IMPACT_LIMIT',
        severity: 'high',
        title: 'Trade Without Price Impact Limit',
        description: 'Large trades accepted without price impact limits. Could enable manipulation or cause unintended losses.',
        location: parsed.path,
        recommendation: 'Implement price impact limits. Reject trades that move price beyond threshold.'
      });
    }
  }

  // Pattern 3: Liquidation MEV extraction
  if (/liquidat/i.test(content)) {
    if (!/priority.*fee.*limit|max.*tip|dutch.*auction/i.test(content)) {
      findings.push({
        id: 'LIQUIDATION_MEV_EXTRACTION',
        severity: 'medium',
        title: 'Liquidations Vulnerable to MEV Extraction',
        description: 'Liquidations without MEV mitigation. Searchers extract value through priority fee bidding.',
        location: parsed.path,
        recommendation: 'Consider Dutch auctions for liquidations. Implement liquidator allowlists. Share MEV with protocol/users.'
      });
    }
  }

  // Pattern 4: Pending transaction exposure
  if (/mempool|pending|unconfirmed/i.test(content) && /transaction|tx/i.test(content)) {
    if (!/private.*mempool|flashbots|jito.*bundle/i.test(content)) {
      findings.push({
        id: 'TX_PENDING_EXPOSURE',
        severity: 'medium',
        title: 'Transactions Exposed in Pending State',
        description: 'Transactions visible in mempool before execution. Enables front-running by searchers.',
        location: parsed.path,
        recommendation: 'Use private mempools (Jito bundles) for sensitive transactions. Consider commit-reveal schemes.'
      });
    }
  }

  // Pattern 5: Oracle update front-running
  if (/oracle|price.*feed|pyth|switchboard/i.test(content) && /update|refresh|push/i.test(content)) {
    if (!/same.*slot|atomic|bundled/i.test(content)) {
      findings.push({
        id: 'ORACLE_UPDATE_FRONTRUNNABLE',
        severity: 'high',
        title: 'Oracle Updates Can Be Front-Run',
        description: 'Oracle price updates can be observed and front-run. Attackers trade before price change hits.',
        location: parsed.path,
        recommendation: 'Bundle oracle updates with user transactions. Use Pyth on-demand pricing. Consider delayed price adoption.'
      });
    }
  }

  // Pattern 6: NFT mint sniping
  if (/nft.*mint|mint.*nft|public.*mint/i.test(content)) {
    if (!/allowlist|whitelist|signature.*gated|merkle.*proof/i.test(content)) {
      findings.push({
        id: 'NFT_MINT_SNIPABLE',
        severity: 'medium',
        title: 'NFT Mint Vulnerable to Sniping',
        description: 'Public mint without protection. Bots can snipe all mints at launch.',
        location: parsed.path,
        recommendation: 'Use allowlists for fair distribution. Implement anti-bot measures. Consider randomized mint timing.'
      });
    }
  }

  // Pattern 7: JIT liquidity extraction
  if (/liquidity|pool|amm/i.test(content) && /add|provide|deposit/i.test(content)) {
    if (!/min.*duration|lockup|time.*weighted/i.test(content)) {
      findings.push({
        id: 'JIT_LIQUIDITY_VULNERABLE',
        severity: 'medium',
        title: 'Vulnerable to JIT Liquidity Attacks',
        description: 'Liquidity can be added/removed instantly. JIT liquidity providers extract fees without risk.',
        location: parsed.path,
        recommendation: 'Implement minimum liquidity duration. Use time-weighted fee sharing. Consider LP lockups.'
      });
    }
  }

  // Pattern 8: Arbitrage bot vulnerability
  if (/arbitrage|arb|price.*diff/i.test(content)) {
    if (!/rate.*limit|cooldown|max.*profit/i.test(content)) {
      findings.push({
        id: 'ARB_EXTRACTION_UNLIMITED',
        severity: 'medium',
        title: 'Arbitrage Extraction Not Limited',
        description: 'Arbitrage opportunities without limits. MEV bots can repeatedly extract value.',
        location: parsed.path,
        recommendation: 'Implement rate limits on arbitrage. Consider capturing arb value for protocol/LPs.'
      });
    }
  }

  // Pattern 9: Block producer MEV
  if (/leader|block.*producer|validator.*schedule/i.test(content)) {
    if (!/random.*selection|rotation|fair.*ordering/i.test(content)) {
      findings.push({
        id: 'BLOCK_PRODUCER_MEV',
        severity: 'low',
        title: 'Block Producer May Extract MEV',
        description: 'Transaction ordering controlled by block producer. Leaders can reorder for profit.',
        location: parsed.path,
        recommendation: 'Consider fair ordering protocols. Use encrypted mempools. Design for ordering-resistant operations.'
      });
    }
  }

  // Pattern 10: Price deadline missing
  if (/swap|trade|order/i.test(content) && /price|quote|rate/i.test(content)) {
    if (!/deadline|expiry|valid.*until/i.test(content)) {
      findings.push({
        id: 'TRADE_NO_DEADLINE',
        severity: 'high',
        title: 'Trade Without Deadline/Expiry',
        description: 'Trades can be held and executed at worse prices later. Stale quotes enable attacks.',
        location: parsed.path,
        recommendation: 'Require deadline on all trades. Reject stale quotes. Include timestamp in swap parameters.'
      });
    }
  }

  // Pattern 11: Multi-step transaction vulnerability
  if (/multi.*step|sequence|batch.*tx/i.test(content)) {
    if (!/atomic|bundle|single.*tx/i.test(content)) {
      findings.push({
        id: 'MULTISTEP_TX_FRONTRUNNABLE',
        severity: 'high',
        title: 'Multi-Step Transaction Can Be Front-Run',
        description: 'Multi-transaction operations can have steps sandwiched. Each step is separately vulnerable.',
        location: parsed.path,
        recommendation: 'Combine operations into single atomic transaction. Use Jito bundles for multi-tx flows.'
      });
    }
  }

  return findings;
}
