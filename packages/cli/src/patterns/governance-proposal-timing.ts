import type { Finding } from '../commands/audit.js';
import type { ParsedRust } from '../parsers/rust.js';

/**
 * Governance Proposal Timing Patterns
 * 
 * Based on Synthetify DAO exploit (Oct 2023) where attacker exploited
 * an inactive DAO by submitting malicious proposals that went unnoticed,
 * stealing $230K. Also covers Audius governance exploit ($6.1M).
 * 
 * Detects:
 * - Short voting periods
 * - Low quorum thresholds
 * - Missing proposal review periods
 * - Governance manipulation vectors
 */

export function checkGovernanceProposalTiming(parsed: ParsedRust): Finding[] {
  const findings: Finding[] = [];
  const content = parsed.content;

  // Pattern 1: Extremely short voting period
  if (/voting.*period|vote.*duration|proposal.*time/i.test(content)) {
    if (/[<]=?\s*[1-3]\s*\*?\s*(day|DAY|86400)|hours?\s*[<]=?\s*24/i.test(content)) {
      findings.push({
        id: 'GOVERNANCE_SHORT_VOTING_PERIOD',
        severity: 'high',
        title: 'Governance Voting Period Too Short',
        description: 'Short voting periods allow malicious proposals to pass before community can review. Synthetify lost $230K when proposals went unnoticed.',
        location: parsed.path,
        recommendation: 'Set minimum voting period of 3-7 days. Implement notification systems for new proposals.'
      });
    }
  }

  // Pattern 2: Low quorum threshold
  if (/quorum|minimum.*votes|threshold/i.test(content) && /governance|proposal|vote/i.test(content)) {
    if (/quorum.*[<]=?\s*[0-9]%|quorum.*[<]=?\s*0\.[0-9]{2}/i.test(content)) {
      findings.push({
        id: 'GOVERNANCE_LOW_QUORUM',
        severity: 'high',
        title: 'Governance Quorum Threshold Too Low',
        description: 'Low quorum allows attackers to pass proposals with minimal participation. Synthetify attacker used their own tokens to meet quorum.',
        location: parsed.path,
        recommendation: 'Set meaningful quorum thresholds (e.g., 10-20% of circulating supply). Monitor for sudden large token acquisitions before votes.'
      });
    }
  }

  // Pattern 3: No proposal delay/timelock
  if (/proposal|governance/i.test(content) && /execute|process|implement/i.test(content)) {
    if (!/timelock|delay|wait.*period|execution.*delay/i.test(content)) {
      findings.push({
        id: 'GOVERNANCE_NO_TIMELOCK',
        severity: 'critical',
        title: 'Governance Proposals Execute Without Timelock',
        description: 'Proposals execute immediately after passing. Timelock allows community to review and potentially veto malicious proposals.',
        location: parsed.path,
        recommendation: 'Implement mandatory timelock (24-72h) between proposal passing and execution. Add veto capability for guardians.'
      });
    }
  }

  // Pattern 4: No proposal review period
  if (/create.*proposal|submit.*proposal|new.*proposal/i.test(content)) {
    if (!/review.*period|pending.*period|warm.*up/i.test(content)) {
      findings.push({
        id: 'GOVERNANCE_NO_REVIEW_PERIOD',
        severity: 'medium',
        title: 'No Proposal Review Period Before Voting',
        description: 'Proposals go to vote immediately without review period. Community cannot analyze potentially malicious code.',
        location: parsed.path,
        recommendation: 'Add review period before voting begins. Allow community to discuss and flag suspicious proposals.'
      });
    }
  }

  // Pattern 5: Single transaction proposals with treasury access
  if (/proposal|governance/i.test(content) && /treasury|transfer|withdraw/i.test(content)) {
    if (!/multi.*step|staged|gradual|limit.*per/i.test(content)) {
      findings.push({
        id: 'GOVERNANCE_TREASURY_SINGLE_TX',
        severity: 'high',
        title: 'Treasury Access in Single Transaction',
        description: 'Proposals can drain treasury in single transaction. Should require staged withdrawals or limits.',
        location: parsed.path,
        recommendation: 'Implement withdrawal limits per proposal. Require multi-stage execution for large treasury operations.'
      });
    }
  }

  // Pattern 6: No veto council or guardian
  if (/governance|dao/i.test(content) && /execute|implement/i.test(content)) {
    if (!/veto|guardian|council|emergency.*stop|override/i.test(content)) {
      findings.push({
        id: 'GOVERNANCE_NO_VETO',
        severity: 'medium',
        title: 'No Veto Mechanism for Malicious Proposals',
        description: 'DAO lacks veto capability for clearly malicious proposals. Audius and Synthetify exploits could have been stopped with veto.',
        location: parsed.path,
        recommendation: 'Implement guardian council with veto power. Add emergency stop for clearly malicious proposals.'
      });
    }
  }

  // Pattern 7: Proposal code not verified
  if (/proposal.*code|execute.*instruction|proposal.*payload/i.test(content)) {
    if (!/verify.*code|audit.*proposal|hash.*check/i.test(content)) {
      findings.push({
        id: 'GOVERNANCE_CODE_NOT_VERIFIED',
        severity: 'high',
        title: 'Proposal Code Not Verified Before Execution',
        description: 'Proposal payload/code executed without verification. Attackers can hide malicious code in innocent-looking proposals.',
        location: parsed.path,
        recommendation: 'Require proposal code to be verified against published hash. Make proposal code publicly readable before execution.'
      });
    }
  }

  // Pattern 8: Token-weighted voting without lockup
  if (/vote.*weight|voting.*power|token.*vote/i.test(content)) {
    if (!/lock|stake|escrow|vest/i.test(content)) {
      findings.push({
        id: 'GOVERNANCE_NO_TOKEN_LOCK',
        severity: 'medium',
        title: 'Voting Power Without Token Lockup',
        description: 'Tokens can be used to vote without lockup. Attackers can borrow tokens via flash loan to manipulate votes.',
        location: parsed.path,
        recommendation: 'Require token lockup for voting. Use snapshot of holdings before proposal creation.'
      });
    }
  }

  // Pattern 9: Inactive DAO vulnerability
  if (/dao|governance/i.test(content)) {
    if (!/activity.*check|last.*proposal|engagement|participation.*track/i.test(content)) {
      findings.push({
        id: 'GOVERNANCE_ACTIVITY_NOT_MONITORED',
        severity: 'low',
        title: 'DAO Activity Not Monitored',
        description: 'Inactive DAOs are prime targets for governance attacks. Synthetify was exploited while inactive.',
        location: parsed.path,
        recommendation: 'Monitor DAO activity levels. Alert if unusual proposal activity in dormant DAO. Consider auto-pause for inactive DAOs.'
      });
    }
  }

  // Pattern 10: Proposal spam protection missing
  if (/create.*proposal|submit.*proposal/i.test(content)) {
    if (!/proposal.*fee|stake.*required|reputation|cooldown/i.test(content)) {
      findings.push({
        id: 'GOVERNANCE_NO_SPAM_PROTECTION',
        severity: 'low',
        title: 'No Spam Protection for Proposals',
        description: 'Anyone can create proposals without cost. Attackers can spam proposals to hide malicious ones.',
        location: parsed.path,
        recommendation: 'Require proposal bond/fee that is returned if proposal is not flagged as malicious.'
      });
    }
  }

  return findings;
}
