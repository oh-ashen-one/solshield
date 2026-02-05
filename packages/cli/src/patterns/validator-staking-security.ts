import type { Finding } from '../commands/audit.js';
import type { ParsedRust } from '../parsers/rust.js';

/**
 * Validator and Staking Security Patterns
 * 
 * Covers validator security, stake pool vulnerabilities, slashing risks,
 * and delegation attacks. Based on various Solana staking exploits and
 * best practices from stake pool audits.
 * 
 * Detects:
 * - Stake pool manipulation
 * - Validator selection attacks
 * - Delegation/undelegation exploits
 * - Slashing mechanism bypasses
 */

export function checkValidatorStakingSecurity(parsed: ParsedRust): Finding[] {
  const findings: Finding[] = [];
  const content = parsed.content;

  // Pattern 1: Stake pool without diversification check
  if (/stake.*pool|staking.*pool|validator.*set/i.test(content)) {
    if (!/max.*per.*validator|diversification|concentration.*limit/i.test(content)) {
      findings.push({
        id: 'STAKE_POOL_NO_DIVERSIFICATION',
        severity: 'high',
        title: 'Stake Pool Without Diversification Limits',
        description: 'Stake pool allows concentration on single validator. Validator failure or attack impacts entire pool.',
        location: parsed.path,
        recommendation: 'Implement maximum stake per validator. Require diversification across validator set.'
      });
    }
  }

  // Pattern 2: Validator selection manipulation
  if (/validator.*select|choose.*validator|delegate.*to/i.test(content)) {
    if (!/performance.*score|uptime.*check|reputation/i.test(content)) {
      findings.push({
        id: 'VALIDATOR_SELECTION_MANIPULABLE',
        severity: 'medium',
        title: 'Validator Selection May Be Manipulable',
        description: 'Validator selection without performance metrics. Malicious validators could game selection.',
        location: parsed.path,
        recommendation: 'Include validator performance, uptime, and reputation in selection criteria. Use randomized selection.'
      });
    }
  }

  // Pattern 3: Stake withdrawal timing attack
  if (/withdraw.*stake|unstake|undelegate/i.test(content)) {
    if (!/cooldown|unbond.*period|epoch.*delay/i.test(content)) {
      findings.push({
        id: 'STAKE_INSTANT_WITHDRAWAL',
        severity: 'high',
        title: 'Stake Withdrawal Without Cooldown',
        description: 'Instant stake withdrawal could enable flash delegation attacks or run-on-stake-pool scenarios.',
        location: parsed.path,
        recommendation: 'Implement unbonding period. Use epoch-based withdrawal processing. Add withdrawal limits.'
      });
    }
  }

  // Pattern 4: Slashing without evidence verification
  if (/slash|penalty|punish.*validator/i.test(content)) {
    if (!/evidence|proof|verify.*violation/i.test(content)) {
      findings.push({
        id: 'SLASHING_NO_EVIDENCE',
        severity: 'critical',
        title: 'Slashing Without Evidence Verification',
        description: 'Slashing mechanism without cryptographic evidence verification. Validators could be unfairly penalized.',
        location: parsed.path,
        recommendation: 'Require cryptographic proof of misbehavior. Implement challenge period for disputed slashing.'
      });
    }
  }

  // Pattern 5: Reward calculation manipulation
  if (/staking.*reward|delegation.*reward|validator.*commission/i.test(content)) {
    if (!/epoch.*snapshot|time.*weight|checkpoint/i.test(content)) {
      findings.push({
        id: 'STAKING_REWARD_FLASH_ATTACK',
        severity: 'high',
        title: 'Staking Rewards Vulnerable to Flash Attack',
        description: 'Rewards calculated without proper time-weighting. Flash delegation could claim disproportionate rewards.',
        location: parsed.path,
        recommendation: 'Use epoch snapshots for reward calculation. Implement time-weighted staking. Add minimum stake duration.'
      });
    }
  }

  // Pattern 6: Validator commission changes
  if (/commission|fee.*rate|validator.*fee/i.test(content)) {
    if (!/commission.*lock|max.*commission|notice.*period/i.test(content)) {
      findings.push({
        id: 'VALIDATOR_COMMISSION_ABUSE',
        severity: 'medium',
        title: 'Validator Commission Can Be Changed Arbitrarily',
        description: 'Validators can change commission without notice. Could bait delegators with low fees then increase.',
        location: parsed.path,
        recommendation: 'Implement commission change notice period. Cap maximum commission. Lock commission for minimum epochs.'
      });
    }
  }

  // Pattern 7: Stake account ownership verification
  if (/stake.*account|delegation.*account/i.test(content)) {
    if (!/owner.*check|authority.*verify|withdrawer.*validate/i.test(content)) {
      findings.push({
        id: 'STAKE_ACCOUNT_OWNERSHIP_CHECK',
        severity: 'high',
        title: 'Stake Account Ownership Not Verified',
        description: 'Operations on stake accounts without proper ownership verification. Attacker could manipulate others stakes.',
        location: parsed.path,
        recommendation: 'Verify stake account withdrawer and staker authorities match expected addresses.'
      });
    }
  }

  // Pattern 8: Pool token price manipulation
  if (/pool.*token|stake.*token|lst|liquid.*stake/i.test(content)) {
    if (!/exchange.*rate.*update|price.*oracle|rate.*validation/i.test(content)) {
      findings.push({
        id: 'POOL_TOKEN_PRICE_MANIPULATION',
        severity: 'high',
        title: 'Pool Token Exchange Rate May Be Manipulable',
        description: 'Liquid staking token price without proper rate validation. Price manipulation could enable arbitrage attacks.',
        location: parsed.path,
        recommendation: 'Use secure exchange rate calculation. Add rate change limits. Implement oracle-based validation.'
      });
    }
  }

  // Pattern 9: Emergency withdrawal bypass
  if (/emergency.*withdraw|forced.*unstake|admin.*withdraw/i.test(content)) {
    if (!/multisig|timelock|governance.*approval/i.test(content)) {
      findings.push({
        id: 'EMERGENCY_WITHDRAW_CENTRALIZED',
        severity: 'high',
        title: 'Emergency Withdrawal Too Centralized',
        description: 'Emergency withdrawal controlled by single admin. Compromised admin could steal all staked funds.',
        location: parsed.path,
        recommendation: 'Require multisig for emergency operations. Add timelock for withdrawal. Implement guardian veto.'
      });
    }
  }

  // Pattern 10: Validator set update without delay
  if (/validator.*set|add.*validator|remove.*validator/i.test(content)) {
    if (!/epoch.*boundary|transition.*period|activation.*delay/i.test(content)) {
      findings.push({
        id: 'VALIDATOR_SET_INSTANT_UPDATE',
        severity: 'medium',
        title: 'Validator Set Updated Without Transition Period',
        description: 'Validator set changes applied immediately. Could disrupt stake distribution or enable attacks.',
        location: parsed.path,
        recommendation: 'Apply validator changes at epoch boundaries. Add activation delay for new validators.'
      });
    }
  }

  // Pattern 11: Stake split/merge vulnerabilities
  if (/split.*stake|merge.*stake|stake.*split/i.test(content)) {
    if (!/total.*preserved|lamport.*check|invariant/i.test(content)) {
      findings.push({
        id: 'STAKE_SPLIT_MERGE_INVARIANT',
        severity: 'high',
        title: 'Stake Split/Merge May Not Preserve Invariants',
        description: 'Stake operations without invariant checks could allow stake creation or destruction.',
        location: parsed.path,
        recommendation: 'Verify total stake preserved across split/merge. Check lamport balances before and after.'
      });
    }
  }

  return findings;
}
