/**
 * Batch 29: Advanced Business Logic & Protocol Patterns
 * Based on Sec3 2025 Report - Business Logic (38.5% of severe findings)
 * Added: Feb 5, 2026 6:00 AM CST
 */

import type { PatternInput } from './index.js';
import type { Finding } from '../commands/audit.js';

// SOL805: Missing Protocol Fee Accrual
export function checkMissingFeeAccrual(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  
  // Check for fee calculations without proper accrual
  if ((content.includes('protocol_fee') || content.includes('fee_rate')) &&
      !content.includes('accrue') && !content.includes('accumulate')) {
    findings.push({
      id: 'SOL805',
      severity: 'high',
      title: 'Missing Protocol Fee Accrual',
      description: 'Protocol fees should be properly accrued before fee-related operations to prevent fee loss',
      location: input.path,
      recommendation: 'Implement fee accrual logic before any fee collection or distribution operations',
    });
  }
  return findings;
}

// SOL806: Incorrect Reward Rate Calculation
export function checkIncorrectRewardRate(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  
  if (content.includes('reward_rate') || content.includes('emission_rate')) {
    // Check for reward rate updates without proper time normalization
    if (!content.includes('per_second') && !content.includes('per_slot') && 
        !content.includes('time_elapsed')) {
      findings.push({
        id: 'SOL806',
        severity: 'high',
        title: 'Incorrect Reward Rate Calculation',
        description: 'Reward rates must be properly normalized to time units to prevent incorrect distributions',
        location: input.path,
        recommendation: 'Normalize reward rates to per-second or per-slot basis with proper time tracking',
      });
    }
  }
  return findings;
}

// SOL807: Missing Withdrawal Queue Processing
export function checkMissingWithdrawalQueue(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  
  if (content.includes('withdraw') && content.includes('unstake')) {
    if (!content.includes('queue') && !content.includes('pending') && 
        !content.includes('cooldown')) {
      findings.push({
        id: 'SOL807',
        severity: 'medium',
        title: 'Missing Withdrawal Queue Processing',
        description: 'Withdrawal operations should use a queue system to prevent bank run scenarios',
        location: input.path,
        recommendation: 'Implement a withdrawal queue with proper cooldown periods',
      });
    }
  }
  return findings;
}

// SOL808: Incorrect Vault Share Calculation
export function checkVaultShareCalculation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  
  if (content.includes('mint_shares') || content.includes('burn_shares') || 
      content.includes('share_price')) {
    // Check for first depositor attack vulnerability
    if (!content.includes('minimum_deposit') && !content.includes('dead_shares') &&
        !content.includes('virtual_price')) {
      findings.push({
        id: 'SOL808',
        severity: 'critical',
        title: 'Vault Share Calculation Vulnerable to First Depositor Attack',
        description: 'Vault share calculations without minimum deposit or virtual price are vulnerable to first depositor attacks',
        location: input.path,
        recommendation: 'Implement minimum deposit requirements or virtual share pricing to prevent first depositor manipulation',
      });
    }
  }
  return findings;
}

// SOL809: Missing Borrow Capacity Check
export function checkMissingBorrowCapacity(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  
  if (content.includes('borrow') && (content.includes('lending') || content.includes('loan'))) {
    if (!content.includes('borrow_cap') && !content.includes('utilization_limit') &&
        !content.includes('max_borrow')) {
      findings.push({
        id: 'SOL809',
        severity: 'high',
        title: 'Missing Borrow Capacity Check',
        description: 'Lending protocols should enforce borrow capacity limits to prevent over-leveraging',
        location: input.path,
        recommendation: 'Implement borrow capacity checks and utilization limits',
      });
    }
  }
  return findings;
}

// SOL810: Incorrect Liquidation Incentive Calculation
export function checkLiquidationIncentiveCalc(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  
  if (content.includes('liquidation') && content.includes('incentive')) {
    // Check for dynamic liquidation incentive based on position health
    if (!content.includes('health_factor') && !content.includes('close_factor')) {
      findings.push({
        id: 'SOL810',
        severity: 'high',
        title: 'Incorrect Liquidation Incentive Calculation',
        description: 'Liquidation incentives should scale with position health to ensure proper incentivization',
        location: input.path,
        recommendation: 'Implement dynamic liquidation incentives based on health factor and close factor',
      });
    }
  }
  return findings;
}

// SOL811: Missing Position Health Update
export function checkMissingHealthUpdate(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  
  if ((content.includes('deposit') || content.includes('withdraw') || 
       content.includes('borrow') || content.includes('repay')) &&
      content.includes('position')) {
    if (!content.includes('update_health') && !content.includes('refresh_health') &&
        !content.includes('calculate_health')) {
      findings.push({
        id: 'SOL811',
        severity: 'high',
        title: 'Missing Position Health Update',
        description: 'Position health should be updated after any position-modifying operation',
        location: input.path,
        recommendation: 'Update position health factor after every deposit, withdraw, borrow, or repay operation',
      });
    }
  }
  return findings;
}

// SOL812: Incorrect Interest Rate Model
export function checkInterestRateModel(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  
  if (content.includes('interest_rate') || content.includes('borrow_rate')) {
    // Check for proper interest rate curve implementation
    if (!content.includes('kink') && !content.includes('utilization') &&
        !content.includes('optimal_rate')) {
      findings.push({
        id: 'SOL812',
        severity: 'medium',
        title: 'Missing Interest Rate Model Kink',
        description: 'Interest rate models should implement a kink mechanism to incentivize utilization balance',
        location: input.path,
        recommendation: 'Implement a kinked interest rate curve with optimal utilization target',
      });
    }
  }
  return findings;
}

// SOL813: Missing Debt Token Tracking
export function checkMissingDebtTracking(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  
  if (content.includes('borrow') && content.includes('lending')) {
    if (!content.includes('debt_token') && !content.includes('debt_shares') &&
        !content.includes('total_borrows')) {
      findings.push({
        id: 'SOL813',
        severity: 'high',
        title: 'Missing Debt Token Tracking',
        description: 'Borrowed amounts should be tracked using debt tokens or shares for accurate interest accrual',
        location: input.path,
        recommendation: 'Implement debt token tracking for accurate interest accrual and position management',
      });
    }
  }
  return findings;
}

// SOL814: Incorrect Collateral Factor Application
export function checkCollateralFactorApplication(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  
  if (content.includes('collateral_factor') || content.includes('ltv')) {
    // Check for proper collateral factor bounds
    if (content.match(/collateral_factor\s*[=<>]\s*[01]\.\d+/) && 
        !content.includes('max_collateral_factor')) {
      findings.push({
        id: 'SOL814',
        severity: 'medium',
        title: 'Missing Collateral Factor Bounds',
        description: 'Collateral factors should have maximum bounds to prevent over-leveraging',
        location: input.path,
        recommendation: 'Enforce maximum collateral factor limits (typically <85%)',
      });
    }
  }
  return findings;
}

// SOL815: Missing Oracle Fallback
export function checkMissingOracleFallback(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  
  if (content.includes('oracle') || content.includes('price_feed')) {
    if (!content.includes('fallback') && !content.includes('backup_oracle') &&
        !content.includes('secondary_oracle')) {
      findings.push({
        id: 'SOL815',
        severity: 'high',
        title: 'Missing Oracle Fallback Mechanism',
        description: 'Critical price feeds should have fallback mechanisms to ensure protocol operation during oracle failures',
        location: input.path,
        recommendation: 'Implement fallback oracle or circuit breaker for oracle failure scenarios',
      });
    }
  }
  return findings;
}

// SOL816: Incorrect AMM Invariant Maintenance
export function checkAmmInvariantMaintenance(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  
  if (content.includes('swap') && (content.includes('constant_product') || 
      content.includes('x * y') || content.includes('k ='))) {
    if (!content.includes('check_invariant') && !content.includes('verify_k')) {
      findings.push({
        id: 'SOL816',
        severity: 'critical',
        title: 'Missing AMM Invariant Verification',
        description: 'AMM swaps must verify the constant product invariant is maintained post-swap',
        location: input.path,
        recommendation: 'Add invariant verification after every swap operation',
      });
    }
  }
  return findings;
}

// SOL817: Missing Slippage Protection in Swaps
export function checkSwapSlippageProtection(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  
  if (content.includes('swap') && content.includes('amount_out')) {
    if (!content.includes('min_amount_out') && !content.includes('slippage') &&
        !content.includes('minimum_received')) {
      findings.push({
        id: 'SOL817',
        severity: 'high',
        title: 'Missing Slippage Protection in Swap',
        description: 'Swap operations must enforce minimum output amount to protect against slippage and sandwich attacks',
        location: input.path,
        recommendation: 'Require min_amount_out parameter and validate against actual output',
      });
    }
  }
  return findings;
}

// SOL818: Incorrect Fee-on-Transfer Token Handling
export function checkFeeOnTransferHandling(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  
  if (content.includes('transfer') && content.includes('amount')) {
    // Check for fee-on-transfer token handling
    if (!content.includes('actual_amount') && !content.includes('balance_before') &&
        !content.includes('balance_after')) {
      findings.push({
        id: 'SOL818',
        severity: 'high',
        title: 'Missing Fee-on-Transfer Token Handling',
        description: 'Token transfers should account for potential fee-on-transfer mechanics by checking actual received amounts',
        location: input.path,
        recommendation: 'Calculate actual received amount using balance difference instead of transfer amount',
      });
    }
  }
  return findings;
}

// SOL819: Missing Epoch Boundary Handling
export function checkEpochBoundaryHandling(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  
  if (content.includes('epoch') && (content.includes('stake') || content.includes('reward'))) {
    if (!content.includes('epoch_boundary') && !content.includes('cross_epoch') &&
        !content.includes('epoch_transition')) {
      findings.push({
        id: 'SOL819',
        severity: 'medium',
        title: 'Missing Epoch Boundary Handling',
        description: 'Staking and reward operations should properly handle epoch boundaries to prevent reward manipulation',
        location: input.path,
        recommendation: 'Implement proper epoch boundary handling for staking rewards',
      });
    }
  }
  return findings;
}

// SOL820: Incorrect Voting Power Calculation
export function checkVotingPowerCalculation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  
  if (content.includes('voting_power') || content.includes('vote_weight')) {
    // Check for time-weighted voting power
    if (!content.includes('lock_duration') && !content.includes('time_weight') &&
        !content.includes('ve_token')) {
      findings.push({
        id: 'SOL820',
        severity: 'medium',
        title: 'Missing Time-Weighted Voting Power',
        description: 'Voting power should consider lock duration to incentivize long-term participation',
        location: input.path,
        recommendation: 'Implement vote escrow (ve) style time-weighted voting power',
      });
    }
  }
  return findings;
}

// Export all batch 29 patterns
export const batchedPatterns29 = {
  checkMissingFeeAccrual,
  checkIncorrectRewardRate,
  checkMissingWithdrawalQueue,
  checkVaultShareCalculation,
  checkMissingBorrowCapacity,
  checkLiquidationIncentiveCalc,
  checkMissingHealthUpdate,
  checkInterestRateModel,
  checkMissingDebtTracking,
  checkCollateralFactorApplication,
  checkMissingOracleFallback,
  checkAmmInvariantMaintenance,
  checkSwapSlippageProtection,
  checkFeeOnTransferHandling,
  checkEpochBoundaryHandling,
  checkVotingPowerCalculation,
};
