/**
 * Batch 14: Advanced Protocol-Specific Patterns (Feb 4-5, 2026)
 * Based on audit reports and protocol-specific vulnerabilities
 * SOL371-SOL400
 */

import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

// Helper to create findings
function createFinding(
  id: string,
  name: string,
  severity: Finding['severity'],
  message: string,
  path: string,
  line?: number,
  recommendation?: string
): Finding {
  return { id, name, severity, message, path, line, recommendation };
}

/**
 * SOL371: Aldrin DEX Order Book Manipulation
 * Checks for order matching vulnerabilities that could allow price manipulation
 */
export function checkAldrinOrderBook(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  const lines = content.split('\n');
  
  // Check for order matching without slippage protection
  if (content.includes('match_orders') && !content.includes('slippage') && !content.includes('min_out')) {
    findings.push(createFinding(
      'SOL371',
      'Aldrin Order Book Pattern',
      'high',
      'Order matching without slippage protection detected - vulnerable to price manipulation',
      input.path,
      lines.findIndex(l => l.includes('match_orders')) + 1,
      'Implement slippage tolerance and minimum output amount checks'
    ));
  }
  
  // Check for partial fill handling
  if (content.includes('fill_order') && !content.includes('partial') && !content.includes('remaining')) {
    findings.push(createFinding(
      'SOL371',
      'Aldrin Order Book Pattern',
      'medium',
      'Order fill without partial fill handling may cause stuck orders',
      input.path,
      undefined,
      'Handle partial fills properly to prevent order book manipulation'
    ));
  }
  
  return findings;
}

/**
 * SOL372: Cross-Chain Message Replay Protection (Swim/Debridge)
 * Checks for proper nonce handling in cross-chain messages
 */
export function checkCrossChainReplay(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  const lines = content.split('\n');
  
  // Check for message processing without nonce
  if ((content.includes('process_message') || content.includes('execute_message')) && 
      !content.includes('nonce') && !content.includes('message_id')) {
    findings.push(createFinding(
      'SOL372',
      'Cross-Chain Replay Pattern',
      'critical',
      'Cross-chain message processing without nonce/message_id - replay attack possible',
      input.path,
      lines.findIndex(l => l.includes('process_message') || l.includes('execute_message')) + 1,
      'Track processed message nonces to prevent replay attacks'
    ));
  }
  
  // Check for chain ID validation
  if (content.includes('source_chain') && !content.includes('validate_chain') && !content.includes('allowed_chains')) {
    findings.push(createFinding(
      'SOL372',
      'Cross-Chain Replay Pattern',
      'high',
      'Source chain validation may be insufficient',
      input.path,
      undefined,
      'Validate source chain against allowlist'
    ));
  }
  
  return findings;
}

/**
 * SOL373: Options Vault Epoch Security (Friktion)
 * Checks for proper epoch transition handling in options vaults
 */
export function checkOptionsVaultEpoch(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  // Check for epoch transition without settlement
  if (content.includes('epoch') && content.includes('transition') && !content.includes('settle')) {
    findings.push(createFinding(
      'SOL373',
      'Options Vault Epoch Pattern',
      'high',
      'Epoch transition without settlement check may cause fund misallocation',
      input.path,
      undefined,
      'Ensure all positions are settled before epoch transition'
    ));
  }
  
  // Check for deposit during auction
  if (content.includes('deposit') && content.includes('auction') && !content.includes('auction_ended')) {
    findings.push(createFinding(
      'SOL373',
      'Options Vault Epoch Pattern',
      'medium',
      'Deposits during active auction may cause pricing issues',
      input.path,
      undefined,
      'Block deposits during active auction periods'
    ));
  }
  
  return findings;
}

/**
 * SOL374: Leverage Vault Controls (Francium)
 * Checks for proper leverage limits and liquidation mechanics
 */
export function checkLeverageVaultControls(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  const lines = content.split('\n');
  
  // Check for uncapped leverage
  if (content.includes('leverage') && !content.includes('max_leverage') && !content.includes('leverage_limit')) {
    findings.push(createFinding(
      'SOL374',
      'Leverage Vault Controls',
      'critical',
      'Leverage operation without maximum limit - excessive risk exposure possible',
      input.path,
      lines.findIndex(l => l.includes('leverage')) + 1,
      'Implement maximum leverage limits (e.g., 3x-5x)'
    ));
  }
  
  // Check for leverage without health factor
  if (content.includes('leverage') && !content.includes('health_factor') && !content.includes('collateral_ratio')) {
    findings.push(createFinding(
      'SOL374',
      'Leverage Vault Controls',
      'high',
      'Leverage operation without health factor monitoring',
      input.path,
      undefined,
      'Monitor health factor to prevent undercollateralized positions'
    ));
  }
  
  return findings;
}

/**
 * SOL375: Synthetic Asset Debt Tracking (Synthetify)
 * Checks for proper debt pool management in synthetic asset protocols
 */
export function checkSyntheticDebtTracking(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  // Check for mint without debt update
  if ((content.includes('mint_synthetic') || content.includes('mint_asset')) && 
      !content.includes('debt') && !content.includes('update_debt')) {
    findings.push(createFinding(
      'SOL375',
      'Synthetic Debt Tracking',
      'critical',
      'Synthetic asset minting without debt tracking - undercollateralization risk',
      input.path,
      undefined,
      'Track total debt when minting synthetic assets'
    ));
  }
  
  // Check for burn without debt reduction
  if ((content.includes('burn_synthetic') || content.includes('burn_asset')) && 
      !content.includes('reduce_debt') && !content.includes('debt')) {
    findings.push(createFinding(
      'SOL375',
      'Synthetic Debt Tracking',
      'high',
      'Synthetic asset burning without debt reduction',
      input.path,
      undefined,
      'Reduce tracked debt when burning synthetic assets'
    ));
  }
  
  return findings;
}

/**
 * SOL376: ZK Proof Verification (Light Protocol)
 * Checks for proper zero-knowledge proof validation
 */
export function checkZkProofVerification(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  const lines = content.split('\n');
  
  // Check for ZK proof without verification
  if ((content.includes('proof') || content.includes('zk_proof') || content.includes('groth16')) && 
      !content.includes('verify_proof') && !content.includes('proof_verify')) {
    findings.push(createFinding(
      'SOL376',
      'ZK Proof Verification',
      'critical',
      'Zero-knowledge proof used without verification call',
      input.path,
      lines.findIndex(l => l.includes('proof')) + 1,
      'Always verify ZK proofs before processing'
    ));
  }
  
  // Check for public inputs validation
  if (content.includes('public_inputs') && !content.includes('validate') && !content.includes('check')) {
    findings.push(createFinding(
      'SOL376',
      'ZK Proof Verification',
      'high',
      'Public inputs may not be properly validated',
      input.path,
      undefined,
      'Validate all public inputs against expected constraints'
    ));
  }
  
  return findings;
}

/**
 * SOL377: CDP Stability Mechanism (Hedge Protocol)
 * Checks for proper collateralized debt position management
 */
export function checkCdpStability(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  // Check for CDP without stability fee
  if ((content.includes('cdp') || content.includes('collateralized_debt')) && 
      !content.includes('stability_fee') && !content.includes('interest')) {
    findings.push(createFinding(
      'SOL377',
      'CDP Stability Mechanism',
      'medium',
      'CDP without stability fee may cause protocol insolvency',
      input.path,
      undefined,
      'Implement stability fees to maintain protocol health'
    ));
  }
  
  // Check for redemption without global collateral ratio check
  if (content.includes('redeem') && !content.includes('global_collateral') && !content.includes('total_collateral')) {
    findings.push(createFinding(
      'SOL377',
      'CDP Stability Mechanism',
      'high',
      'Redemption without global collateral ratio check',
      input.path,
      undefined,
      'Check global collateral ratio before allowing redemptions'
    ));
  }
  
  return findings;
}

/**
 * SOL378: DCA (Dollar Cost Averaging) Security (Mean Finance)
 * Checks for proper DCA execution safety
 */
export function checkDcaSecurity(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  const lines = content.split('\n');
  
  // Check for DCA without time bounds
  if ((content.includes('dca') || content.includes('recurring_swap')) && 
      !content.includes('interval') && !content.includes('frequency')) {
    findings.push(createFinding(
      'SOL378',
      'DCA Security',
      'medium',
      'DCA operation without time interval validation',
      input.path,
      lines.findIndex(l => l.includes('dca') || l.includes('recurring_swap')) + 1,
      'Enforce minimum time intervals between DCA executions'
    ));
  }
  
  // Check for execution without price check
  if (content.includes('execute_dca') && !content.includes('price_deviation') && !content.includes('slippage')) {
    findings.push(createFinding(
      'SOL378',
      'DCA Security',
      'high',
      'DCA execution without price deviation protection',
      input.path,
      undefined,
      'Add price deviation limits to protect against manipulation'
    ));
  }
  
  return findings;
}

/**
 * SOL379: Lending Pool Isolation (Hubble)
 * Checks for proper isolation between lending pools
 */
export function checkLendingPoolIsolation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  // Check for cross-pool operations without isolation
  if (content.includes('pool') && content.includes('borrow') && !content.includes('isolated') && !content.includes('pool_id')) {
    findings.push(createFinding(
      'SOL379',
      'Lending Pool Isolation',
      'high',
      'Cross-pool borrowing may not be properly isolated',
      input.path,
      undefined,
      'Ensure borrowing is isolated per pool or explicitly allowed'
    ));
  }
  
  // Check for shared collateral without explicit handling
  if (content.includes('collateral') && content.includes('pool') && !content.includes('cross_collateral')) {
    findings.push(createFinding(
      'SOL379',
      'Lending Pool Isolation',
      'medium',
      'Collateral sharing across pools may not be explicitly handled',
      input.path,
      undefined,
      'Explicitly define cross-collateral rules if allowed'
    ));
  }
  
  return findings;
}

/**
 * SOL380: CLMM Fee Growth Tracking (Invariant)
 * Checks for proper fee accrual in concentrated liquidity pools
 */
export function checkClmmFeeGrowth(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  // Check for fee collection without growth update
  if (content.includes('collect_fee') && !content.includes('fee_growth') && !content.includes('update_fee')) {
    findings.push(createFinding(
      'SOL380',
      'CLMM Fee Growth Tracking',
      'high',
      'Fee collection without fee growth global update',
      input.path,
      undefined,
      'Update global fee growth before collecting position fees'
    ));
  }
  
  // Check for position fee calculation
  if (content.includes('position') && content.includes('fee') && !content.includes('fee_growth_inside')) {
    findings.push(createFinding(
      'SOL380',
      'CLMM Fee Growth Tracking',
      'medium',
      'Position fee calculation may not account for range-specific growth',
      input.path,
      undefined,
      'Calculate fees using fee_growth_inside for the position range'
    ));
  }
  
  return findings;
}

/**
 * SOL381: Liquidation Incentive Manipulation (Larix)
 * Checks for proper liquidation bonus handling
 */
export function checkLiquidationIncentive(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  const lines = content.split('\n');
  
  // Check for liquidation without bonus cap
  if (content.includes('liquidat') && content.includes('bonus') && !content.includes('max_bonus') && !content.includes('bonus_cap')) {
    findings.push(createFinding(
      'SOL381',
      'Liquidation Incentive',
      'high',
      'Liquidation bonus without maximum cap - exploitation risk',
      input.path,
      lines.findIndex(l => l.includes('liquidat') && l.includes('bonus')) + 1,
      'Cap liquidation bonus to prevent excessive incentives'
    ));
  }
  
  // Check for liquidation eligibility
  if (content.includes('liquidate') && !content.includes('health_factor') && !content.includes('is_liquidatable')) {
    findings.push(createFinding(
      'SOL381',
      'Liquidation Incentive',
      'critical',
      'Liquidation without health factor check',
      input.path,
      undefined,
      'Verify position is actually unhealthy before allowing liquidation'
    ));
  }
  
  return findings;
}

/**
 * SOL382: NFT Staking Duration Validation (Genopets)
 * Checks for proper staking time validation in NFT staking
 */
export function checkNftStakingDuration(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  // Check for unstaking without duration check
  if (content.includes('unstake') && content.includes('nft') && !content.includes('stake_duration') && !content.includes('min_stake')) {
    findings.push(createFinding(
      'SOL382',
      'NFT Staking Duration',
      'medium',
      'NFT unstaking without minimum duration check',
      input.path,
      undefined,
      'Enforce minimum staking duration to prevent gaming'
    ));
  }
  
  // Check for reward calculation without time normalization
  if (content.includes('calculate_reward') && content.includes('stake') && !content.includes('per_second') && !content.includes('per_slot')) {
    findings.push(createFinding(
      'SOL382',
      'NFT Staking Duration',
      'low',
      'Reward calculation may not properly normalize time',
      input.path,
      undefined,
      'Calculate rewards based on precise time elapsed'
    ));
  }
  
  return findings;
}

/**
 * SOL383: AMM Invariant Preservation (GooseFX/Cropper)
 * Checks for proper constant product maintenance
 */
export function checkAmmInvariant(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  const lines = content.split('\n');
  
  // Check for swap without invariant check
  if (content.includes('swap') && !content.includes('invariant') && !content.includes('k =') && !content.includes('constant_product')) {
    findings.push(createFinding(
      'SOL383',
      'AMM Invariant Preservation',
      'critical',
      'Swap operation without invariant preservation check',
      input.path,
      lines.findIndex(l => l.includes('swap')) + 1,
      'Verify k = x * y is maintained after each swap'
    ));
  }
  
  // Check for fee precision
  if (content.includes('fee') && content.includes('swap') && !content.includes('fee_numerator') && !content.includes('basis_points')) {
    findings.push(createFinding(
      'SOL383',
      'AMM Invariant Preservation',
      'medium',
      'Swap fee calculation may have precision issues',
      input.path,
      undefined,
      'Use basis points or numerator/denominator for fee precision'
    ));
  }
  
  return findings;
}

/**
 * SOL384: Vesting Contract Security (Streamflow)
 * Checks for proper vesting schedule enforcement
 */
export function checkVestingContractSecurity(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  // Check for vesting withdrawal without schedule check
  if (content.includes('withdraw') && content.includes('vest') && !content.includes('vested_amount') && !content.includes('unlocked')) {
    findings.push(createFinding(
      'SOL384',
      'Vesting Contract Security',
      'critical',
      'Vesting withdrawal without checking vested amount',
      input.path,
      undefined,
      'Calculate and enforce vested amount based on schedule'
    ));
  }
  
  // Check for cliff period
  if (content.includes('vest') && !content.includes('cliff') && !content.includes('start_time')) {
    findings.push(createFinding(
      'SOL384',
      'Vesting Contract Security',
      'medium',
      'Vesting schedule may not have cliff period validation',
      input.path,
      undefined,
      'Implement cliff period before any tokens can be claimed'
    ));
  }
  
  return findings;
}

/**
 * SOL385: Order Book Depth Protection (Phoenix)
 * Checks for proper order book manipulation protection
 */
export function checkOrderBookDepth(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  // Check for order placement without depth check
  if (content.includes('place_order') && !content.includes('max_orders') && !content.includes('order_limit')) {
    findings.push(createFinding(
      'SOL385',
      'Order Book Depth',
      'medium',
      'Order placement without maximum orders limit per user',
      input.path,
      undefined,
      'Limit orders per user to prevent order book spam'
    ));
  }
  
  // Check for self-trade prevention
  if (content.includes('match') && content.includes('order') && !content.includes('self_trade') && !content.includes('same_user')) {
    findings.push(createFinding(
      'SOL385',
      'Order Book Depth',
      'high',
      'Order matching without self-trade prevention',
      input.path,
      undefined,
      'Prevent users from matching their own orders (wash trading)'
    ));
  }
  
  return findings;
}

/**
 * SOL386: Perpetual Funding Rate Manipulation
 * Checks for proper funding rate calculation and bounds
 */
export function checkPerpFundingRate(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  const lines = content.split('\n');
  
  // Check for funding rate without bounds
  if (content.includes('funding_rate') && !content.includes('max_funding') && !content.includes('funding_cap')) {
    findings.push(createFinding(
      'SOL386',
      'Perp Funding Rate',
      'high',
      'Funding rate without maximum bounds - manipulation risk',
      input.path,
      lines.findIndex(l => l.includes('funding_rate')) + 1,
      'Cap funding rate to prevent extreme manipulation'
    ));
  }
  
  // Check for funding rate based on index price
  if (content.includes('funding') && !content.includes('index_price') && !content.includes('oracle')) {
    findings.push(createFinding(
      'SOL386',
      'Perp Funding Rate',
      'high',
      'Funding calculation may not use reliable index price',
      input.path,
      undefined,
      'Use oracle index price for funding rate calculation'
    ));
  }
  
  return findings;
}

/**
 * SOL387: Multi-Collateral Type Risk (Parrot)
 * Checks for proper handling of multiple collateral types
 */
export function checkMultiCollateralRisk(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  // Check for collateral without type-specific LTV
  if (content.includes('collateral') && content.includes('mint') && !content.includes('ltv') && !content.includes('collateral_factor')) {
    findings.push(createFinding(
      'SOL387',
      'Multi-Collateral Risk',
      'high',
      'Multiple collateral types without type-specific LTV ratios',
      input.path,
      undefined,
      'Define LTV/collateral factor per collateral type'
    ));
  }
  
  // Check for correlated asset risk
  if (content.includes('collateral') && !content.includes('correlation') && !content.includes('diversity')) {
    findings.push(createFinding(
      'SOL387',
      'Multi-Collateral Risk',
      'medium',
      'Multi-collateral without correlation risk assessment',
      input.path,
      undefined,
      'Consider correlation between collateral assets for risk management'
    ));
  }
  
  return findings;
}

/**
 * SOL388: Storage Slot Authorization (Audius Pattern)
 * Checks for proper storage slot access control
 */
export function checkStorageSlotAuth(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  const lines = content.split('\n');
  
  // Check for storage write without authorization
  if ((content.includes('storage') || content.includes('slot')) && 
      content.includes('write') && !content.includes('authorized') && !content.includes('owner')) {
    findings.push(createFinding(
      'SOL388',
      'Storage Slot Authorization',
      'critical',
      'Storage write without proper authorization check',
      input.path,
      lines.findIndex(l => l.includes('write')) + 1,
      'Verify authorization before writing to storage slots'
    ));
  }
  
  // Check for slot initialization
  if (content.includes('slot') && content.includes('init') && !content.includes('is_initialized')) {
    findings.push(createFinding(
      'SOL388',
      'Storage Slot Authorization',
      'high',
      'Storage slot initialization without checking existing state',
      input.path,
      undefined,
      'Check if slot is already initialized before init'
    ));
  }
  
  return findings;
}

/**
 * SOL389: VAA Guardian Quorum (Wormhole Deep)
 * Detailed checks for Wormhole-style guardian signature validation
 */
export function checkVaaGuardianQuorum(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  // Check for guardian threshold
  if (content.includes('guardian') && content.includes('signature') && !content.includes('quorum') && !content.includes('threshold')) {
    findings.push(createFinding(
      'SOL389',
      'VAA Guardian Quorum',
      'critical',
      'Guardian signatures without quorum threshold check',
      input.path,
      undefined,
      'Require 2/3+1 guardian signatures for VAA validation'
    ));
  }
  
  // Check for unique guardian check
  if (content.includes('guardian') && !content.includes('unique') && !content.includes('duplicate')) {
    findings.push(createFinding(
      'SOL389',
      'VAA Guardian Quorum',
      'critical',
      'Guardian signature validation may allow duplicates',
      input.path,
      undefined,
      'Ensure each guardian can only sign once per VAA'
    ));
  }
  
  return findings;
}

/**
 * SOL390: Double-Claim Prevention (Debridge Pattern)
 * Checks for proper claim tracking in bridge protocols
 */
export function checkDoubleClaimPrevention(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  const lines = content.split('\n');
  
  // Check for claim without tracking
  if (content.includes('claim') && !content.includes('claimed') && !content.includes('processed') && !content.includes('used')) {
    findings.push(createFinding(
      'SOL390',
      'Double-Claim Prevention',
      'critical',
      'Claim operation without tracking claimed status - double-claim possible',
      input.path,
      lines.findIndex(l => l.includes('claim')) + 1,
      'Track claimed/processed status to prevent double claims'
    ));
  }
  
  // Check for claim ID uniqueness
  if (content.includes('claim_id') && !content.includes('unique') && !content.includes('exists')) {
    findings.push(createFinding(
      'SOL390',
      'Double-Claim Prevention',
      'high',
      'Claim ID may not be checked for uniqueness',
      input.path,
      undefined,
      'Verify claim ID has not been used before processing'
    ));
  }
  
  return findings;
}

/**
 * SOL391: Multisig Threshold Bounds (Cashmere/Squads)
 * Checks for proper multisig configuration
 */
export function checkMultisigThresholdBounds(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  // Check for threshold bounds
  if (content.includes('threshold') && content.includes('multisig') && !content.includes('min_threshold') && !content.includes('threshold > 0')) {
    findings.push(createFinding(
      'SOL391',
      'Multisig Threshold Bounds',
      'critical',
      'Multisig threshold without minimum validation - could be set to 0',
      input.path,
      undefined,
      'Ensure threshold >= 1 and <= total signers'
    ));
  }
  
  // Check for threshold vs signers
  if (content.includes('threshold') && !content.includes('num_signers') && !content.includes('owners.len()')) {
    findings.push(createFinding(
      'SOL391',
      'Multisig Threshold Bounds',
      'high',
      'Threshold not validated against number of signers',
      input.path,
      undefined,
      'Validate threshold <= number of signers'
    ));
  }
  
  return findings;
}

/**
 * SOL392: Stake Pool Deposit/Withdraw Security (Marinade)
 * Checks for proper stake pool mechanics
 */
export function checkStakePoolMechanics(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  // Check for stake without validator selection
  if (content.includes('stake') && content.includes('deposit') && !content.includes('validator') && !content.includes('delegation')) {
    findings.push(createFinding(
      'SOL392',
      'Stake Pool Mechanics',
      'medium',
      'Stake deposit without validator selection logic',
      input.path,
      undefined,
      'Implement fair validator selection for stake distribution'
    ));
  }
  
  // Check for withdraw fee calculation
  if (content.includes('withdraw') && content.includes('stake') && !content.includes('fee') && !content.includes('epoch')) {
    findings.push(createFinding(
      'SOL392',
      'Stake Pool Mechanics',
      'medium',
      'Stake withdrawal without fee or epoch consideration',
      input.path,
      undefined,
      'Consider stake account epoch for withdrawal timing'
    ));
  }
  
  return findings;
}

/**
 * SOL393: Tick Array Boundary Security (Whirlpool)
 * Checks for proper tick array handling in CLMM
 */
export function checkTickArrayBoundary(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  // Check for tick array crossing without validation
  if (content.includes('tick_array') && content.includes('cross') && !content.includes('boundary') && !content.includes('adjacent')) {
    findings.push(createFinding(
      'SOL393',
      'Tick Array Boundary',
      'high',
      'Tick array crossing without boundary validation',
      input.path,
      undefined,
      'Validate tick array boundaries when crossing arrays'
    ));
  }
  
  // Check for tick initialization
  if (content.includes('tick') && content.includes('init') && !content.includes('spacing') && !content.includes('valid_tick')) {
    findings.push(createFinding(
      'SOL393',
      'Tick Array Boundary',
      'medium',
      'Tick initialization without spacing validation',
      input.path,
      undefined,
      'Ensure ticks align with pool tick spacing'
    ));
  }
  
  return findings;
}

/**
 * SOL394: Pyth Confidence Interval Check
 * Checks for proper Pyth oracle confidence handling
 */
export function checkPythConfidenceInterval(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  const lines = content.split('\n');
  
  // Check for Pyth price without confidence
  if ((content.includes('pyth') || content.includes('Price {')) && 
      content.includes('price') && !content.includes('conf') && !content.includes('confidence')) {
    findings.push(createFinding(
      'SOL394',
      'Pyth Confidence Check',
      'high',
      'Pyth oracle price used without confidence interval check',
      input.path,
      lines.findIndex(l => l.includes('price')) + 1,
      'Check confidence interval relative to price (e.g., conf/price < 5%)'
    ));
  }
  
  // Check for price age
  if (content.includes('pyth') && !content.includes('publish_time') && !content.includes('price_age')) {
    findings.push(createFinding(
      'SOL394',
      'Pyth Confidence Check',
      'high',
      'Pyth price may be stale - no age check',
      input.path,
      undefined,
      'Verify price publish_time is recent'
    ));
  }
  
  return findings;
}

/**
 * SOL395: Oracle Guardrails (Drift Pattern)
 * Comprehensive oracle safety checks
 */
export function checkOracleGuardrails(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  // Check for oracle deviation limits
  if (content.includes('oracle') && content.includes('price') && !content.includes('max_deviation') && !content.includes('price_band')) {
    findings.push(createFinding(
      'SOL395',
      'Oracle Guardrails',
      'high',
      'Oracle price used without deviation guardrails',
      input.path,
      undefined,
      'Implement price deviation limits from TWAP or reference price'
    ));
  }
  
  // Check for multiple oracle sources
  if (content.includes('oracle') && !content.includes('backup') && !content.includes('fallback') && !content.includes('secondary')) {
    findings.push(createFinding(
      'SOL395',
      'Oracle Guardrails',
      'medium',
      'Single oracle source without fallback',
      input.path,
      undefined,
      'Consider backup oracle sources for resilience'
    ));
  }
  
  return findings;
}
