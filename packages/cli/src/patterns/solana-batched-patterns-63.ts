/**
 * SolShield Pattern Batch 63: 2025-2026 Latest Exploits & Advanced Security
 * 
 * Based on:
 * - Helius "Solana Hacks, Bugs, and Exploits: A Complete History" (Jun 2025)
 * - Sec3 "Solana Security Ecosystem Review 2025" - 163 audits, 1,669 vulnerabilities
 * - NoOnes Platform exploit (Feb 2025)
 * - Loopscale exploit (Apr 2025) - $5.8M RateX PT token flaw
 * - DEXX exploit (Nov 2024) - $30M private key leak
 * - Solareum exploit (Mar 2024) - NK dev insider threat
 * 
 * Patterns: SOL2701-SOL2800
 */

import type { Finding, PatternInput } from './index.js';

// Loopscale-Style RateX Token Valuation Patterns (SOL2701-SOL2720)
const RATEX_VALUATION_PATTERNS = [
  {
    id: 'SOL2701',
    name: 'PT Token Valuation Without Maturity Check',
    severity: 'critical' as const,
    pattern: /pt[\s_]?token[\s\S]{0,100}(value|price|worth)(?![\s\S]{0,100}maturity)/i,
    description: 'Principal Token (PT) valuation without maturity consideration. Loopscale lost $5.8M from this.',
    recommendation: 'PT tokens must be valued based on time-to-maturity and underlying redemption value.'
  },
  {
    id: 'SOL2702',
    name: 'Yield Token Redemption Without Rate Validation',
    severity: 'high' as const,
    pattern: /yt[\s_]?token[\s\S]{0,100}redeem(?![\s\S]{0,100}(rate|yield|check))/i,
    description: 'Yield Token redemption without validating underlying yield rate.',
    recommendation: 'Validate yield rate from trusted oracle before allowing redemptions.'
  },
  {
    id: 'SOL2703',
    name: 'Fixed Rate Protocol Manipulation',
    severity: 'critical' as const,
    pattern: /fixed[\s_]?rate[\s\S]{0,50}(set|update|change)(?![\s\S]{0,100}(authority|admin|owner))/i,
    description: 'Fixed rate can be changed without authority check.',
    recommendation: 'Only authorized accounts should modify fixed rates with timelock.'
  },
  {
    id: 'SOL2704',
    name: 'Tokenized Asset Circular Collateral',
    severity: 'critical' as const,
    pattern: /(deposit|collateral)[\s\S]{0,50}(pt|yt|synthetic)[\s\S]{0,100}(borrow|mint)/i,
    description: 'Circular collateral: synthetic/tokenized asset used as collateral for itself.',
    recommendation: 'Prevent using derivative tokens as collateral for their underlying.'
  },
  {
    id: 'SOL2705',
    name: 'Principal Token Redemption Before Maturity',
    severity: 'high' as const,
    pattern: /pt[\s_]?(token)?[\s\S]{0,50}redeem(?![\s\S]{0,100}(maturity|timestamp|clock))/i,
    description: 'PT redemption without maturity date check allows early redemption exploit.',
    recommendation: 'Check Clock::get() timestamp against maturity before allowing redemption.'
  },
  {
    id: 'SOL2706',
    name: 'Yield Stripping Without Balance Verification',
    severity: 'high' as const,
    pattern: /strip[\s_]?yield[\s\S]{0,100}transfer(?![\s\S]{0,100}balance)/i,
    description: 'Yield stripping without verifying sufficient underlying balance.',
    recommendation: 'Verify underlying token balance before stripping yield.'
  },
  {
    id: 'SOL2707',
    name: 'Tokenized Position Value Cache Stale',
    severity: 'high' as const,
    pattern: /position[\s_]?value[\s\S]{0,30}cache(?![\s\S]{0,100}(refresh|update|recalculate))/i,
    description: 'Cached position values can become stale and exploitable.',
    recommendation: 'Recalculate position values on each use or use staleness check.'
  },
  {
    id: 'SOL2708',
    name: 'Synthetic Token Backing Ratio Unchecked',
    severity: 'critical' as const,
    pattern: /synthetic[\s\S]{0,50}(mint|create)(?![\s\S]{0,100}(backing|collateral|ratio))/i,
    description: 'Synthetic token minting without verifying backing ratio.',
    recommendation: 'Enforce minimum backing ratio before minting synthetic tokens.'
  },
];

// DEXX-Style Private Key Exposure Patterns (SOL2721-SOL2740)
const DEXX_KEY_EXPOSURE_PATTERNS = [
  {
    id: 'SOL2721',
    name: 'Private Key in Request Body',
    severity: 'critical' as const,
    pattern: /(post|put|send)[\s\S]{0,100}(private[\s_]?key|secret[\s_]?key|keypair)/i,
    description: 'Private key transmitted over network. DEXX lost $30M from key leakage.',
    recommendation: 'Never transmit private keys. Use client-side signing only.'
  },
  {
    id: 'SOL2722',
    name: 'Centralized Key Storage',
    severity: 'critical' as const,
    pattern: /(database|db|storage)[\s\S]{0,50}(private[\s_]?key|secret|seed)/i,
    description: 'Private keys stored in centralized database - single point of failure.',
    recommendation: 'Use HSM, MPC, or client-side key management. Never store user keys.'
  },
  {
    id: 'SOL2723',
    name: 'Seed Phrase in Logs',
    severity: 'critical' as const,
    pattern: /(log|print|debug|console)[\s\S]{0,50}(seed|mnemonic|phrase)/i,
    description: 'Seed phrases logged. Slope Wallet exploit exposed $8M through logging.',
    recommendation: 'Never log any key material. Implement secure logging policies.'
  },
  {
    id: 'SOL2724',
    name: 'Key Material in Error Messages',
    severity: 'critical' as const,
    pattern: /(error|err|exception)[\s\S]{0,50}(key|secret|seed|private)/i,
    description: 'Key material exposed in error messages.',
    recommendation: 'Sanitize error messages to exclude any sensitive data.'
  },
  {
    id: 'SOL2725',
    name: 'Unencrypted Key in Memory',
    severity: 'high' as const,
    pattern: /String[\s\S]{0,20}(private_key|secret_key|seed_phrase)/i,
    description: 'Keys stored as regular strings remain in memory longer.',
    recommendation: 'Use secure memory types like Zeroizing<> that clear on drop.'
  },
  {
    id: 'SOL2726',
    name: 'Trading Bot Custodial Keys',
    severity: 'critical' as const,
    pattern: /bot[\s\S]{0,50}(custody|hold|store)[\s\S]{0,50}key/i,
    description: 'Trading bot holds user keys. Solareum lost $1.4M from insider theft.',
    recommendation: 'Use non-custodial design with delegated authority instead.'
  },
  {
    id: 'SOL2727',
    name: 'Third-Party Service Key Access',
    severity: 'high' as const,
    pattern: /(mongo|redis|postgres|external)[\s\S]{0,50}(key|secret|credential)/i,
    description: 'Keys accessible to third-party services. Thunder Terminal lost $240K via MongoDB.',
    recommendation: 'Isolate key management from all third-party integrations.'
  },
];

// NoOnes & Insider Threat Patterns (SOL2741-SOL2760)
const INSIDER_THREAT_PATTERNS = [
  {
    id: 'SOL2741',
    name: 'Single Admin Key No Multisig',
    severity: 'critical' as const,
    pattern: /admin[\s\S]{0,30}(authority|key|signer)(?![\s\S]{0,100}multisig)/i,
    description: 'Single admin key without multisig. Insider can drain protocol.',
    recommendation: 'Require multisig (e.g., 3/5) for all admin operations.'
  },
  {
    id: 'SOL2742',
    name: 'Employee Access to Production Keys',
    severity: 'critical' as const,
    pattern: /(employee|dev|team)[\s\S]{0,50}(access|key|authority)/i,
    description: 'Employee access to production signing keys. Pump.fun lost $1.9M.',
    recommendation: 'Use hardware wallets and segregated duties for production keys.'
  },
  {
    id: 'SOL2743',
    name: 'DAO 1-of-N Multisig',
    severity: 'critical' as const,
    pattern: /multisig[\s\S]{0,30}(1[\s_]?of|1\/)/i,
    description: '1-of-N multisig provides no security. Saga DAO lost $60K.',
    recommendation: 'Require at least 2/3 or 3/5 threshold for treasury multisig.'
  },
  {
    id: 'SOL2744',
    name: 'Withdrawal Authority No Timelock',
    severity: 'high' as const,
    pattern: /withdraw[\s\S]{0,50}authority(?![\s\S]{0,100}timelock)/i,
    description: 'Withdrawal authority without timelock. Instant rug possible.',
    recommendation: 'Add 24-48 hour timelock on large withdrawals.'
  },
  {
    id: 'SOL2745',
    name: 'Treasury Access No Event Emission',
    severity: 'medium' as const,
    pattern: /treasury[\s\S]{0,50}(transfer|withdraw)(?![\s\S]{0,100}(emit|event|log))/i,
    description: 'Treasury operations without event emission. Hard to detect theft.',
    recommendation: 'Emit events for all treasury movements for monitoring.'
  },
  {
    id: 'SOL2746',
    name: 'Team Token Unlock No Vesting',
    severity: 'high' as const,
    pattern: /team[\s_]?token[\s\S]{0,50}(unlock|release)(?![\s\S]{0,100}vest)/i,
    description: 'Team tokens unlockable without vesting schedule.',
    recommendation: 'Implement proper vesting with cliff and linear release.'
  },
  {
    id: 'SOL2747',
    name: 'Upgrade Authority Single Key',
    severity: 'critical' as const,
    pattern: /upgrade[\s_]?authority[\s\S]{0,30}(pubkey|key)(?![\s\S]{0,100}multisig)/i,
    description: 'Program upgrade controlled by single key. Full protocol takeover risk.',
    recommendation: 'Transfer upgrade authority to multisig or make immutable.'
  },
];

// Governance Attack Patterns - Synthetify & Audius Style (SOL2761-SOL2780)
const GOVERNANCE_ATTACK_PATTERNS = [
  {
    id: 'SOL2761',
    name: 'Governance Proposal No Delay',
    severity: 'critical' as const,
    pattern: /proposal[\s\S]{0,50}execute(?![\s\S]{0,100}(delay|timelock|wait))/i,
    description: 'Proposals execute immediately. Audius lost $6.1M to instant execution.',
    recommendation: 'Add 24-72 hour delay between approval and execution.'
  },
  {
    id: 'SOL2762',
    name: 'Low Quorum for Critical Actions',
    severity: 'high' as const,
    pattern: /quorum[\s\S]{0,20}(1|5|10)[\s_]?%/i,
    description: 'Very low quorum allows attackers to pass proposals unnoticed.',
    recommendation: 'Set quorum to at least 10-20% of circulating supply.'
  },
  {
    id: 'SOL2763',
    name: 'Proposal Voting During Creation',
    severity: 'high' as const,
    pattern: /proposal[\s\S]{0,30}(create|new)[\s\S]{0,50}vote/i,
    description: 'Same transaction creates and votes on proposal. No community review.',
    recommendation: 'Separate proposal creation and voting period by at least 24 hours.'
  },
  {
    id: 'SOL2764',
    name: 'Token-Weighted Voting Flash Loan Vulnerable',
    severity: 'critical' as const,
    pattern: /voting[\s_]?power[\s\S]{0,30}(balance|amount)(?![\s\S]{0,100}snapshot)/i,
    description: 'Voting power from current balance. Attackable via flash loan.',
    recommendation: 'Use snapshot-based voting power from past block.'
  },
  {
    id: 'SOL2765',
    name: 'Inactive DAO No Notification',
    severity: 'high' as const,
    pattern: /dao[\s\S]{0,50}proposal(?![\s\S]{0,100}(notify|alert|event))/i,
    description: 'No notifications for proposals in inactive DAO. Synthetify lost $230K.',
    recommendation: 'Implement proposal alerts and require active monitoring.'
  },
  {
    id: 'SOL2766',
    name: 'Governance Bypass via Direct Call',
    severity: 'critical' as const,
    pattern: /(admin|treasury)[\s\S]{0,30}(pub|public)[\s\S]{0,30}fn(?![\s\S]{0,100}governance)/i,
    description: 'Critical functions callable directly, bypassing governance.',
    recommendation: 'Gate all admin functions through governance proposal execution.'
  },
  {
    id: 'SOL2767',
    name: 'No Veto Council',
    severity: 'medium' as const,
    pattern: /governance[\s\S]{0,100}(?!veto|guardian|emergency)/i,
    description: 'No veto mechanism for malicious proposals.',
    recommendation: 'Add guardian/veto council for emergency proposal rejection.'
  },
  {
    id: 'SOL2768',
    name: 'Proposal Data Not Validated',
    severity: 'critical' as const,
    pattern: /proposal[\s\S]{0,30}data[\s\S]{0,50}execute(?![\s\S]{0,100}(validate|verify|check))/i,
    description: 'Proposal instruction data executed without validation.',
    recommendation: 'Validate proposal instructions against allowed operations.'
  },
];

// Advanced DeFi Economic Patterns (SOL2781-SOL2800)
const ADVANCED_DEFI_PATTERNS = [
  {
    id: 'SOL2781',
    name: 'Bonding Curve Flash Loan Exploitable',
    severity: 'critical' as const,
    pattern: /bonding[\s_]?curve[\s\S]{0,100}(buy|sell|swap)(?![\s\S]{0,100}(block|lock|delay))/i,
    description: 'Bonding curve exploitable via flash loan. Nirvana lost $3.5M.',
    recommendation: 'Add per-block limits or time delays on large curve operations.'
  },
  {
    id: 'SOL2782',
    name: 'AMM Constant Product Unprotected',
    severity: 'high' as const,
    pattern: /x[\s]*\*[\s]*y[\s]*=[\s]*k(?![\s\S]{0,100}(slippage|check|guard))/i,
    description: 'Constant product formula without slippage protection.',
    recommendation: 'Enforce minimum output amounts for all swaps.'
  },
  {
    id: 'SOL2783',
    name: 'Liquidity Mining Infinite Emission',
    severity: 'high' as const,
    pattern: /emission[\s_]?(rate|per)(?![\s\S]{0,100}(cap|max|limit|halving))/i,
    description: 'Uncapped token emissions dilute value indefinitely.',
    recommendation: 'Implement emission caps, halvings, or decay schedules.'
  },
  {
    id: 'SOL2784',
    name: 'Staking Rewards Calculator Overflow',
    severity: 'high' as const,
    pattern: /reward[\s\S]{0,30}(accumulated|total)[\s\S]{0,30}\*/i,
    description: 'Reward calculation multiplication without overflow check.',
    recommendation: 'Use checked_mul for all reward calculations.'
  },
  {
    id: 'SOL2785',
    name: 'Bridge Guardian Set Too Small',
    severity: 'critical' as const,
    pattern: /guardian[\s\S]{0,30}(count|len|size)[\s\S]{0,10}(3|4|5)(?![\s_]?of)/i,
    description: 'Small guardian set easier to compromise. Wormhole had 19.',
    recommendation: 'Use at least 13 guardians with 2/3 threshold.'
  },
  {
    id: 'SOL2786',
    name: 'Cross-Chain Message Replay',
    severity: 'critical' as const,
    pattern: /message[\s\S]{0,30}(verify|validate)(?![\s\S]{0,100}(nonce|sequence|used))/i,
    description: 'Cross-chain messages without replay protection.',
    recommendation: 'Track processed message nonces to prevent replay.'
  },
  {
    id: 'SOL2787',
    name: 'Liquidation No Dust Protection',
    severity: 'medium' as const,
    pattern: /liquidat[\s\S]{0,50}(amount|value)(?![\s\S]{0,100}(min|dust|threshold))/i,
    description: 'Dust amounts can be liquidated profitably via gas subsidies.',
    recommendation: 'Set minimum liquidation amount above dust threshold.'
  },
  {
    id: 'SOL2788',
    name: 'Vault Deposit No Slippage',
    severity: 'high' as const,
    pattern: /vault[\s\S]{0,30}deposit(?![\s\S]{0,100}(min|slippage|expected))/i,
    description: 'Vault deposits without minimum shares protection.',
    recommendation: 'Require minimum shares parameter for sandwich protection.'
  },
  {
    id: 'SOL2789',
    name: 'Oracle TWAP Period Too Short',
    severity: 'high' as const,
    pattern: /twap[\s\S]{0,30}(period|window)[\s\S]{0,10}(1|5|10)[\s_]?(min|minute)/i,
    description: 'TWAP period under 15 min is manipulatable.',
    recommendation: 'Use TWAP period of at least 15-30 minutes.'
  },
  {
    id: 'SOL2790',
    name: 'LP Token Calculation Before Fee',
    severity: 'high' as const,
    pattern: /lp[\s_]?(token|share)[\s\S]{0,50}(amount|calc)[\s\S]{0,50}fee/i,
    description: 'LP shares calculated before fee deduction. Fee avoidance possible.',
    recommendation: 'Calculate LP shares after deducting all fees.'
  },
  {
    id: 'SOL2791',
    name: 'Yield Aggregator Strategy No Validation',
    severity: 'critical' as const,
    pattern: /strategy[\s\S]{0,30}(add|register)(?![\s\S]{0,100}(validate|whitelist|verify))/i,
    description: 'Strategies can be added without validation. Tulip-style risk.',
    recommendation: 'Whitelist and audit all strategies before deployment.'
  },
  {
    id: 'SOL2792',
    name: 'Perpetual Funding Rate Manipulation',
    severity: 'high' as const,
    pattern: /funding[\s_]?rate[\s\S]{0,50}(calc|compute)(?![\s\S]{0,100}(cap|clamp|limit))/i,
    description: 'Uncapped funding rates can drain positions.',
    recommendation: 'Cap funding rates at reasonable bounds (e.g., ±0.1% per hour).'
  },
  {
    id: 'SOL2793',
    name: 'Insurance Fund Drain No Limit',
    severity: 'high' as const,
    pattern: /insurance[\s_]?fund[\s\S]{0,50}(use|withdraw|drain)(?![\s\S]{0,100}(limit|cap|max))/i,
    description: 'Insurance fund can be fully drained in single event.',
    recommendation: 'Limit insurance fund usage per event to preserve solvency.'
  },
  {
    id: 'SOL2794',
    name: 'Leverage Without Margin Call',
    severity: 'critical' as const,
    pattern: /leverage[\s\S]{0,50}(position|trade)(?![\s\S]{0,100}(margin|liquidat|health))/i,
    description: 'Leveraged positions without margin call mechanism.',
    recommendation: 'Implement continuous margin monitoring and liquidation.'
  },
  {
    id: 'SOL2795',
    name: 'Stablecoin Depeg No Emergency',
    severity: 'critical' as const,
    pattern: /stable[\s_]?coin[\s\S]{0,100}(?!(emergency|depeg|circuit|pause))/i,
    description: 'No emergency mechanism for depeg scenario. Cashio collapsed.',
    recommendation: 'Implement circuit breakers and emergency redemption at par.'
  },
];

export function checkBatch63Patterns(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (!input.rust?.content) {
    return findings;
  }

  const content = input.rust.content;
  const lines = content.split('\n');

  const allPatterns = [
    ...RATEX_VALUATION_PATTERNS,
    ...DEXX_KEY_EXPOSURE_PATTERNS,
    ...INSIDER_THREAT_PATTERNS,
    ...GOVERNANCE_ATTACK_PATTERNS,
    ...ADVANCED_DEFI_PATTERNS,
  ];

  for (const pattern of allPatterns) {
    const match = pattern.pattern.exec(content);
    if (match) {
      const lineNumber = content.substring(0, match.index).split('\n').length;
      findings.push({
        id: pattern.id,
        title: pattern.name,
        severity: pattern.severity,
        description: pattern.description,
        location: { file: input.path, line: lineNumber },
        recommendation: pattern.recommendation,
      });
    }
  }

  // Context-aware checks
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const context = lines.slice(Math.max(0, i - 10), Math.min(lines.length, i + 10)).join('\n');

    // SOL2796: Timestamp-Based Randomness
    if ((line.includes('Clock::get') || line.includes('unix_timestamp')) && 
        (context.includes('random') || context.includes('lottery') || context.includes('raffle'))) {
      findings.push({
        id: 'SOL2796',
        title: 'Timestamp Used for Randomness',
        severity: 'critical',
        description: 'Timestamps are predictable and manipulatable. Not suitable for randomness.',
        location: { file: input.path, line: i + 1 },
        recommendation: 'Use VRF (Switchboard/Chainlink) for on-chain randomness.',
      });
    }

    // SOL2797: Unchecked Division By Zero
    if (line.includes('/') && !line.includes('//') && !line.includes('/*') &&
        !context.includes('checked_div') && !context.includes('!= 0') && 
        !context.includes('> 0') && context.includes('fn ')) {
      if (line.match(/\w+\s*\/\s*\w+/)) {
        findings.push({
          id: 'SOL2797',
          title: 'Potential Division by Zero',
          severity: 'high',
          description: 'Division without checking divisor is non-zero.',
          location: { file: input.path, line: i + 1 },
          recommendation: 'Use checked_div or verify divisor > 0 before division.',
        });
      }
    }

    // SOL2798: Large Number Literal Without Underscore
    if (line.match(/\b\d{7,}\b/) && !line.includes('_')) {
      findings.push({
        id: 'SOL2798',
        title: 'Large Number Without Underscore Separator',
        severity: 'low',
        description: 'Large numbers without underscores are error-prone (e.g., 1000000 vs 100000).',
        location: { file: input.path, line: i + 1 },
        recommendation: 'Use underscores: 1_000_000 instead of 1000000.',
      });
    }

    // SOL2799: External Call in Loop
    if ((line.includes('invoke') || line.includes('invoke_signed') || line.includes('CpiContext')) &&
        context.includes('for ') && context.includes('in ')) {
      findings.push({
        id: 'SOL2799',
        title: 'CPI Call Inside Loop',
        severity: 'high',
        description: 'External program calls in loops are expensive and may hit compute limits.',
        location: { file: input.path, line: i + 1 },
        recommendation: 'Batch operations or limit loop iterations with compute budget.',
      });
    }

    // SOL2800: Account Close Without Lamport Check  
    if ((line.includes('close') || line.includes('Close')) && 
        line.includes('account') && !context.includes('lamport')) {
      findings.push({
        id: 'SOL2800',
        title: 'Account Close Without Final Lamport Check',
        severity: 'medium',
        description: 'Closing accounts should verify final lamport balance transfer.',
        location: { file: input.path, line: i + 1 },
        recommendation: 'Verify lamports transferred to destination equals account balance.',
      });
    }
  }

  return findings;
}
