/**
 * SolGuard Security Patterns SOL697-SOL716 (20 patterns)
 * Based on Real-World Exploits + Sec3 2025 Report Categories
 * Focus: Input Validation & Data Hygiene (25% of all vulns)
 */

import type { Finding } from '../commands/audit.js';
import type { ParsedIdl } from '../parsers/idl.js';
import type { ParsedRust } from '../parsers/rust.js';

interface PatternInput {
  idl?: ParsedIdl;
  rust?: ParsedRust;
  raw?: string;
}

// SOL697: Input Length Overflow Attack
export function checkInputLengthOverflow(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const raw = input.raw || '';
  
  // Look for string/vec handling without length checks
  const stringPatterns = [
    /String::from_utf8|str::from_utf8/i,
    /Vec::with_capacity|vec!\[/i,
    /\.as_bytes\(\)|\.as_slice\(\)/i,
  ];
  
  for (const pattern of stringPatterns) {
    if (pattern.test(raw)) {
      // Check for length validation
      const hasLengthCheck = /\.len\(\)\s*[<>=]|max_len|MAX_LENGTH|length.*check/i.test(raw);
      
      if (!hasLengthCheck) {
        findings.push({
          id: 'SOL697',
          name: 'Input Length Overflow Attack Vector',
          severity: 'high',
          description: 'String or vector operations without length validation can cause buffer overflows or excessive memory allocation.',
          location: 'String/Vec operations without length check',
          recommendation: 'Always validate input length against maximum bounds before processing. Use bounded types where possible.'
        });
        break;
      }
    }
  }
  
  return findings;
}

// SOL698: Numeric Range Validation Missing
export function checkNumericRangeValidation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const raw = input.raw || '';
  
  // Look for numeric parameters
  const numericParams = /fn\s+\w+\s*\([^)]*:\s*(u8|u16|u32|u64|u128|i8|i16|i32|i64|i128)[^)]*\)/gi;
  const matches = raw.match(numericParams);
  
  if (matches && matches.length > 0) {
    // Check for range validation
    const hasRangeCheck = /require!\s*\(.*[<>=]|assert!\s*\(.*[<>=]|\.clamp\(|\.min\(|\.max\(/i.test(raw);
    
    if (!hasRangeCheck) {
      findings.push({
        id: 'SOL698',
        name: 'Missing Numeric Range Validation',
        severity: 'medium',
        description: 'Numeric parameters accepted without range validation can lead to unexpected behavior with extreme values.',
        location: `${matches.length} numeric parameter(s) without range checks`,
        recommendation: 'Validate numeric inputs against business logic bounds. Check for zero, negative (if signed), and maximum value edge cases.'
      });
    }
  }
  
  return findings;
}

// SOL699: Pubkey Format Validation
export function checkPubkeyFormatValidation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const raw = input.raw || '';
  
  // Look for pubkey parsing
  const pubkeyPatterns = [
    /Pubkey::from_str|Pubkey::new|pubkey!/i,
    /try_from_slice.*Pubkey/i,
  ];
  
  for (const pattern of pubkeyPatterns) {
    if (pattern.test(raw)) {
      // Check if there's validation
      const hasValidation = /is_on_curve|validate_pubkey|pubkey.*valid/i.test(raw);
      
      if (!hasValidation) {
        findings.push({
          id: 'SOL699',
          name: 'Pubkey Format Validation Missing',
          severity: 'medium',
          description: 'Pubkeys created from user input without validation may not be valid ed25519 keys or may be the system program address.',
          location: 'Pubkey creation without validation',
          recommendation: 'Validate pubkeys are on the ed25519 curve, not zero address, and not system program address unless intended.'
        });
        break;
      }
    }
  }
  
  return findings;
}

// SOL700: Array Index Bounds Checking
export function checkArrayIndexBounds(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const raw = input.raw || '';
  
  // Look for array indexing
  const indexPattern = /\[\s*\w+\s*\]|\[\s*\d+\s*\]/g;
  const matches = raw.match(indexPattern);
  
  if (matches && matches.length > 5) {
    // Check for bounds checking
    const hasBoundsCheck = /\.get\(|\.get_mut\(|if\s+.*<\s*.*\.len\(\)|\.len\(\)\s*>/i.test(raw);
    
    if (!hasBoundsCheck) {
      findings.push({
        id: 'SOL700',
        name: 'Array Index Bounds Not Checked',
        severity: 'high',
        description: 'Direct array indexing without bounds checking can panic on out-of-bounds access, causing DoS.',
        location: `${matches.length} array index operations detected`,
        recommendation: 'Use .get() or .get_mut() for safe indexing, or explicitly check index < array.len() before access.'
      });
    }
  }
  
  return findings;
}

// SOL701: Timestamp Future/Past Validation
export function checkTimestampFuturePastValidation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const raw = input.raw || '';
  
  // Look for timestamp usage
  const timestampPatterns = [
    /unix_timestamp|timestamp|Clock::get/i,
    /deadline|expiry|start_time|end_time/i,
  ];
  
  for (const pattern of timestampPatterns) {
    if (pattern.test(raw)) {
      // Check for reasonable bounds
      const hasBounds = /max_timestamp|min_timestamp|reasonable.*time|time.*bounds/i.test(raw);
      const hasFutureCheck = />\s*clock|timestamp.*<.*future/i.test(raw);
      
      if (!hasBounds && !hasFutureCheck) {
        findings.push({
          id: 'SOL701',
          name: 'Timestamp Validation Missing',
          severity: 'medium',
          description: 'Timestamps accepted without validation can be set to extreme future or past values, bypassing time-based controls.',
          location: 'Timestamp usage without bounds validation',
          recommendation: 'Validate timestamps are within reasonable bounds. Check that deadlines are not too far in the future and start times are not in the past.'
        });
        break;
      }
    }
  }
  
  return findings;
}

// SOL702: Percentage/Basis Points Overflow
export function checkPercentageOverflow(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const raw = input.raw || '';
  
  // Look for percentage or basis point patterns
  const percentPatterns = [
    /percent|percentage|bps|basis_points/i,
    /fee_rate|interest_rate|commission/i,
    /\*\s*100|\*\s*10000|\/\s*100|\/\s*10000/,
  ];
  
  for (const pattern of percentPatterns) {
    if (pattern.test(raw)) {
      // Check for bounds (0-100% or 0-10000 bps)
      const hasBounds = /<=?\s*100|<=?\s*10000|MAX_BPS|MAX_PERCENT/i.test(raw);
      
      if (!hasBounds) {
        findings.push({
          id: 'SOL702',
          name: 'Percentage/Basis Points Overflow Risk',
          severity: 'high',
          description: 'Percentage or basis point values without maximum bounds can exceed 100%, leading to fund extraction or broken math.',
          location: 'Percentage calculation without bounds check',
          recommendation: 'Validate percentages are <= 100 (or bps <= 10000). Check for zero divisors when calculating percentages.'
        });
        break;
      }
    }
  }
  
  return findings;
}

// SOL703: Enum Variant Exhaustiveness
export function checkEnumVariantExhaustiveness(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const raw = input.raw || '';
  
  // Look for match statements on enums
  const matchPattern = /match\s+\w+\s*\{[\s\S]*?_\s*=>/gi;
  
  if (matchPattern.test(raw)) {
    findings.push({
      id: 'SOL703',
      name: 'Non-Exhaustive Enum Match',
      severity: 'medium',
      description: 'Using wildcard (_) in enum match statements hides unhandled variants. Future enum additions may be silently ignored.',
      location: 'Wildcard match arm detected',
      recommendation: 'Explicitly match all enum variants or use a specific error for unknown variants rather than silently ignoring them.'
    });
  }
  
  return findings;
}

// SOL704: Merkle Proof Validation Depth
export function checkMerkleProofDepth(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const raw = input.raw || '';
  
  // Look for merkle proof patterns
  const merklePatterns = [
    /merkle.*proof|proof.*merkle/i,
    /verify_proof|validate_proof/i,
    /merkle.*root|root.*hash/i,
  ];
  
  for (const pattern of merklePatterns) {
    if (pattern.test(raw)) {
      // Check for depth limits
      const hasDepthLimit = /max_depth|proof.*len.*<|MAX_PROOF_SIZE/i.test(raw);
      
      if (!hasDepthLimit) {
        findings.push({
          id: 'SOL704',
          name: 'Merkle Proof Depth Not Limited',
          severity: 'high',
          description: 'Merkle proofs without depth limits can cause compute exhaustion or be used to manipulate verification.',
          location: 'Merkle proof without depth limit',
          recommendation: 'Limit merkle proof depth to prevent excessive computation. Typical trees have depth <= 32 for 2^32 leaves.'
        });
        break;
      }
    }
  }
  
  return findings;
}

// SOL705: Program ID Validation in CPI
export function checkProgramIdValidationCpi(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const raw = input.raw || '';
  
  // Look for CPI calls
  const cpiPatterns = [
    /invoke\s*\(|invoke_signed\s*\(/i,
    /CpiContext::new|cpi::/i,
    /solana_program::program::invoke/i,
  ];
  
  for (const pattern of cpiPatterns) {
    if (pattern.test(raw)) {
      // Check for program ID validation
      const hasProgramIdCheck = /program.*id.*==|check_program_account|expected_program/i.test(raw);
      
      if (!hasProgramIdCheck) {
        findings.push({
          id: 'SOL705',
          name: 'Missing Program ID Validation in CPI',
          severity: 'critical',
          description: 'CPI calls without validating the target program ID can invoke malicious programs that mimic expected behavior.',
          location: 'CPI without program ID check',
          recommendation: 'Always validate the program ID before CPI. Use hardcoded expected program IDs, not user-provided ones.'
        });
        break;
      }
    }
  }
  
  return findings;
}

// SOL706: Data Version Migration
export function checkDataVersionMigration(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const raw = input.raw || '';
  
  // Look for account data structures
  const dataStructPattern = /#\[account\]|#\[derive.*Account.*\]/i;
  
  if (dataStructPattern.test(raw)) {
    // Check for version field
    const hasVersion = /version:|data_version|schema_version|account_version/i.test(raw);
    
    if (!hasVersion) {
      findings.push({
        id: 'SOL706',
        name: 'Missing Data Version Field',
        severity: 'low',
        description: 'Account data structures without version fields make schema migrations difficult and risky.',
        location: 'Account struct without version field',
        recommendation: 'Include a version field in account data to support future schema migrations without breaking existing accounts.'
      });
    }
  }
  
  return findings;
}

// SOL707: Checksum Validation
export function checkChecksumValidation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const raw = input.raw || '';
  
  // Look for data integrity patterns
  const integrityPatterns = [
    /checksum|hash.*verify|verify.*hash/i,
    /integrity.*check|data.*hash/i,
  ];
  
  // Check if there's critical data without checksums
  if (/critical.*data|sensitive.*data|config.*data/i.test(raw)) {
    let hasChecksum = false;
    for (const pattern of integrityPatterns) {
      if (pattern.test(raw)) {
        hasChecksum = true;
        break;
      }
    }
    
    if (!hasChecksum) {
      findings.push({
        id: 'SOL707',
        name: 'Missing Checksum Validation',
        severity: 'medium',
        description: 'Critical data stored without checksum validation can be corrupted without detection.',
        location: 'Critical data without integrity check',
        recommendation: 'Store checksums or hashes of critical data and verify before use. Use discriminators for account type verification.'
      });
    }
  }
  
  return findings;
}

// SOL708: Race Condition in State Updates
export function checkRaceConditionStateUpdate(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const raw = input.raw || '';
  
  // Look for read-modify-write patterns
  const rmwPatterns = [
    /let.*=.*borrow\(\)[\s\S]*?borrow_mut\(\)/i,
    /account\.data\.borrow\(\)[\s\S]*?borrow_mut\(\)/i,
    /read.*state[\s\S]*?write.*state/i,
  ];
  
  for (const pattern of rmwPatterns) {
    if (pattern.test(raw)) {
      findings.push({
        id: 'SOL708',
        name: 'Potential Race Condition in State Update',
        severity: 'high',
        description: 'Read-modify-write patterns without proper locking can lead to race conditions when multiple transactions execute concurrently.',
        location: 'Read-modify-write pattern detected',
        recommendation: 'Use atomic operations where possible. Consider using exclusive locks or sequence numbers to detect concurrent modifications.'
      });
      break;
    }
  }
  
  return findings;
}

// SOL709: Atomic Update Guarantee
export function checkAtomicUpdateGuarantee(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const raw = input.raw || '';
  
  // Look for multi-account updates
  const multiUpdatePattern = /borrow_mut\(\)[\s\S]*?borrow_mut\(\)/gi;
  const matches = raw.match(multiUpdatePattern);
  
  if (matches && matches.length > 0) {
    // Check for error handling that could leave partial state
    const hasPartialRisk = /\?[\s\S]*?borrow_mut\(\)/i.test(raw);
    
    if (hasPartialRisk) {
      findings.push({
        id: 'SOL709',
        name: 'Non-Atomic Multi-Account Update',
        severity: 'high',
        description: 'Multiple account updates with early returns (?) can leave accounts in inconsistent state if later operations fail.',
        location: 'Multi-account update with early returns',
        recommendation: 'Perform all validation before any state mutations. Use check-effects-interactions pattern. Consider bundling updates atomically.'
      });
    }
  }
  
  return findings;
}

// SOL710: Bit Manipulation Correctness
export function checkBitManipulationCorrectness(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const raw = input.raw || '';
  
  // Look for bitwise operations
  const bitwisePatterns = [
    /<<|>>|&|\\||\^/g,
    /\.rotate_left|\.rotate_right/g,
  ];
  
  let hasBitOps = false;
  for (const pattern of bitwisePatterns) {
    if (pattern.test(raw)) {
      hasBitOps = true;
      break;
    }
  }
  
  if (hasBitOps) {
    // Check for overflow in shifts
    const hasShiftOverflow = /<<\s*\d{2,}|>>\s*\d{2,}/i.test(raw);
    
    if (hasShiftOverflow) {
      findings.push({
        id: 'SOL710',
        name: 'Bit Shift Overflow Risk',
        severity: 'medium',
        description: 'Large bit shifts (>= type width) result in undefined behavior or zero, which may not be intended.',
        location: 'Large bit shift detected',
        recommendation: 'Ensure shift amounts are less than the bit width of the type. Use checked_shl/checked_shr for safe shifts.'
      });
    }
  }
  
  return findings;
}

// SOL711: Compute Unit Exhaustion DoS
export function checkComputeUnitExhaustionDos(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const raw = input.raw || '';
  
  // Look for unbounded iterations
  const unboundedPatterns = [
    /for\s+\w+\s+in\s+\w+\.iter\(\)/gi,
    /while\s+let\s+Some/gi,
    /loop\s*\{/gi,
  ];
  
  for (const pattern of unboundedPatterns) {
    if (pattern.test(raw)) {
      // Check for compute limits
      const hasComputeLimit = /MAX_ITER|max_iterations|compute.*limit|CU_LIMIT/i.test(raw);
      
      if (!hasComputeLimit) {
        findings.push({
          id: 'SOL711',
          name: 'Compute Unit Exhaustion DoS Risk',
          severity: 'high',
          description: 'Unbounded iterations can exhaust compute units, causing transactions to fail. Attackers can craft inputs to maximize compute usage.',
          location: 'Unbounded iteration without compute limit',
          recommendation: 'Limit iterations with explicit bounds. Consider pagination for large data sets. Monitor compute unit usage in tests.'
        });
        break;
      }
    }
  }
  
  return findings;
}

// SOL712: Memory Allocation DoS
export function checkMemoryAllocationDos(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const raw = input.raw || '';
  
  // Look for dynamic allocations
  const allocPatterns = [
    /Vec::with_capacity\s*\(\s*\w+/gi,
    /vec!\[\w+;\s*\w+\]/gi,
    /String::with_capacity/gi,
  ];
  
  for (const pattern of allocPatterns) {
    if (pattern.test(raw)) {
      // Check for size limits
      const hasSizeLimit = /MAX_CAPACITY|max_size|\.min\(|\.clamp\(/i.test(raw);
      
      if (!hasSizeLimit) {
        findings.push({
          id: 'SOL712',
          name: 'Memory Allocation DoS Risk',
          severity: 'high',
          description: 'Dynamic memory allocation with user-controlled size can exhaust heap memory, causing transaction failure.',
          location: 'Dynamic allocation without size limit',
          recommendation: 'Limit allocation sizes with explicit maximums. Use bounded types or validate sizes before allocation.'
        });
        break;
      }
    }
  }
  
  return findings;
}

// SOL713: Stack Overflow via Recursion
export function checkStackOverflowRecursion(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const raw = input.raw || '';
  
  // Look for recursive function calls
  const fnNamePattern = /fn\s+(\w+)/g;
  let match;
  const functionNames: string[] = [];
  
  while ((match = fnNamePattern.exec(raw)) !== null) {
    functionNames.push(match[1]);
  }
  
  for (const fnName of functionNames) {
    // Check if function calls itself
    const selfCallPattern = new RegExp(`fn\\s+${fnName}[\\s\\S]*?${fnName}\\s*\\(`, 'i');
    if (selfCallPattern.test(raw)) {
      // Check for depth limit
      const hasDepthLimit = /max_depth|depth.*limit|depth.*<|recursion.*limit/i.test(raw);
      
      if (!hasDepthLimit) {
        findings.push({
          id: 'SOL713',
          name: 'Stack Overflow via Recursion Risk',
          severity: 'high',
          description: `Recursive function '${fnName}' without depth limit can cause stack overflow.`,
          location: `Recursive function: ${fnName}`,
          recommendation: 'Add recursion depth limits or convert to iterative approach. Solana programs have limited stack space.'
        });
        break;
      }
    }
  }
  
  return findings;
}

// SOL714: Log Spam Attack
export function checkLogSpamAttack(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const raw = input.raw || '';
  
  // Look for logging in loops
  const logInLoopPattern = /for\s+[\s\S]*?\{[\s\S]*?(msg!|sol_log|emit!)/gi;
  
  if (logInLoopPattern.test(raw)) {
    findings.push({
      id: 'SOL714',
      name: 'Log Spam Attack Vector',
      severity: 'low',
      description: 'Logging inside loops can be used to fill transaction logs, potentially hiding important events or consuming compute.',
      location: 'Logging inside loop detected',
      recommendation: 'Limit logging in loops or aggregate messages. Consider logging summaries instead of per-item logs.'
    });
  }
  
  return findings;
}

// SOL715: Queue Griefing Attack
export function checkQueueGriefingAttack(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const raw = input.raw || '';
  
  // Look for queue-like structures
  const queuePatterns = [
    /queue|fifo|lifo|pending.*orders|order.*queue/i,
    /push_back|pop_front|enqueue|dequeue/i,
  ];
  
  for (const pattern of queuePatterns) {
    if (pattern.test(raw)) {
      // Check for anti-griefing measures
      const hasAntiGriefing = /fee.*queue|stake.*queue|rate.*limit|max.*queue.*size/i.test(raw);
      
      if (!hasAntiGriefing) {
        findings.push({
          id: 'SOL715',
          name: 'Queue Griefing Attack Risk',
          severity: 'medium',
          description: 'Queues without economic disincentives can be spammed, blocking legitimate users or delaying critical operations.',
          location: 'Queue without griefing protection',
          recommendation: 'Implement queue fees, stake requirements, or rate limits to prevent griefing. Consider priority queues for time-sensitive operations.'
        });
        break;
      }
    }
  }
  
  return findings;
}

// SOL716: Oracle Liveness Dependency
export function checkOracleLivenessDependency(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const raw = input.raw || '';
  
  // Look for oracle dependencies
  const oraclePatterns = [
    /oracle|price_feed|pyth|switchboard|chainlink/i,
    /get_price|fetch_price|update_price/i,
  ];
  
  for (const pattern of oraclePatterns) {
    if (pattern.test(raw)) {
      // Check for fallback or circuit breaker
      const hasFallback = /fallback|backup.*oracle|circuit.*breaker|pause.*oracle/i.test(raw);
      
      if (!hasFallback) {
        findings.push({
          id: 'SOL716',
          name: 'Oracle Liveness Dependency',
          severity: 'high',
          description: 'Critical operations depending on oracle liveness without fallback can halt if oracle goes down.',
          location: 'Oracle dependency without fallback',
          recommendation: 'Implement fallback oracles, circuit breakers, or pause mechanisms to handle oracle downtime gracefully.'
        });
        break;
      }
    }
  }
  
  return findings;
}

// Export with aliases for naming conflicts
export const checkStackOverflowRecursionV2 = checkStackOverflowRecursion;
export const checkLogSpamAttackV2 = checkLogSpamAttack;
export const checkQueueGriefingAttackV2 = checkQueueGriefingAttack;
export const checkOracleLivenessDependencyV2 = checkOracleLivenessDependency;

export const patterns697to716 = [
  checkInputLengthOverflow,
  checkNumericRangeValidation,
  checkPubkeyFormatValidation,
  checkArrayIndexBounds,
  checkTimestampFuturePastValidation,
  checkPercentageOverflow,
  checkEnumVariantExhaustiveness,
  checkMerkleProofDepth,
  checkProgramIdValidationCpi,
  checkDataVersionMigration,
  checkChecksumValidation,
  checkRaceConditionStateUpdate,
  checkAtomicUpdateGuarantee,
  checkBitManipulationCorrectness,
  checkComputeUnitExhaustionDos,
  checkMemoryAllocationDos,
  checkStackOverflowRecursion,
  checkLogSpamAttack,
  checkQueueGriefingAttack,
  checkOracleLivenessDependency,
];
