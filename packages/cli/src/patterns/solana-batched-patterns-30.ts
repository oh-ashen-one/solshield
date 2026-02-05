/**
 * Batch 30: Input Validation & Data Hygiene Patterns
 * Based on Sec3 2025 Report - Input Validation (25% of severe findings)
 * Added: Feb 5, 2026 6:00 AM CST
 */

import type { PatternInput } from './index.js';
import type { Finding } from '../commands/audit.js';

// SOL821: Missing Account Data Size Validation
export function checkAccountDataSizeValidation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  
  if (content.includes('AccountInfo') || content.includes('try_borrow_data')) {
    if (!content.includes('data.len()') && !content.includes('data_len') &&
        !content.includes('MIN_SIZE')) {
      findings.push({
        id: 'SOL821',
        severity: 'high',
        title: 'Missing Account Data Size Validation',
        description: 'Account data size should be validated before deserialization to prevent buffer overflows',
        location: input.path,
        recommendation: 'Validate account data length matches expected size before processing',
      });
    }
  }
  return findings;
}

// SOL822: Unsafe String Input Handling
export function checkUnsafeStringInput(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  
  if (content.includes('String') && (content.includes('instruction_data') || 
      content.includes('from_utf8'))) {
    if (!content.includes('max_len') && !content.includes('truncate') &&
        !content.includes('MAX_STRING_LENGTH')) {
      findings.push({
        id: 'SOL822',
        severity: 'medium',
        title: 'Unsafe String Input Handling',
        description: 'String inputs should have maximum length limits to prevent DoS and memory exhaustion',
        location: input.path,
        recommendation: 'Enforce maximum string length limits on all string inputs',
      });
    }
  }
  return findings;
}

// SOL823: Missing Pubkey Format Validation
export function checkPubkeyFormatValidation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  
  // Check for pubkey handling without proper validation
  if (content.includes('Pubkey::new') || content.includes('Pubkey::from')) {
    if (!content.includes('try_from') && !content.includes('is_on_curve')) {
      findings.push({
        id: 'SOL823',
        severity: 'medium',
        title: 'Missing Pubkey Format Validation',
        description: 'Pubkeys should be validated for proper format before use',
        location: input.path,
        recommendation: 'Use Pubkey::try_from and validate pubkey format',
      });
    }
  }
  return findings;
}

// SOL824: Unchecked Array Bounds Access
export function checkUncheckedArrayBounds(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  
  // Check for direct array indexing without bounds checking
  if (content.match(/\[\s*\d+\s*\]/) || content.match(/\[\s*index\s*\]/)) {
    if (!content.includes('.get(') && !content.includes('.get_mut(') &&
        !content.includes('if index <')) {
      findings.push({
        id: 'SOL824',
        severity: 'high',
        title: 'Unchecked Array Bounds Access',
        description: 'Array access should use .get() or bounds checking to prevent panics',
        location: input.path,
        recommendation: 'Use .get() for safe array access or validate index bounds before access',
      });
    }
  }
  return findings;
}

// SOL825: Missing Timestamp Range Validation
export function checkTimestampRangeValidation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  
  if (content.includes('timestamp') || content.includes('unix_timestamp')) {
    // Check for timestamp range validation
    if (!content.includes('MIN_TIMESTAMP') && !content.includes('MAX_TIMESTAMP') &&
        !content.includes('is_valid_timestamp')) {
      findings.push({
        id: 'SOL825',
        severity: 'medium',
        title: 'Missing Timestamp Range Validation',
        description: 'Timestamps should be validated to be within reasonable ranges',
        location: input.path,
        recommendation: 'Validate timestamps are within expected min/max bounds',
      });
    }
  }
  return findings;
}

// SOL826: Missing Percentage/BPS Validation
export function checkPercentageValidation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  
  if (content.includes('percentage') || content.includes('bps') || 
      content.includes('basis_points')) {
    if (!content.includes('<= 100') && !content.includes('<= 10000') &&
        !content.includes('MAX_BPS')) {
      findings.push({
        id: 'SOL826',
        severity: 'high',
        title: 'Missing Percentage/BPS Bounds Validation',
        description: 'Percentage and basis points values must be validated to be within valid ranges (0-100% or 0-10000 bps)',
        location: input.path,
        recommendation: 'Enforce maximum bounds on percentage/BPS inputs',
      });
    }
  }
  return findings;
}

// SOL827: Missing Decimal Precision Handling
export function checkDecimalPrecisionHandling(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  
  if (content.includes('decimals') && (content.includes('mint') || content.includes('token'))) {
    if (!content.includes('10.pow(decimals)') && !content.includes('decimal_factor') &&
        !content.includes('normalize_amount')) {
      findings.push({
        id: 'SOL827',
        severity: 'high',
        title: 'Missing Decimal Precision Handling',
        description: 'Token amounts must be properly normalized for decimal differences between tokens',
        location: input.path,
        recommendation: 'Implement decimal normalization when comparing or operating on different tokens',
      });
    }
  }
  return findings;
}

// SOL828: Unsafe Borsh Deserialization
export function checkUnsafeBorshDeserialization(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  
  if (content.includes('try_from_slice') || content.includes('deserialize')) {
    if (!content.includes('try_from_slice_unchecked') === false &&
        !content.includes('BorshDeserialize')) {
      // Check for proper error handling
      if (!content.includes('?') && !content.includes('unwrap_or') &&
          !content.includes('map_err')) {
        findings.push({
          id: 'SOL828',
          severity: 'high',
          title: 'Unsafe Borsh Deserialization',
          description: 'Deserialization operations should properly handle errors to prevent crashes',
          location: input.path,
          recommendation: 'Use proper error handling for all deserialization operations',
        });
      }
    }
  }
  return findings;
}

// SOL829: Missing Enum Variant Validation
export function checkEnumVariantValidation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  
  // Check for enum handling without exhaustive matching
  if (content.includes('match') && content.includes('enum')) {
    if (content.includes('_ =>') && !content.includes('unreachable!')) {
      findings.push({
        id: 'SOL829',
        severity: 'medium',
        title: 'Non-Exhaustive Enum Matching',
        description: 'Enum matching should be exhaustive to handle all variants explicitly',
        location: input.path,
        recommendation: 'Remove wildcard match and handle all enum variants explicitly',
      });
    }
  }
  return findings;
}

// SOL830: Missing Negative Number Check
export function checkNegativeNumberCheck(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  
  if (content.includes('i64') || content.includes('i128') || content.includes('i32')) {
    // Check for negative number handling in amounts
    if (content.includes('amount') && !content.includes('>= 0') && 
        !content.includes('is_positive') && !content.includes('abs()')) {
      findings.push({
        id: 'SOL830',
        severity: 'high',
        title: 'Missing Negative Number Check',
        description: 'Signed integers used for amounts should be validated for non-negative values',
        location: input.path,
        recommendation: 'Validate signed integer amounts are non-negative or use unsigned types',
      });
    }
  }
  return findings;
}

// SOL831: Missing Instruction Discriminator Validation
export function checkInstructionDiscriminatorValidation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  
  if (content.includes('instruction_data') && !content.includes('#[program]')) {
    if (!content.includes('discriminator') && !content.includes('instruction_data[0]') &&
        !content.includes('tag')) {
      findings.push({
        id: 'SOL831',
        severity: 'high',
        title: 'Missing Instruction Discriminator Validation',
        description: 'Instructions should validate discriminator/tag before processing',
        location: input.path,
        recommendation: 'Implement instruction discriminator validation at the start of processing',
      });
    }
  }
  return findings;
}

// SOL832: Missing Remaining Data Check
export function checkRemainingDataCheck(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  
  if (content.includes('deserialize') || content.includes('try_from_slice')) {
    if (!content.includes('remaining') && !content.includes('is_empty()') &&
        !content.includes('exact_size')) {
      findings.push({
        id: 'SOL832',
        severity: 'low',
        title: 'Missing Remaining Data Check',
        description: 'Deserialization should verify no remaining data to detect malformed inputs',
        location: input.path,
        recommendation: 'Check for remaining data after deserialization',
      });
    }
  }
  return findings;
}

// SOL833: Missing Account Lamport Validation
export function checkAccountLamportValidation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  
  if (content.includes('lamports') && content.includes('AccountInfo')) {
    if (!content.includes('rent_exempt') && !content.includes('minimum_balance') &&
        !content.includes('lamports() >=')) {
      findings.push({
        id: 'SOL833',
        severity: 'medium',
        title: 'Missing Account Lamport Validation',
        description: 'Account lamport balances should be validated for rent exemption',
        location: input.path,
        recommendation: 'Validate accounts have sufficient lamports for rent exemption',
      });
    }
  }
  return findings;
}

// SOL834: Unsafe Vec Capacity Allocation
export function checkUnsafeVecCapacity(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  
  if (content.includes('Vec::with_capacity') || content.includes('vec!')) {
    // Check for unbounded vec allocation
    if (content.match(/with_capacity\s*\(\s*[a-z_]+\s*\)/) &&
        !content.includes('MAX_CAPACITY') && !content.includes('min(')) {
      findings.push({
        id: 'SOL834',
        severity: 'high',
        title: 'Unsafe Vec Capacity Allocation',
        description: 'Vec capacity should be bounded to prevent memory exhaustion attacks',
        location: input.path,
        recommendation: 'Enforce maximum bounds on Vec capacity allocation',
      });
    }
  }
  return findings;
}

// SOL835: Missing Seed Length Validation
export function checkSeedLengthValidation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  
  if (content.includes('seeds') && content.includes('Pubkey::find_program_address')) {
    if (!content.includes('MAX_SEED_LEN') && !content.includes('32') &&
        !content.includes('seed.len()')) {
      findings.push({
        id: 'SOL835',
        severity: 'medium',
        title: 'Missing Seed Length Validation',
        description: 'PDA seeds should validate length (max 32 bytes each) before use',
        location: input.path,
        recommendation: 'Validate seed lengths do not exceed 32 bytes',
      });
    }
  }
  return findings;
}

// SOL836: Missing Account Executable Check
export function checkAccountExecutableCheck(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  
  if (content.includes('invoke') || content.includes('invoke_signed')) {
    if (!content.includes('executable') && !content.includes('is_executable')) {
      findings.push({
        id: 'SOL836',
        severity: 'high',
        title: 'Missing Account Executable Check',
        description: 'Program accounts should be verified as executable before CPI',
        location: input.path,
        recommendation: 'Verify program accounts are executable before invoking',
      });
    }
  }
  return findings;
}

// Export all batch 30 patterns
export const batchedPatterns30 = {
  checkAccountDataSizeValidation,
  checkUnsafeStringInput,
  checkPubkeyFormatValidation,
  checkUncheckedArrayBounds,
  checkTimestampRangeValidation,
  checkPercentageValidation,
  checkDecimalPrecisionHandling,
  checkUnsafeBorshDeserialization,
  checkEnumVariantValidation,
  checkNegativeNumberCheck,
  checkInstructionDiscriminatorValidation,
  checkRemainingDataCheck,
  checkAccountLamportValidation,
  checkUnsafeVecCapacity,
  checkSeedLengthValidation,
  checkAccountExecutableCheck,
};
