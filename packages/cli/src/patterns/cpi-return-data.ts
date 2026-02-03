import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL085: CPI Return Data Security
 * Detects vulnerabilities in handling CPI return data
 */
export function checkCpiReturnData(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;

  if (!rust || !rust.content) return findings;

  const hasCpiReturn = rust.content.includes('get_return_data') ||
                       rust.content.includes('return_data') ||
                       rust.content.includes('set_return_data');

  if (!hasCpiReturn && !rust.content.includes('invoke')) return findings;

  // Check for get_return_data without program ID verification
  if (rust.content.includes('get_return_data')) {
    if (!rust.content.includes('program_id') && !rust.content.includes('.0 ==')) {
      findings.push({
        id: 'SOL085',
        severity: 'critical',
        title: 'Return Data Without Program ID Check',
        description: 'Reading return data without verifying it came from expected program',
        location: input.path,
        recommendation: 'Check get_return_data().0 == expected_program_id before using data',
      });
    }
  }

  // Check for return data trust after failed CPI
  if (rust.content.includes('invoke') && rust.content.includes('get_return_data')) {
    const invokeWithoutResultCheck = /invoke[^?]*;[\s\S]*?get_return_data/;
    if (invokeWithoutResultCheck.test(rust.content)) {
      if (!rust.content.includes('?') && !rust.content.includes('.unwrap()')) {
        findings.push({
          id: 'SOL085',
          severity: 'high',
          title: 'Return Data After Unchecked CPI',
          description: 'Reading return data without checking if CPI succeeded',
          location: input.path,
          recommendation: 'Check CPI result before reading return data: invoke(...)?',
        });
      }
    }
  }

  // Check for return data size limits
  if (rust.content.includes('set_return_data')) {
    // Solana has 1024 byte limit for return data
    const largeReturn = /set_return_data\s*\([^)]*(?:vec!|Vec::)|return_data[\s\S]*?1024/;
    if (largeReturn.test(rust.content)) {
      findings.push({
        id: 'SOL085',
        severity: 'medium',
        title: 'Large Return Data',
        description: 'Return data has 1024 byte limit - may fail with large payloads',
        location: input.path,
        recommendation: 'Ensure return data is under 1024 bytes or handle overflow',
      });
    }
  }

  // Check for return data deserialization
  if (rust.content.includes('get_return_data') && 
      (rust.content.includes('try_from_slice') || rust.content.includes('deserialize'))) {
    if (!rust.content.includes('len()') && !rust.content.includes('is_empty')) {
      findings.push({
        id: 'SOL085',
        severity: 'medium',
        title: 'Return Data Deserialization Without Length Check',
        description: 'Deserializing return data without checking data length',
        location: input.path,
        recommendation: 'Verify return data length matches expected type size before deserializing',
      });
    }
  }

  // Check for multi-CPI return data handling
  const multipleInvokes = (rust.content.match(/invoke\s*\(/g) || []).length;
  if (multipleInvokes > 1 && rust.content.includes('get_return_data')) {
    findings.push({
      id: 'SOL085',
      severity: 'medium',
      title: 'Return Data With Multiple CPIs',
      description: 'Multiple CPIs but only one return data buffer - ensure reading correct data',
      location: input.path,
      recommendation: 'Read return data immediately after each CPI that returns data',
    });
  }

  // Check for return data in anchor CPI
  if (rust.content.includes('CpiContext') && rust.content.includes('return_data')) {
    findings.push({
      id: 'SOL085',
      severity: 'low',
      title: 'Anchor CPI Return Data',
      description: 'Anchor CPI with return data - ensure proper handling',
      location: input.path,
      recommendation: 'Use cpi_return_data attribute for proper Anchor return data handling',
    });
  }

  return findings;
}
