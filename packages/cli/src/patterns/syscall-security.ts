import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL090: Solana Syscall Security
 * Detects risky usage of Solana syscalls and runtime features
 */
export function checkSyscallSecurity(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;

  if (!rust || !rust.content) return findings;

  // Check for sol_log abuse (compute units)
  const logCount = (rust.content.match(/msg!|sol_log|log/g) || []).length;
  if (logCount > 20) {
    findings.push({
      id: 'SOL090',
      severity: 'medium',
      title: 'Excessive Logging',
      description: `${logCount} log statements - each costs compute units`,
      location: input.path,
      recommendation: 'Reduce logging in production; consider feature flags for debug logs',
    });
  }

  // Check for compute budget manipulation
  if (rust.content.includes('ComputeBudget') || rust.content.includes('request_heap_frame')) {
    findings.push({
      id: 'SOL090',
      severity: 'low',
      title: 'Compute Budget Modification',
      description: 'Program modifies compute budget - ensure client handles this correctly',
      location: input.path,
      recommendation: 'Document compute budget requirements for client integration',
    });
  }

  // Check for set_return_data without size consideration
  if (rust.content.includes('set_return_data')) {
    if (!rust.content.includes('MAX_RETURN_DATA') && !rust.content.includes('1024')) {
      findings.push({
        id: 'SOL090',
        severity: 'medium',
        title: 'Return Data Without Size Check',
        description: 'Setting return data without checking 1024 byte limit',
        location: input.path,
        recommendation: 'Ensure return data is under MAX_RETURN_DATA (1024 bytes)',
      });
    }
  }

  // Check for get_stack_height usage
  if (rust.content.includes('get_stack_height') || rust.content.includes('stack_height')) {
    findings.push({
      id: 'SOL090',
      severity: 'medium',
      title: 'Stack Height Dependency',
      description: 'Program depends on stack height - may break with CPI depth changes',
      location: input.path,
      recommendation: 'Avoid relying on specific stack heights; use explicit recursion limits',
    });
  }

  // Check for sol_memcpy/memmove with user-controlled sizes
  if (rust.content.includes('sol_memcpy') || rust.content.includes('sol_memmove')) {
    if (rust.content.includes('len') || rust.content.includes('size')) {
      findings.push({
        id: 'SOL090',
        severity: 'high',
        title: 'Memory Copy With Variable Size',
        description: 'Memory copy with potentially user-controlled size parameter',
        location: input.path,
        recommendation: 'Validate size bounds before memory operations',
      });
    }
  }

  // Check for poseidon/alt_bn128 syscalls (experimental)
  if (rust.content.includes('poseidon') || rust.content.includes('alt_bn128')) {
    findings.push({
      id: 'SOL090',
      severity: 'low',
      title: 'Experimental Syscall Usage',
      description: 'Using experimental cryptographic syscalls - may change',
      location: input.path,
      recommendation: 'Track Solana updates for syscall stability changes',
    });
  }

  // Check for sol_remaining_compute_units
  if (rust.content.includes('sol_remaining_compute_units')) {
    findings.push({
      id: 'SOL090',
      severity: 'low',
      title: 'Compute Unit Check',
      description: 'Program checks remaining compute units - ensure graceful handling',
      location: input.path,
      recommendation: 'Handle low compute units gracefully rather than panicking',
    });
  }

  // Check for create_program_address (deprecated pattern)
  if (rust.content.includes('create_program_address') && 
      !rust.content.includes('find_program_address')) {
    findings.push({
      id: 'SOL090',
      severity: 'medium',
      title: 'Using create_program_address',
      description: 'create_program_address requires known bump - use find_program_address instead',
      location: input.path,
      recommendation: 'Use find_program_address which returns canonical bump',
    });
  }

  // Check for sol_invoke_signed with many accounts
  if (rust.content.includes('invoke_signed')) {
    const accountRefs = (rust.content.match(/AccountInfo|AccountMeta/g) || []).length;
    if (accountRefs > 20) {
      findings.push({
        id: 'SOL090',
        severity: 'medium',
        title: 'CPI With Many Accounts',
        description: `CPI with ${accountRefs}+ accounts may hit transaction size limits`,
        location: input.path,
        recommendation: 'Consider batching or reducing accounts per CPI',
      });
    }
  }

  return findings;
}
