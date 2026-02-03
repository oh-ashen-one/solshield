import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL074: Wrapped SOL Security
 * Detects vulnerabilities in wrapped SOL (wSOL) handling
 */
export function checkWrappedSol(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;

  if (!rust || !rust.content) return findings;

  const hasWrappedSol = rust.content.includes('native_mint') ||
                        rust.content.includes('NATIVE_MINT') ||
                        rust.content.includes('wrapped_sol') ||
                        rust.content.includes('wSOL') ||
                        rust.content.includes('So11111111111111111111111111111111111111112');

  // Even without explicit wSOL, check for native mint handling
  const hasNativeHandling = rust.content.includes('is_native') ||
                            rust.content.includes('native_amount');

  if (!hasWrappedSol && !hasNativeHandling) return findings;

  // Check for native mint comparison
  if (rust.content.includes('mint') && rust.content.includes('token')) {
    if (!rust.content.includes('native_mint::id()') && 
        !rust.content.includes('NATIVE_MINT') &&
        !rust.content.includes('spl_token::native_mint')) {
      findings.push({
        id: 'SOL074',
        severity: 'medium',
        title: 'Missing Native Mint Check',
        description: 'Token operations without checking for native SOL mint',
        location: input.path,
        recommendation: 'Handle native SOL mint specially: if mint == native_mint::id()',
      });
    }
  }

  // Check for SyncNative after lamport changes
  if (rust.content.includes('lamports') && (hasWrappedSol || hasNativeHandling)) {
    if (!rust.content.includes('SyncNative') && !rust.content.includes('sync_native')) {
      findings.push({
        id: 'SOL074',
        severity: 'high',
        title: 'Missing SyncNative After Lamport Change',
        description: 'Wrapped SOL account lamports changed without syncing token balance',
        location: input.path,
        recommendation: 'Call SyncNative instruction after any lamport changes to wSOL accounts',
      });
    }
  }

  // Check for CloseAccount on native token accounts
  if (rust.content.includes('CloseAccount') || rust.content.includes('close_account')) {
    if (hasWrappedSol && !rust.content.includes('close_authority')) {
      findings.push({
        id: 'SOL074',
        severity: 'medium',
        title: 'wSOL Close Without Authority Check',
        description: 'Closing wrapped SOL account may have special considerations',
        location: input.path,
        recommendation: 'Ensure proper authority checks when closing wSOL accounts',
      });
    }
  }

  // Check for direct SOL transfer vs wSOL
  if (rust.content.includes('system_instruction::transfer') && 
      rust.content.includes('token::transfer')) {
    findings.push({
      id: 'SOL074',
      severity: 'low',
      title: 'Mixed SOL and Token Transfers',
      description: 'Both system and token transfers used - ensure correct handling of wSOL',
      location: input.path,
      recommendation: 'Be consistent: convert wSOL to SOL or vice versa before operations',
    });
  }

  // Check for InitializeAccount with native mint
  if (rust.content.includes('InitializeAccount') || rust.content.includes('initialize_account')) {
    if (hasWrappedSol && !rust.content.includes('rent')) {
      findings.push({
        id: 'SOL074',
        severity: 'medium',
        title: 'wSOL Account Initialization',
        description: 'Initializing wSOL account - ensure proper rent handling',
        location: input.path,
        recommendation: 'wSOL accounts need rent-exemption plus desired balance as lamports',
      });
    }
  }

  // Check for amount confusion between lamports and tokens
  if ((rust.content.includes('lamports') || rust.content.includes('Lamports')) &&
      rust.content.includes('amount') && hasWrappedSol) {
    const directComparison = /lamports\s*[<>=]+\s*amount|amount\s*[<>=]+\s*lamports/i;
    if (directComparison.test(rust.content)) {
      findings.push({
        id: 'SOL074',
        severity: 'high',
        title: 'Lamports/Token Amount Confusion',
        description: 'Comparing lamports with token amounts directly - may cause precision issues',
        location: input.path,
        recommendation: 'For wSOL, lamports = token amount, but ensure context is correct',
      });
    }
  }

  // Check for unwrap to non-signer
  if (rust.content.includes('close_account') && hasWrappedSol) {
    if (!rust.content.includes('signer') && !rust.content.includes('authority')) {
      findings.push({
        id: 'SOL074',
        severity: 'high',
        title: 'wSOL Unwrap Destination Not Validated',
        description: 'Closing wSOL account sends lamports to destination - validate ownership',
        location: input.path,
        recommendation: 'Ensure destination account is owned by expected party',
      });
    }
  }

  return findings;
}
