import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL656: NPM Supply Chain Attack 2025 Pattern
 * 
 * Based on September 2025 massive npm supply chain attack
 * 18 popular packages compromised including 'chalk' and 'debug'
 * (2 billion+ weekly downloads affected)
 * 
 * Attack injected crypto-clipper malware that replaced wallet addresses
 * 
 * References:
 * - Cyber Daily: DeFi Security Breaches Exceed $3.1 Billion (Nov 2025)
 * - npm security advisories
 */

export function checkNpmSupplyChain2025(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  const idl = input.idl;
  const path = input.path;

  // Note: This pattern checks Rust code but the real risk is in JS/TS
  // dependencies. We flag any patterns that suggest external dependency usage

  // Pattern 1: Hardcoded addresses that could be clipper targets
  const hardcodedAddresses = content.match(/[1-9A-HJ-NP-Za-km-z]{32,44}/g) || [];
  
  if (hardcodedAddresses.length > 0) {
    // Check if addresses are defined as constants vs inline
    const hasConstantDef = /const\s+\w+\s*:\s*Pubkey\s*=\s*pubkey!/i.test(content);
    
    if (!hasConstantDef && hardcodedAddresses.length > 2) {
      findings.push({
        id: 'SOL656',
        severity: 'high',
        title: 'Hardcoded Addresses (Supply Chain Attack Risk)',
        description: `Multiple hardcoded addresses found. The Sept 2025 npm attack used crypto-clippers to replace addresses. Hardcoded addresses in source could be modified by compromised build tools. Found ${hardcodedAddresses.length} potential addresses.`,
        location: path,
        recommendation: 'Define critical addresses as named constants. Use verification checksums. Implement address whitelists that are verified on-chain.',
      });
    }
  }

  // Pattern 2: Dynamic address construction
  const dynamicAddressPatterns = [
    /Pubkey::from_str\(/gi,
    /bs58::decode/gi,
    /parse.*pubkey/gi,
    /address.*from.*string/gi,
  ];

  for (const pattern of dynamicAddressPatterns) {
    if (pattern.test(content)) {
      findings.push({
        id: 'SOL656-2',
        severity: 'medium',
        title: 'Dynamic Address Construction',
        description: `Addresses constructed from strings at runtime. Supply chain attacks can inject malicious address strings. Prefer compile-time constant addresses.`,
        location: path,
        recommendation: 'Use pubkey! macro for compile-time address verification. Validate addresses against known-good list.',
      });
    }
  }

  // Pattern 3: External program invocations without hardcoded program IDs
  if (/invoke\(|invoke_signed\(/i.test(content)) {
    const programIdHardcoded = /program_id\s*:\s*&(spl_token|system_program|TOKEN_PROGRAM)/i.test(content);
    
    if (!programIdHardcoded) {
      findings.push({
        id: 'SOL656-3',
        severity: 'high',
        title: 'CPI Without Hardcoded Program ID',
        description: `Cross-program invocation without compile-time verified program ID. Compromised dependencies could inject malicious program addresses.`,
        location: path,
        recommendation: 'Always use constants for well-known program IDs (TOKEN_PROGRAM_ID, SYSTEM_PROGRAM_ID). Verify program IDs at runtime.',
      });
    }
  }

  // Pattern 4: Build script execution patterns
  const buildScriptPatterns = [
    /build\.rs/gi,
    /proc-macro/gi,
    /include_bytes!/gi,
    /include_str!/gi,
  ];

  for (const pattern of buildScriptPatterns) {
    if (pattern.test(content)) {
      findings.push({
        id: 'SOL656-4',
        severity: 'info',
        title: 'Build-Time Code Execution',
        description: `Build scripts or macros that execute at compile time. Supply chain attacks can inject malicious code through compromised build dependencies.`,
        location: path,
        recommendation: 'Audit all build.rs and proc-macro dependencies. Pin exact versions. Use cargo-audit and cargo-deny.',
      });
    }
  }

  // Pattern 5: Check for dangerous patterns that clippers target
  const clipperTargetPatterns = [
    /recipient|destination|to_account|withdraw_to/gi,
  ];

  for (const pattern of clipperTargetPatterns) {
    const matches = content.match(pattern);
    if (matches && matches.length > 3) {
      findings.push({
        id: 'SOL656-5',
        severity: 'medium',
        title: 'Multiple Recipient Fields (Clipper Target)',
        description: `Multiple recipient/destination fields found. Crypto-clippers specifically target these patterns to replace addresses with attacker-controlled ones.`,
        location: path,
        recommendation: 'Implement address verification. Consider on-chain address registries. Add checksums for critical addresses.',
      });
    }
  }

  // Pattern 6: External data fetching
  const externalFetchPatterns = [
    /reqwest|hyper|http_client/gi,
    /fetch.*url|download.*address/gi,
    /ipfs|arweave.*address/gi,
  ];

  for (const pattern of externalFetchPatterns) {
    if (pattern.test(content)) {
      findings.push({
        id: 'SOL656-6',
        severity: 'high',
        title: 'External Data Fetching (Supply Chain Risk)',
        description: `Code fetches data from external sources. Compromised endpoints or MITM attacks could inject malicious data including wallet addresses.`,
        location: path,
        recommendation: 'Pin and verify external data sources. Use content-addressed storage (IPFS) with hash verification. Avoid dynamic address fetching.',
      });
    }
  }

  return findings;
}
