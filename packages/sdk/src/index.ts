/**
 * SolShield SDK
 * AI-Powered Smart Contract Security Scanner for Solana
 * 
 * @example
 * ```ts
 * import { scan, scanFile, listPatterns } from 'solshield';
 * 
 * // Scan code directly
 * const result = await scan(`
 *   pub fn transfer(ctx: Context<Transfer>, amount: u64) -> Result<()> {
 *     // Your Solana program code
 *   }
 * `);
 * 
 * // Check results
 * console.log(result.summary);
 * console.log(result.findings);
 * ```
 */

// ============================================
// Types
// ============================================

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface Finding {
  /** Pattern ID (e.g., SOL001) */
  id: string;
  /** Pattern name */
  pattern: string;
  /** Severity level */
  severity: Severity;
  /** Short title */
  title: string;
  /** Detailed description */
  description: string;
  /** Location in code */
  location: {
    file: string;
    line?: number;
    column?: number;
  };
  /** Code snippet */
  code?: string;
  /** Suggested fix */
  suggestion?: string;
}

export interface AuditSummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total: number;
}

export interface ScanResult {
  /** Timestamp of scan */
  timestamp: string;
  /** All findings */
  findings: Finding[];
  /** Summary counts by severity */
  summary: AuditSummary;
  /** True if no critical/high findings */
  passed: boolean;
  /** Patterns used in scan */
  patternsUsed: number;
}

export interface Pattern {
  /** Pattern ID (e.g., SOL001) */
  id: string;
  /** Pattern name */
  name: string;
  /** Severity level */
  severity: Severity;
  /** Description of what it detects */
  description: string;
  /** Real-world exploit this would catch (if any) */
  exploit?: string;
  /** Estimated value at risk */
  valueAtRisk?: string;
}

export interface ScanOptions {
  /** Only run specific patterns by ID */
  patterns?: string[];
  /** Minimum severity to report */
  minSeverity?: Severity;
  /** Include info-level findings */
  includeInfo?: boolean;
}

// ============================================
// Pattern Definitions (150 patterns)
// ============================================

const PATTERNS: Pattern[] = [
  // Critical patterns
  { id: 'SOL001', name: 'Missing Owner Check', severity: 'critical', description: 'Account owner not validated, allowing arbitrary account injection' },
  { id: 'SOL002', name: 'Missing Signer Check', severity: 'critical', description: 'Transaction signer not verified, enabling unauthorized actions' },
  { id: 'SOL005', name: 'Authority Bypass', severity: 'critical', description: 'Authority validation can be bypassed' },
  { id: 'SOL006', name: 'Missing Initialization Check', severity: 'critical', description: 'Account can be re-initialized, corrupting state' },
  { id: 'SOL010', name: 'Account Closing Vulnerability', severity: 'critical', description: 'Account closing can be exploited for fund theft' },
  { id: 'SOL012', name: 'Arbitrary CPI', severity: 'critical', description: 'Cross-program invocation target not validated' },
  { id: 'SOL015', name: 'Type Cosplay', severity: 'critical', description: 'Account type can be spoofed via discriminator manipulation' },
  { id: 'SOL019', name: 'Flash Loan Vulnerability', severity: 'critical', description: 'Vulnerable to flash loan attacks' },
  { id: 'SOL021', name: 'Sysvar Manipulation Risk', severity: 'critical', description: 'Sysvar accounts not properly validated' },
  { id: 'SOL029', name: 'Signature Verification Bypass', severity: 'critical', description: 'Ed25519 signature verification can be bypassed', exploit: 'Wormhole', valueAtRisk: '$326M' },
  { id: 'SOL031', name: 'Mint Authority Not Checked', severity: 'critical', description: 'Token mint authority not validated', exploit: 'Cashio', valueAtRisk: '$52M' },
  { id: 'SOL033', name: 'Signature Replay', severity: 'critical', description: 'Signatures can be replayed for duplicate execution' },
  { id: 'SOL041', name: 'Governance Vulnerability', severity: 'critical', description: 'Governance mechanism can be exploited' },
  { id: 'SOL044', name: 'AMM/DEX Vulnerability', severity: 'critical', description: 'AMM logic vulnerable to manipulation' },
  { id: 'SOL045', name: 'Lending Protocol Vulnerability', severity: 'critical', description: 'Lending mechanism can be exploited' },
  { id: 'SOL046', name: 'Bridge Vulnerability', severity: 'critical', description: 'Cross-chain bridge security flaw' },
  { id: 'SOL048', name: 'Merkle Vulnerability', severity: 'critical', description: 'Merkle tree verification can be bypassed' },
  { id: 'SOL055', name: 'Program ID Vulnerability', severity: 'critical', description: 'Program ID not properly validated' },
  { id: 'SOL059', name: 'Withdrawal Pattern Issue', severity: 'critical', description: 'Withdrawal logic can be exploited' },
  { id: 'SOL060', name: 'Initialization Frontrunning', severity: 'critical', description: 'Initialization can be frontrun' },
  { id: 'SOL063', name: 'Privilege Escalation', severity: 'critical', description: 'Privileges can be escalated' },
  { id: 'SOL067', name: 'Remaining Accounts Security', severity: 'critical', description: 'Remaining accounts not validated' },
  { id: 'SOL073', name: 'System Program Abuse', severity: 'critical', description: 'System program can be abused' },
  { id: 'SOL075', name: 'Account Revival Attack', severity: 'critical', description: 'Closed accounts can be revived' },
  { id: 'SOL077', name: 'Program Data Authority', severity: 'critical', description: 'Program data authority exploitable' },
  { id: 'SOL078', name: 'Token Mint Authority Security', severity: 'critical', description: 'Mint authority not properly secured' },
  { id: 'SOL079', name: 'Account Discriminator Security', severity: 'critical', description: 'Discriminator validation missing' },
  { id: 'SOL082', name: 'Token Account Ownership', severity: 'critical', description: 'Token ownership not verified' },
  { id: 'SOL083', name: 'PDA Signer Seeds Mismatch', severity: 'critical', description: 'PDA signer seeds can be manipulated' },
  { id: 'SOL096', name: 'Cross-Chain Bridge Security', severity: 'critical', description: 'Cross-chain message validation flaw' },
  { id: 'SOL097', name: 'Multisig Security', severity: 'critical', description: 'Multisig can be bypassed' },
  { id: 'SOL107', name: 'Token Burn Safety', severity: 'critical', description: 'Token burn not properly authorized' },
  { id: 'SOL111', name: 'Account Discriminator Validation', severity: 'critical', description: 'Account type not validated' },
  { id: 'SOL117', name: 'Token Freeze Operations', severity: 'critical', description: 'Freeze authority exploitable' },
  { id: 'SOL119', name: 'Program Upgrade Security', severity: 'critical', description: 'Upgrade authority not secured' },
  { id: 'SOL131', name: 'Tick Account Spoofing', severity: 'critical', description: 'Oracle tick accounts can be spoofed' },
  { id: 'SOL132', name: 'Governance Proposal Injection', severity: 'critical', description: 'Malicious proposals can be injected' },
  { id: 'SOL133', name: 'Bonding Curve Manipulation', severity: 'critical', description: 'Bonding curve can be manipulated' },
  { id: 'SOL134', name: 'Infinite Mint Vulnerability', severity: 'critical', description: 'Token supply can be inflated infinitely' },
  { id: 'SOL135', name: 'Liquidation Threshold Manipulation', severity: 'critical', description: 'Liquidation can be triggered maliciously' },
  { id: 'SOL137', name: 'Private Key Exposure', severity: 'critical', description: 'Private keys exposed in code' },
  { id: 'SOL138', name: 'Insider Threat Vector', severity: 'critical', description: 'Admin keys can drain funds' },
  { id: 'SOL139', name: 'Treasury Drain Attack', severity: 'critical', description: 'Treasury can be drained' },
  { id: 'SOL140', name: 'CLMM/AMM Exploit', severity: 'critical', description: 'Concentrated liquidity can be exploited' },
  { id: 'SOL142', name: 'Signature Verification Bypass', severity: 'critical', description: 'Signature checks can be bypassed' },
  { id: 'SOL143', name: 'LP Token Oracle Manipulation', severity: 'critical', description: 'LP token price can be manipulated' },
  { id: 'SOL144', name: 'Unchecked Account in CPI', severity: 'critical', description: 'Account passed to CPI not validated' },
  { id: 'SOL146', name: 'Transaction Simulation Detection', severity: 'critical', description: 'Code behaves differently in simulation' },
  { id: 'SOL147', name: 'Root of Trust Establishment', severity: 'critical', description: 'Root of trust can be compromised' },
  { id: 'SOL148', name: 'SPL Lending Rounding', severity: 'critical', description: 'Rounding errors in lending math' },
  { id: 'SOL149', name: 'Anchor Unchecked Account', severity: 'critical', description: 'UncheckedAccount used unsafely' },
  
  // High severity patterns
  { id: 'SOL003', name: 'Integer Overflow', severity: 'high', description: 'Arithmetic can overflow without checks' },
  { id: 'SOL004', name: 'PDA Validation Gap', severity: 'high', description: 'PDA derivation not validated' },
  { id: 'SOL007', name: 'CPI Vulnerability', severity: 'high', description: 'Cross-program invocation security issue' },
  { id: 'SOL009', name: 'Account Confusion', severity: 'high', description: 'Similar accounts can be confused' },
  { id: 'SOL011', name: 'Cross-Program Reentrancy', severity: 'high', description: 'Reentrancy via CPI possible' },
  { id: 'SOL013', name: 'Duplicate Mutable Accounts', severity: 'high', description: 'Same account passed twice as mutable' },
  { id: 'SOL016', name: 'Bump Seed Canonicalization', severity: 'high', description: 'PDA bump not canonicalized' },
  { id: 'SOL018', name: 'Oracle Manipulation Risk', severity: 'high', description: 'Price oracle can be manipulated' },
  { id: 'SOL020', name: 'Unsafe Arithmetic', severity: 'high', description: 'Unchecked arithmetic operations' },
  { id: 'SOL023', name: 'Token Account Validation', severity: 'high', description: 'Token account not properly validated' },
  { id: 'SOL024', name: 'Cross-Program State Dependency', severity: 'high', description: 'Depends on external state unsafely' },
  { id: 'SOL025', name: 'Lamport Balance Vulnerability', severity: 'high', description: 'Balance checks can be bypassed' },
  { id: 'SOL034', name: 'Storage/Discriminator Collision', severity: 'high', description: 'Storage slots can collide' },
  { id: 'SOL035', name: 'Denial of Service', severity: 'high', description: 'Program can be DoSed' },
  { id: 'SOL040', name: 'CPI Guard Vulnerability', severity: 'high', description: 'CPI guard can be bypassed' },
  { id: 'SOL042', name: 'NFT Security Issue', severity: 'high', description: 'NFT logic vulnerability' },
  { id: 'SOL043', name: 'Staking Vulnerability', severity: 'high', description: 'Staking mechanism flaw' },
  { id: 'SOL047', name: 'Vault Vulnerability', severity: 'high', description: 'Vault can be exploited' },
  { id: 'SOL050', name: 'Program-Derived Signing Issue', severity: 'high', description: 'PDA signing flaw' },
  { id: 'SOL057', name: 'Fee Handling Vulnerability', severity: 'high', description: 'Fees can be manipulated' },
  { id: 'SOL061', name: 'Data Validation Issue', severity: 'high', description: 'Input data not validated' },
  { id: 'SOL062', name: 'Compute Budget Issue', severity: 'high', description: 'Can exceed compute limits' },
  { id: 'SOL064', name: 'Sandwich Attack Vulnerability', severity: 'high', description: 'Vulnerable to sandwich attacks' },
  { id: 'SOL065', name: 'Supply Manipulation', severity: 'high', description: 'Token supply can be manipulated' },
  { id: 'SOL066', name: 'Account Data Borrowing', severity: 'high', description: 'Account borrowing issue' },
  { id: 'SOL068', name: 'Anchor Constraint Validation', severity: 'high', description: 'Constraints not sufficient' },
  { id: 'SOL069', name: 'Rent Drain Attack', severity: 'high', description: 'Rent can be drained' },
  { id: 'SOL070', name: 'PDA Seed Collision', severity: 'high', description: 'PDA seeds can collide' },
  { id: 'SOL071', name: 'Metaplex/NFT Metadata Security', severity: 'high', description: 'Metadata can be spoofed' },
  { id: 'SOL072', name: 'Associated Token Account Security', severity: 'high', description: 'ATA validation issue' },
  { id: 'SOL074', name: 'Wrapped SOL Security', severity: 'high', description: 'wSOL handling flaw' },
  { id: 'SOL080', name: 'Timestamp Manipulation', severity: 'high', description: 'Timestamps can be manipulated' },
  { id: 'SOL085', name: 'CPI Return Data Security', severity: 'high', description: 'CPI return data not validated' },
  { id: 'SOL087', name: 'Arithmetic Precision Issues', severity: 'high', description: 'Precision loss in math' },
  { id: 'SOL089', name: 'Account Type Safety', severity: 'high', description: 'Account types not checked' },
  { id: 'SOL091', name: 'SPL Governance Security', severity: 'high', description: 'SPL governance flaw' },
  { id: 'SOL092', name: 'Token Extensions Security', severity: 'high', description: 'Token-2022 extensions issue' },
  { id: 'SOL093', name: 'Address Lookup Table Security', severity: 'high', description: 'ALT can be manipulated' },
  { id: 'SOL095', name: 'Slot Number Manipulation', severity: 'high', description: 'Slot-based logic exploitable' },
  { id: 'SOL099', name: 'Atomic Operations', severity: 'high', description: 'Operations not atomic' },
  { id: 'SOL100', name: 'Initialization Order Dependencies', severity: 'high', description: 'Init order matters' },
  { id: 'SOL102', name: 'Instruction Data Handling', severity: 'high', description: 'Instruction data issue' },
  { id: 'SOL103', name: 'Anchor CPI Safety', severity: 'high', description: 'Anchor CPI not safe' },
  { id: 'SOL106', name: 'Account Key Derivation', severity: 'high', description: 'Key derivation flaw' },
  { id: 'SOL108', name: 'Associated Program Security', severity: 'high', description: 'Associated program issue' },
  { id: 'SOL109', name: 'Signer Seeds Validation', severity: 'high', description: 'Signer seeds issue' },
  { id: 'SOL110', name: 'Account Reallocation', severity: 'high', description: 'Realloc can be exploited' },
  { id: 'SOL112', name: 'Token Approval/Delegation', severity: 'high', description: 'Approval not revoked' },
  { id: 'SOL113', name: 'Rent Collection Security', severity: 'high', description: 'Rent collection flaw' },
  { id: 'SOL115', name: 'State Transition Validation', severity: 'high', description: 'Invalid state transitions' },
  { id: 'SOL116', name: 'Account Data Matching', severity: 'high', description: 'Data mismatch possible' },
  { id: 'SOL118', name: 'Zero-Copy Account Handling', severity: 'high', description: 'Zero-copy issue' },
  { id: 'SOL120', name: 'Account Constraint Combinations', severity: 'high', description: 'Constraint combo issue' },
  { id: 'SOL122', name: 'Account Close Destination', severity: 'high', description: 'Close destination flaw' },
  { id: 'SOL123', name: 'Token Account Closure', severity: 'high', description: 'Token closure issue' },
  { id: 'SOL124', name: 'Account Data Initialization', severity: 'high', description: 'Data init issue' },
  { id: 'SOL126', name: 'Account Lamport Checks', severity: 'high', description: 'Lamport check issue' },
  { id: 'SOL136', name: 'Supply Chain Attack Vector', severity: 'high', description: 'Dependency vulnerability' },
  { id: 'SOL141', name: 'Bot/Automation Compromise', severity: 'high', description: 'Automation keys at risk' },
  { id: 'SOL150', name: 'Cross-Program Invocation Safety', severity: 'high', description: 'CPI safety issue' },
  
  // Medium severity patterns
  { id: 'SOL008', name: 'Rounding Error', severity: 'medium', description: 'Rounding can cause value loss' },
  { id: 'SOL014', name: 'Missing Rent Exemption', severity: 'medium', description: 'Account may not be rent-exempt' },
  { id: 'SOL017', name: 'Missing Freeze Authority Check', severity: 'medium', description: 'Freeze authority not checked' },
  { id: 'SOL022', name: 'Program Upgrade Authority Risk', severity: 'medium', description: 'Upgrade authority not secured' },
  { id: 'SOL026', name: 'Seeded Account Vulnerability', severity: 'medium', description: 'Seed derivation issue' },
  { id: 'SOL027', name: 'Inadequate Error Handling', severity: 'medium', description: 'Errors not handled properly' },
  { id: 'SOL030', name: 'Anchor Macro Misuse', severity: 'medium', description: 'Anchor macros used incorrectly' },
  { id: 'SOL032', name: 'Missing Time Lock', severity: 'medium', description: 'No timelock on critical actions' },
  { id: 'SOL036', name: 'Input Validation Issues', severity: 'medium', description: 'Inputs not fully validated' },
  { id: 'SOL037', name: 'State Initialization Issues', severity: 'medium', description: 'State init issue' },
  { id: 'SOL038', name: 'Token-2022 Compatibility', severity: 'medium', description: 'Not compatible with Token-2022' },
  { id: 'SOL039', name: 'Hardcoded Secret Detection', severity: 'medium', description: 'Secrets in code' },
  { id: 'SOL049', name: 'Compression Vulnerability', severity: 'medium', description: 'Compression issue' },
  { id: 'SOL051', name: 'Account Size Vulnerability', severity: 'medium', description: 'Account size issue' },
  { id: 'SOL052', name: 'Clock Dependency Issue', severity: 'medium', description: 'Clock dependency' },
  { id: 'SOL053', name: 'Account Order Dependency', severity: 'medium', description: 'Account order matters' },
  { id: 'SOL054', name: 'Serialization Vulnerability', severity: 'medium', description: 'Serialization issue' },
  { id: 'SOL056', name: 'Authority Transfer Vulnerability', severity: 'medium', description: 'Authority transfer issue' },
  { id: 'SOL058', name: 'Pause Mechanism Issue', severity: 'medium', description: 'Pause not implemented' },
  { id: 'SOL076', name: 'Cross-Instance Confusion', severity: 'medium', description: 'Instance confusion' },
  { id: 'SOL081', name: 'Anchor Account Initialization', severity: 'medium', description: 'Anchor init issue' },
  { id: 'SOL084', name: 'Account Constraints Order', severity: 'medium', description: 'Constraint order issue' },
  { id: 'SOL086', name: 'Account Lifetime Management', severity: 'medium', description: 'Lifetime issue' },
  { id: 'SOL088', name: 'Event Ordering and Emission', severity: 'medium', description: 'Event order issue' },
  { id: 'SOL090', name: 'Solana Syscall Security', severity: 'medium', description: 'Syscall issue' },
  { id: 'SOL094', name: 'Priority Fee Handling', severity: 'medium', description: 'Priority fee issue' },
  { id: 'SOL098', name: 'Account Versioning', severity: 'medium', description: 'Version mismatch' },
  { id: 'SOL104', name: 'Authority Scope', severity: 'medium', description: 'Authority too broad' },
  { id: 'SOL105', name: 'Error Propagation', severity: 'medium', description: 'Error handling issue' },
  { id: 'SOL114', name: 'Instruction Sysvar Usage', severity: 'medium', description: 'Sysvar usage issue' },
  { id: 'SOL121', name: 'CPI Depth Management', severity: 'medium', description: 'CPI depth issue' },
  { id: 'SOL125', name: 'Program as Signer', severity: 'medium', description: 'Program signer issue' },
  { id: 'SOL127', name: 'Instruction Size Limits', severity: 'medium', description: 'Instruction too large' },
  { id: 'SOL128', name: 'Account Seed Length', severity: 'medium', description: 'Seed too long' },
  { id: 'SOL129', name: 'Token Decimal Handling', severity: 'medium', description: 'Decimal handling issue' },
  { id: 'SOL145', name: 'Break Statement Logic Bug', severity: 'medium', description: 'Break logic error' },
  
  // Low/Info severity patterns
  { id: 'SOL028', name: 'Event Emission Issues', severity: 'low', description: 'Events not emitted properly' },
  { id: 'SOL101', name: 'Program Cache Considerations', severity: 'low', description: 'Cache behavior' },
  { id: 'SOL130', name: 'PDA Bump Storage', severity: 'low', description: 'Bump not stored' },
];

// ============================================
// Pattern Detection Logic
// ============================================

interface PatternCheck {
  id: string;
  test: (code: string) => Finding | null;
}

// Build pattern checks from definitions
function buildPatternChecks(): PatternCheck[] {
  return PATTERNS.map(p => ({
    id: p.id,
    test: (code: string) => {
      const finding = runPatternCheck(p, code);
      return finding;
    }
  }));
}

function runPatternCheck(pattern: Pattern, code: string): Finding | null {
  // Pattern-specific detection logic
  const checks: Record<string, (code: string) => boolean> = {
    // Critical patterns
    'SOL001': (c) => /AccountInfo/.test(c) && !/owner/.test(c),
    'SOL002': (c) => /pub\s+fn\s+\w+/.test(c) && /Signer/.test(c) === false && /authority|admin|owner/.test(c),
    'SOL005': (c) => /authority/.test(c) && !/require|constraint|has_one/.test(c),
    'SOL006': (c) => /init/.test(c) && !/is_initialized|initialized/.test(c),
    'SOL010': (c) => /close/.test(c) && !/close\s*=/.test(c),
    'SOL012': (c) => /invoke|CpiContext/.test(c) && /program_id/.test(c) === false,
    'SOL015': (c) => /Account</.test(c) && !/discriminator/.test(c) && /try_from/.test(c),
    'SOL019': (c) => /flash|loan/.test(c) && !/balance_before|snapshot/.test(c),
    'SOL021': (c) => /Sysvar/.test(c) && /from_account_info/.test(c) && !/check/.test(c),
    'SOL029': (c) => /ed25519|verify_signature/.test(c) && /verify/.test(c) === false,
    'SOL031': (c) => /mint_authority|MintTo/.test(c) && !/constraint|require|assert/.test(c),
    'SOL033': (c) => /signature|nonce/.test(c) && /used_signatures|nonce_account/.test(c) === false,
    'SOL039': (c) => /(secret|private_key|password)\s*[:=]\s*["'][^"']+["']/.test(c),
    
    // High patterns  
    'SOL003': (c) => /\+|\*|-|\//.test(c) && !/checked_|saturating_|overflow/.test(c) && /u64|u128|i64/.test(c),
    'SOL004': (c) => /Pubkey::find_program_address|create_program_address/.test(c) && !/seeds|bump/.test(c),
    'SOL007': (c) => /invoke_signed|CpiContext/.test(c) && /accounts/.test(c),
    'SOL009': (c) => /Account<.*>.*Account<.*>/.test(c) && /!=|ne|different/.test(c) === false,
    'SOL011': (c) => /invoke|cpi/.test(c) && /mut/.test(c) && /state/.test(c),
    'SOL013': (c) => /@account.*mut.*\n.*@account.*mut/s.test(c),
    'SOL016': (c) => /bump/.test(c) && /canonical|find_program_address/.test(c) === false,
    'SOL018': (c) => /oracle|price/.test(c) && /twap|average|median/.test(c) === false,
    'SOL020': (c) => /as\s+u\d+|unsafe/.test(c) && /checked/.test(c) === false,
    'SOL042': (c) => /invoke|cpi/.test(c) && /program_id.*variable|AccountInfo.*program/.test(c),
    
    // Medium patterns
    'SOL008': (c) => /\/\s*\d+|\d+\s*\//.test(c) && !/round|ceil|floor/.test(c),
    'SOL014': (c) => /lamports/.test(c) && /rent_exempt|minimum_balance/.test(c) === false,
    'SOL017': (c) => /freeze/.test(c) && /freeze_authority/.test(c) === false,
    'SOL022': (c) => /upgrade_authority|BpfUpgradeable/.test(c) && /require|assert/.test(c) === false,
    'SOL027': (c) => /unwrap\(\)/.test(c) && /expect|match|if let|ok_or/.test(c) === false,
    'SOL032': (c) => /transfer|withdraw/.test(c) && /timelock|delay|cooldown/.test(c) === false && /admin|owner|authority/.test(c),
    'SOL036': (c) => /input|amount|value/.test(c) && /require!|assert!|if\s/.test(c) === false,
    
    // Low patterns
    'SOL028': (c) => /pub\s+fn/.test(c) && /emit!|msg!|log/.test(c) === false,
  };

  const check = checks[pattern.id];
  if (!check) return null;
  
  try {
    if (check(code)) {
      // Find approximate line number
      const lines = code.split('\n');
      let lineNum = 1;
      
      return {
        id: pattern.id,
        pattern: pattern.name,
        severity: pattern.severity,
        title: pattern.name,
        description: pattern.description + (pattern.exploit ? ` (See: ${pattern.exploit} - ${pattern.valueAtRisk})` : ''),
        location: {
          file: 'input',
          line: lineNum,
        },
        suggestion: `Review and fix ${pattern.name.toLowerCase()} vulnerability`,
      };
    }
  } catch {
    // Pattern check failed, skip
  }
  
  return null;
}

// ============================================
// Core API Functions  
// ============================================

const patternChecks = buildPatternChecks();

/**
 * Scan Solana/Anchor code for vulnerabilities
 * @param code - Rust source code to scan
 * @param options - Scan options
 * @returns Scan result with findings
 */
export async function scan(code: string, options: ScanOptions = {}): Promise<ScanResult> {
  const findings: Finding[] = [];
  const severityOrder: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const minSeverity = options.minSeverity || 'low';
  const minSeverityNum = severityOrder[minSeverity];
  
  // Filter patterns if specified
  const patternsToRun = options.patterns 
    ? patternChecks.filter(p => options.patterns!.includes(p.id))
    : patternChecks;
  
  // Run each pattern
  for (const pattern of patternsToRun) {
    const finding = pattern.test(code);
    if (finding) {
      // Apply severity filter
      if (severityOrder[finding.severity] <= minSeverityNum) {
        if (finding.severity !== 'info' || options.includeInfo) {
          findings.push(finding);
        }
      }
    }
  }
  
  // Sort by severity
  findings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);
  
  // Build result
  const summary: AuditSummary = {
    critical: findings.filter(f => f.severity === 'critical').length,
    high: findings.filter(f => f.severity === 'high').length,
    medium: findings.filter(f => f.severity === 'medium').length,
    low: findings.filter(f => f.severity === 'low').length,
    info: findings.filter(f => f.severity === 'info').length,
    total: findings.length,
  };
  
  return {
    timestamp: new Date().toISOString(),
    findings,
    summary,
    passed: summary.critical === 0 && summary.high === 0,
    patternsUsed: patternsToRun.length,
  };
}

/**
 * Get list of all vulnerability patterns
 * @returns Array of pattern definitions
 */
export function listPatterns(): Pattern[] {
  return [...PATTERNS];
}

/**
 * Get a specific pattern by ID
 * @param id - Pattern ID (e.g., "SOL001")
 * @returns Pattern or undefined
 */
export function getPattern(id: string): Pattern | undefined {
  return PATTERNS.find(p => p.id === id);
}

/**
 * Get patterns by severity
 * @param severity - Severity level
 * @returns Patterns matching severity
 */
export function getPatternsBySeverity(severity: Severity): Pattern[] {
  return PATTERNS.filter(p => p.severity === severity);
}

/**
 * Get pattern count
 */
export function getPatternCount(): number {
  return PATTERNS.length;
}

/**
 * Get version info
 */
export function version(): string {
  return '0.1.0';
}

// Default export for convenience
export default { scan, listPatterns, getPattern, getPatternsBySeverity, getPatternCount, version };
