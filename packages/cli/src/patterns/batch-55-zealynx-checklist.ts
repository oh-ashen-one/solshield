import type { ParsedRust } from '../parsers/rust.js';

interface Finding {
  id: string;
  title: string;
  severity: string;
  category: string;
  description: string;
  recommendation: string;
  line?: number;
  code?: string;
}

/**
 * Batch 55 (Zealynx Checklist): 30 patterns from Zealynx Security Checklist + DEV.to 2025 Research
 * SOL7556-SOL7585
 * Sources: zealynx.io/blogs/solana-security-checklist, dev.to/4k_mira
 * Focus: Token-2022 extensions, CPI safety, account lifecycle, oracle manipulation, real exploits
 */

const PATTERNS = [
  { id: 'SOL7556', title: 'Stale Account Data After CPI', severity: 'high', category: 'state-management', pattern: /invoke_signed?\s*\([\s\S]{0,400}(?:\.amount|\.balance|\.data_len)/i, desc: 'Account data read after CPI may be stale — call reload() after any CPI that modifies accounts', rec: 'Call account.reload()? immediately after CPIs before reading fields.' },
  { id: 'SOL7557', title: 'Missing Reload After Token Transfer CPI', severity: 'high', category: 'token-operations', pattern: /token::transfer[\s\S]{0,300}\.amount/i, desc: 'Token account amount accessed after transfer CPI without reload — accounting mismatch', rec: 'Always reload token accounts after transfer CPIs.' },
  { id: 'SOL7558', title: 'Account Reallocation Without Zero Init', severity: 'medium', category: 'state-management', pattern: /realloc[\s\S]{0,50}zero_init\s*=\s*false/i, desc: 'Reallocation with zero_init=false may expose stale data in newly allocated space', rec: 'Set zero_init = true when account size may increase after a decrease in same tx.' },
  { id: 'SOL7559', title: 'Duplicate Mutable Account Attack', severity: 'high', category: 'account-validation', pattern: /#\[account\(mut\)\]\s*pub\s+\w+[\s\S]{0,200}#\[account\(mut\)\]\s*pub\s+\w+/i, desc: 'Two mutable accounts without uniqueness constraint — same account can be passed twice for double-counting', rec: 'Add constraint: account_a.key() != account_b.key().' },
  { id: 'SOL7560', title: 'User Wallet Signer Forwarded in CPI', severity: 'critical', category: 'cpi-security', pattern: /invoke\w*\s*\([\s\S]{0,300}user[\s\S]{0,100}is_signer:\s*true/i, desc: 'Forwarding user wallet as signer to untrusted CPI enables "steal the wallet" attack', rec: 'Use protocol PDAs as CPI authorities instead of forwarding user wallets.' },
  { id: 'SOL7561', title: 'Account Closed Without Data Zeroing', severity: 'high', category: 'state-management', pattern: /lamports\s*=\s*0[\s\S]{0,200}(?!sol_memset|fill\(0\)|CLOSED_ACCOUNT)/i, desc: 'Account closed by zeroing lamports but data not zeroed — revival attack possible', rec: 'Zero all data and set CLOSED_ACCOUNT_DISCRIMINATOR before transferring lamports.' },
  { id: 'SOL7562', title: 'Token-2022 Transfer Hook Bypass', severity: 'critical', category: 'token-2022', pattern: /spl_token::instruction::transfer\b[\s\S]{0,200}token.?2022/i, desc: 'Legacy SPL Token transfer used with Token-2022 bypasses transfer hooks', rec: 'Use transfer_checked from Token-2022 program for tokens with extensions.' },
  { id: 'SOL7563', title: 'Token-2022 Close Authority Not Validated', severity: 'high', category: 'token-2022', pattern: /mint[\s\S]{0,200}token.?2022[\s\S]{0,200}(?!close_authority|MintCloseAuthority)/i, desc: 'Token-2022 mint accepted without checking close authority extension — mint can be closed', rec: 'Check for MintCloseAuthority extension. Reject mints with close authority unless trusted.' },
  { id: 'SOL7564', title: 'Token-2022 Permanent Delegate Unchecked', severity: 'high', category: 'token-2022', pattern: /deposit|collateral|stake[\s\S]{0,300}token.?2022[\s\S]{0,200}(?!permanent_delegate|PermanentDelegate)/i, desc: 'Token-2022 permanent delegate can drain any holders tokens at any time', rec: 'Check PermanentDelegate extension. Reject in lending/staking/escrow contexts.' },
  { id: 'SOL7565', title: 'Token-2022 Transfer Fee Unaccounted', severity: 'high', category: 'token-2022', pattern: /transfer_checked[\s\S]{0,200}amount[\s\S]{0,100}(?!fee|TransferFee)/i, desc: 'Transfer amount used without accounting for Token-2022 transfer fee — accounting mismatch', rec: 'Query TransferFeeConfig extension to calculate actual received amount after fees.' },
  { id: 'SOL7566', title: 'Unrestricted Protocol Initialization', severity: 'critical', category: 'access-control', pattern: /pub\s+fn\s+initialize[\s\S]{0,500}(?!upgrade_authority|deployer|ADMIN_PUBKEY)/i, desc: 'Initialize callable by anyone — attacker can front-run deployment with malicious params', rec: 'Restrict to program upgrade authority or hardcoded deployer pubkey.' },
  { id: 'SOL7567', title: 'Single-Step Authority Transfer', severity: 'medium', category: 'access-control', pattern: /authority\s*=\s*new_authority[\s\S]{0,50}(?!pending|nominee|accept)/i, desc: 'Direct authority transfer risks permanent lockout if wrong address specified', rec: 'Implement two-step: nominate_authority() then accept_authority().' },
  { id: 'SOL7568', title: 'Arithmetic Overflow in Release Build', severity: 'critical', category: 'math-precision', pattern: /(?:amount|price|balance|supply|rate)\s*[\*\+\-][\s\S]{0,50}(?!checked_|saturating_)/i, desc: 'Rust release builds silently wrap on integer overflow — u64 multiplication can wrap to tiny values', rec: 'Use checked_mul(), checked_add(), etc. Or enable overflow-checks = true in Cargo.toml.' },
  { id: 'SOL7569', title: 'PDA Seed Without User Differentiation', severity: 'high', category: 'pda-security', pattern: /seeds\s*=\s*\[\s*b"[\w]+"\s*\]\s*(?!.*\.key\(\))/i, desc: 'PDA with only static seeds is shared across all users — state collision', rec: 'Include user pubkey in seeds: seeds = [b"user_state", user.key().as_ref()].' },
  { id: 'SOL7570', title: 'Custodial Key Storage (DEXX $30M Pattern)', severity: 'critical', category: 'key-management', pattern: /private_key|secret_key|keypair[\s\S]{0,100}(?:store|save|database|redis|server)/i, desc: 'DEXX hack ($30M, 9000+ wallets) — storing private keys server-side is a single point of failure', rec: 'Never store user private keys. Use non-custodial arch or HSMs/MPC threshold signing.' },
  { id: 'SOL7571', title: 'Cross-Chain Bridge Message Insufficient Validation', severity: 'critical', category: 'bridge-security', pattern: /bridge[\s\S]{0,200}(?:message|payload)[\s\S]{0,200}(?!verify_source|validate_chain|guardian)/i, desc: 'NoOnes exploit ($8M, Jan 2025) — bridge messages without full source validation enable forgery', rec: 'Validate source chain ID, sender contract, guardian signatures, and message nonce.' },
  { id: 'SOL7572', title: 'Nested Account Validation Root Bypass (Cashio $48M)', severity: 'critical', category: 'account-validation', pattern: /collateral[\s\S]{0,200}(?:mint|crate)[\s\S]{0,100}(?!root|verified_mint|hardcoded)/i, desc: 'Cashio ($48M) — validated chain of account refs but not the root, allowing fake root injection', rec: 'Validate ENTIRE chain including root. Use hardcoded known-good root addresses.' },
  { id: 'SOL7573', title: 'Single-Source AMM Oracle (Solend $1.26M)', severity: 'critical', category: 'oracle-security', pattern: /price[\s\S]{0,100}(?:pool|reserve|amm)[\s\S]{0,100}(?!twap|median|aggregate|pyth|switchboard)/i, desc: 'Solend/USDH exploit ($1.26M) — single AMM pool oracle trivially manipulated with capital', rec: 'Use TWAP over multiple blocks. Aggregate from multiple sources (Pyth, Switchboard, multiple DEXes).' },
  { id: 'SOL7574', title: 'Account Substitution Without Constraint', severity: 'high', category: 'account-validation', pattern: /Account<'info,\s*\w+>\s*,[\s\S]{0,100}(?!has_one|constraint|seeds|address\s*=)/i, desc: 'Typed account without has_one/address constraint — attacker can substitute valid but wrong account', rec: 'Use has_one constraints to bind accounts to parent: #[account(has_one = vault)].' },
  { id: 'SOL7575', title: 'CPI Return Data Source Not Verified', severity: 'medium', category: 'cpi-security', pattern: /get_return_data[\s\S]{0,200}(?!program_id|verify)/i, desc: 'CPI return data read without verifying source program ID — malicious prior instruction can set it', rec: 'Verify program_id from sol_get_return_data() matches expected callee.' },
  { id: 'SOL7576', title: 'Token-2022 Non-Transferable Extension Ignored', severity: 'medium', category: 'token-2022', pattern: /(?:collateral|escrow|transfer)[\s\S]{0,200}token.?2022[\s\S]{0,200}(?!non_transferable|NonTransferable)/i, desc: 'Non-transferable (soulbound) Token-2022 tokens cause stuck positions if not checked', rec: 'Check for NonTransferable extension before accepting as collateral or transferring.' },
  { id: 'SOL7577', title: 'Token-2022 Confidential Transfer Hidden Balance', severity: 'high', category: 'token-2022', pattern: /\.amount[\s\S]{0,100}token.?2022[\s\S]{0,100}(?!confidential|decrypt)/i, desc: 'Confidential transfers encrypt balances — .amount shows 0, bypassing balance checks', rec: 'Check ConfidentialTransferMint extension. Reject or use decryption flow for actual balances.' },
  { id: 'SOL7578', title: 'Token-2022 Interest-Bearing Token Mispriced', severity: 'medium', category: 'token-2022', pattern: /\.amount[\s\S]{0,100}interest.?bearing/i, desc: 'Interest-bearing tokens have virtual accruing balance — raw .amount undervalues positions', rec: 'Use amount_to_ui_amount() for interest-adjusted balance in pricing.' },
  { id: 'SOL7579', title: 'Arbitrary Program in CPI Target', severity: 'critical', category: 'cpi-security', pattern: /invoke\w*\s*\(\s*[\s\S]{0,100}(?:AccountInfo|UncheckedAccount)[\s\S]{0,100}(?!\.key\(\)\s*==|program_id)/i, desc: 'CPI to user-supplied program ID without verification — attacker substitutes malicious program', rec: 'Assert target program key matches expected ID. Use Anchor Program<T> for auto-validation.' },
  { id: 'SOL7580', title: 'Guardian Verification Bypass (Wormhole $326M)', severity: 'critical', category: 'bridge-security', pattern: /(?:guardian|verify_signatures)[\s\S]{0,200}(?:deprecated|legacy|secp256k1_program)/i, desc: 'Wormhole ($326M) — deprecated verify_signatures call bypassed guardian set validation', rec: 'Use current, audited verification. For bridges, verify active guardian set with proper quorum.' },
  { id: 'SOL7581', title: 'CLMM Tick Account Spoofing (Crema $8.8M)', severity: 'critical', category: 'defi-security', pattern: /tick[\s\S]{0,200}(?:AccountInfo|UncheckedAccount)[\s\S]{0,200}(?!seeds|constraint|owner)/i, desc: 'Crema ($8.8M) — fake tick accounts with fabricated price data accepted without PDA verification', rec: 'Derive tick accounts as PDAs from pool + tick index. Verify derivation matches passed account.' },
  { id: 'SOL7582', title: 'Perp Oracle Manipulation (Mango $115M)', severity: 'critical', category: 'oracle-security', pattern: /unrealized_pnl|perp[\s\S]{0,200}(?:collateral|borrow|margin)[\s\S]{0,100}(?!liquidity_check|depth)/i, desc: 'Mango ($115M) — thin-liquidity perp market manipulated to inflate unrealized PnL as collateral', rec: 'Weight collateral by market liquidity depth. Use time-delayed prices. Cap volatile position borrowing.' },
  { id: 'SOL7583', title: 'Flash Loan + Liquidation Combo Attack', severity: 'high', category: 'defi-security', pattern: /flash_loan[\s\S]{0,500}liquidat/i, desc: 'Flash loans enable zero-capital oracle manipulation + liquidation extraction in single tx', rec: 'Prevent flash loan and liquidation in same tx. Use TWAP oracles resistant to single-slot manipulation.' },
  { id: 'SOL7584', title: 'Account Re-Initialization Vulnerability', severity: 'critical', category: 'state-management', pattern: /pub\s+fn\s+initialize[\s\S]{0,500}(?!is_initialized|init\s*,|discriminator)/i, desc: 'Initialize callable multiple times can reset admin, clear balances, or change config', rec: 'Use Anchor init constraint (succeeds once). For native, check is_initialized flag.' },
  { id: 'SOL7585', title: 'User-Provided PDA Bump Seed', severity: 'medium', category: 'pda-security', pattern: /bump\s*:\s*(?:ctx\.accounts|args|instruction)[\s\S]{0,100}(?!canonical|find_program_address)/i, desc: 'Non-canonical bumps create different PDAs, enabling duplicate accounts or uniqueness bypass', rec: 'Always derive canonical bumps via find_program_address(). Never accept bumps from instruction args.' },
];

export function checkBatch55ZealynxPatterns(input: { content: string; parsed?: ParsedRust }): Finding[] {
  const findings: Finding[] = [];
  const content = input.content;

  for (const p of PATTERNS) {
    const match = p.pattern.exec(content);
    if (match) {
      findings.push({
        id: p.id,
        title: p.title,
        severity: p.severity,
        category: p.category,
        description: p.desc,
        recommendation: p.rec,
        line: content.substring(0, match.index).split('\n').length,
        code: match[0].substring(0, 200),
      });
    }
  }

  return findings;
}
