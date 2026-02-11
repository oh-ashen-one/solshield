'use client';

import { useState, useCallback, useEffect, useRef } from 'react';
import Link from 'next/link';
import { motion, useInView, AnimatePresence } from 'framer-motion';

// ============================================================
// TYPES & CONSTANTS
// ============================================================
type InputMode = 'github' | 'upload' | 'paste';

const KNOWN_AUDITED_PROTOCOLS = [
  'jupiter','kamino','marinade','orca','raydium','mango',
  'pyth','metaplex','sanctum','drift','phoenix','tensor','jito',
];

function isKnownAuditedProtocol(code: string, githubUrl: string): boolean {
  const combined = (code + ' ' + githubUrl).toLowerCase();
  return KNOWN_AUDITED_PROTOCOLS.some(p => combined.includes(p));
}

function isCpiWrapperFile(finding: any): boolean {
  const loc = finding.location?.file || finding.location?.path || '';
  return /cpi|wrapper|adapter|proxy/i.test(loc);
}

// ============================================================
// ANIMATION VARIANTS
// ============================================================
const fadeUp = {
  hidden: { opacity: 0, y: 40 },
  visible: { opacity: 1, y: 0, transition: { duration: 0.7 } },
} as const;

const staggerContainer = {
  hidden: {},
  visible: { transition: { staggerChildren: 0.12 } },
} as const;

const scaleIn = {
  hidden: { opacity: 0, scale: 0.9 },
  visible: { opacity: 1, scale: 1, transition: { duration: 0.5 } },
} as const;

// ============================================================
// ANIMATED COUNTER
// ============================================================
function Counter({ end, suffix = '', prefix = '', duration = 2 }: { end: number; suffix?: string; prefix?: string; duration?: number }) {
  const ref = useRef<HTMLSpanElement>(null);
  const inView = useInView(ref, { once: true, margin: '-50px' });
  const [count, setCount] = useState(0);

  useEffect(() => {
    if (!inView) return;
    let start = 0;
    const step = end / (duration * 60);
    const timer = setInterval(() => {
      start += step;
      if (start >= end) { setCount(end); clearInterval(timer); }
      else setCount(Math.floor(start));
    }, 1000 / 60);
    return () => clearInterval(timer);
  }, [inView, end, duration]);

  return <span ref={ref}>{prefix}{count.toLocaleString()}{suffix}</span>;
}

// ============================================================
// PARTICLE BACKGROUND
// ============================================================
function ParticleField() {
  return (
    <div className="fixed inset-0 overflow-hidden pointer-events-none z-0">
      {Array.from({ length: 30 }).map((_, i) => (
        <div
          key={i}
          className="particle"
          style={{
            left: `${Math.random() * 100}%`,
            animationDuration: `${8 + Math.random() * 12}s`,
            animationDelay: `${Math.random() * 10}s`,
            opacity: 0.3 + Math.random() * 0.4,
            width: `${1 + Math.random() * 2}px`,
            height: `${1 + Math.random() * 2}px`,
          }}
        />
      ))}
    </div>
  );
}

// ============================================================
// CODE SCANNER ANIMATION (Hero)
// ============================================================
const SCAN_CODE = [
  'use anchor_lang::prelude::*;',
  '',
  '#[program]',
  'pub mod token_vault {',
  '    use super::*;',
  '',
  '    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {',
  '        let vault = &mut ctx.accounts.vault;',
  '        // No authority check here!',
  '        vault.balance = vault.balance - amount;',
  '        **ctx.accounts.vault_account.try_borrow_mut_lamports()? -= amount;',
  '        Ok(())',
  '    }',
  '}',
];

const SCAN_FINDINGS = [
  { line: 8, text: '⚠ CRITICAL: Missing signer verification', color: 'text-red-400' },
  { line: 9, text: '⚠ HIGH: Integer overflow — use checked_sub', color: 'text-orange-400' },
  { line: 10, text: '⚠ HIGH: Unchecked lamport transfer', color: 'text-amber-400' },
];

function CodeScanner() {
  const [scanLine, setScanLine] = useState(0);
  const [findings, setFindings] = useState<typeof SCAN_FINDINGS>([]);

  useEffect(() => {
    let line = 0;
    const interval = setInterval(() => {
      line++;
      if (line > SCAN_CODE.length) {
        // Reset after pause
        setTimeout(() => { setScanLine(0); setFindings([]); }, 2000);
        clearInterval(interval);
        return;
      }
      setScanLine(line);
      const found = SCAN_FINDINGS.filter(f => f.line === line);
      if (found.length) setFindings(prev => [...prev, ...found]);
    }, 350);
    
    // Auto-restart
    const restart = setInterval(() => {
      setScanLine(0);
      setFindings([]);
    }, (SCAN_CODE.length + 1) * 350 + 3000);

    return () => { clearInterval(interval); clearInterval(restart); };
  }, []);

  return (
    <div className="relative rounded-xl overflow-hidden border border-zinc-800 bg-zinc-950/80 backdrop-blur">
      {/* Terminal header */}
      <div className="flex items-center gap-2 px-4 py-2.5 bg-zinc-900/80 border-b border-zinc-800">
        <div className="flex gap-1.5">
          <div className="w-3 h-3 rounded-full bg-red-500/70" />
          <div className="w-3 h-3 rounded-full bg-yellow-500/70" />
          <div className="w-3 h-3 rounded-full bg-green-500/70" />
        </div>
        <span className="ml-2 text-zinc-500 text-xs font-mono">solshield scan — token_vault.rs</span>
      </div>
      
      <div className="relative p-4 font-mono text-sm leading-relaxed">
        {/* Scan line glow */}
        {scanLine > 0 && scanLine <= SCAN_CODE.length && (
          <div
            className="absolute left-0 right-0 h-6 bg-cyan-500/5 border-l-2 border-cyan-400 transition-all duration-300"
            style={{ top: `${(scanLine - 1) * 24 + 16}px` }}
          />
        )}
        
        {SCAN_CODE.map((line, i) => (
          <div
            key={i}
            className={`flex gap-3 h-6 transition-opacity duration-300 ${
              i < scanLine ? 'opacity-100' : 'opacity-30'
            }`}
          >
            <span className="text-zinc-600 w-6 text-right select-none text-xs leading-6">{i + 1}</span>
            <span className={`${
              line.includes('// No authority') ? 'text-red-400/80' :
              line.includes('balance - amount') ? 'text-orange-400/80' :
              line.includes('use anchor') ? 'text-cyan-400' :
              line.includes('#[program]') ? 'text-purple-400' :
              line.includes('pub fn') || line.includes('pub mod') ? 'text-blue-400' :
              'text-zinc-300'
            }`}>{line}</span>
          </div>
        ))}
        
        {/* Findings pop-ups */}
        <AnimatePresence>
          {findings.map((f, i) => (
            <motion.div
              key={f.line}
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              className={`absolute right-4 ${f.color} text-xs font-semibold bg-zinc-900/90 px-3 py-1 rounded-lg border border-zinc-700`}
              style={{ top: `${(f.line - 1) * 24 + 16}px` }}
            >
              {f.text}
            </motion.div>
          ))}
        </AnimatePresence>
      </div>
    </div>
  );
}

// ============================================================
// LIVE TERMINAL ANIMATION
// ============================================================
const TERMINAL_LINES = [
  { text: '$ npx solshield audit ./programs/token-vault', color: 'text-green-400', delay: 0 },
  { text: '', color: '', delay: 600 },
  { text: '  ⟳ Scanning 14 files across 3 programs...', color: 'text-zinc-400', delay: 800 },
  { text: '', color: '', delay: 1000 },
  { text: '  ✗ CRITICAL  Missing signer check          SOL002  src/lib.rs:47', color: 'text-red-400', delay: 1500 },
  { text: '  ✗ HIGH      Integer overflow possible     SOL003  src/lib.rs:52', color: 'text-orange-400', delay: 2000 },
  { text: '  ✗ HIGH      Unchecked CPI invocation      SOL008  src/cpi.rs:19', color: 'text-orange-400', delay: 2400 },
  { text: '  ⚠ MEDIUM    Missing rent-exempt check     SOL015  src/init.rs:8', color: 'text-yellow-400', delay: 2800 },
  { text: '  ℹ LOW       Account not closed properly   SOL021  src/close.rs:3', color: 'text-blue-400', delay: 3100 },
  { text: '', color: '', delay: 3400 },
  { text: '  ────────────────────────────────────────────────────', color: 'text-zinc-700', delay: 3500 },
  { text: '  Found 5 issues (1 critical, 2 high, 1 medium, 1 low)', color: 'text-white', delay: 3700 },
  { text: '  Scanned in 0.47s • 7,142 patterns checked', color: 'text-zinc-500', delay: 4000 },
  { text: '', color: '', delay: 4200 },
  { text: '  → Run `solshield audit --fix` for suggestions', color: 'text-cyan-400', delay: 4500 },
];

function LiveTerminal() {
  const [visibleLines, setVisibleLines] = useState(0);
  const ref = useRef<HTMLDivElement>(null);
  const inView = useInView(ref, { once: true, margin: '-100px' });

  useEffect(() => {
    if (!inView) return;
    TERMINAL_LINES.forEach((line, i) => {
      setTimeout(() => setVisibleLines(i + 1), line.delay);
    });
  }, [inView]);

  return (
    <div ref={ref} className="rounded-xl overflow-hidden border border-zinc-800 bg-zinc-950/80 backdrop-blur max-w-3xl mx-auto">
      <div className="flex items-center gap-2 px-4 py-2.5 bg-zinc-900/80 border-b border-zinc-800">
        <div className="flex gap-1.5">
          <div className="w-3 h-3 rounded-full bg-red-500/70" />
          <div className="w-3 h-3 rounded-full bg-yellow-500/70" />
          <div className="w-3 h-3 rounded-full bg-green-500/70" />
        </div>
        <span className="ml-2 text-zinc-500 text-xs font-mono">Terminal — solshield</span>
      </div>
      <div className="p-5 font-mono text-sm leading-relaxed min-h-[340px]">
        {TERMINAL_LINES.slice(0, visibleLines).map((line, i) => (
          <motion.div
            key={i}
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className={`${line.color} h-6`}
          >
            {line.text}
          </motion.div>
        ))}
        {visibleLines < TERMINAL_LINES.length && (
          <span className="inline-block w-2 h-4 bg-cyan-400 cursor-blink" />
        )}
      </div>
    </div>
  );
}

// ============================================================
// SECTION WRAPPER with scroll reveal
// ============================================================
function Section({ children, className = '', id }: { children: React.ReactNode; className?: string; id?: string }) {
  return (
    <motion.section
      id={id}
      initial="hidden"
      whileInView="visible"
      viewport={{ once: true, margin: '-80px' }}
      variants={fadeUp}
      className={className}
    >
      {children}
    </motion.section>
  );
}

// ============================================================
// MAIN PAGE
// ============================================================
export default function Home() {
  const [inputMode, setInputMode] = useState<InputMode>('github');
  const [code, setCode] = useState('');
  const [githubUrl, setGithubUrl] = useState('');
  const [files, setFiles] = useState<File[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [loadingStatus, setLoadingStatus] = useState('');
  const [result, setResult] = useState<any>(null);
  const [isDragging, setIsDragging] = useState(false);

  // ---- GitHub parsing (unchanged logic) ----
  const parseGitHubUrl = (url: string) => {
    const patterns = [
      /github\.com\/([^\/]+)\/([^\/]+)(?:\/tree\/([^\/]+))?(?:\/(.*))?/,
      /github\.com\/([^\/]+)\/([^\/]+)/,
    ];
    for (const pattern of patterns) {
      const match = url.match(pattern);
      if (match) return { owner: match[1], repo: match[2], branch: match[3] || 'main', path: match[4] || '' };
    }
    return null;
  };

  const fetchGitHubFiles = async (url: string): Promise<string> => {
    const parsed = parseGitHubUrl(url);
    if (!parsed) throw new Error('Invalid GitHub URL');
    setLoadingStatus(`Fetching from ${parsed.owner}/${parsed.repo}...`);
    const branchesToTry = parsed.branch !== 'main' ? [parsed.branch, 'main', 'master'] : ['main', 'master'];
    let data: any = null;
    let usedBranch = 'main';
    for (const branch of branchesToTry) {
      const apiUrl = `https://api.github.com/repos/${parsed.owner}/${parsed.repo}/git/trees/${branch}?recursive=1`;
      const response = await fetch(apiUrl);
      if (response.ok) { data = await response.json(); usedBranch = branch; break; }
    }
    if (!data) {
      const contentsUrl = `https://api.github.com/repos/${parsed.owner}/${parsed.repo}/contents/`;
      const response = await fetch(contentsUrl);
      if (!response.ok) throw new Error('Could not access repository. Make sure it\'s public and the URL is correct.');
      const commonPaths = ['programs', 'src', 'program/src', 'programs/src'];
      const fileContents: string[] = [];
      for (const dir of commonPaths) {
        try {
          const dirRes = await fetch(`https://api.github.com/repos/${parsed.owner}/${parsed.repo}/contents/${dir}`);
          if (dirRes.ok) {
            const items = await dirRes.json();
            const rsFiles = Array.isArray(items) ? items.filter((f: any) => f.name.endsWith('.rs')) : [];
            for (const file of rsFiles.slice(0, 5)) {
              const rawUrl = `https://raw.githubusercontent.com/${parsed.owner}/${parsed.repo}/HEAD/${file.path}`;
              const fileRes = await fetch(rawUrl);
              if (fileRes.ok) { const content = await fileRes.text(); fileContents.push(`// ===== ${file.path} =====\n${content}`); }
            }
          }
        } catch { /* skip */ }
      }
      if (fileContents.length === 0) throw new Error('No Rust files found in repository');
      return fileContents.join('\n\n');
    }
    const rustFiles = data.tree?.filter((f: any) => f.path.endsWith('.rs') && f.type === 'blob') || [];
    if (rustFiles.length === 0) throw new Error('No Rust files found in repository');
    setLoadingStatus(`Found ${rustFiles.length} Rust files. Downloading...`);
    const filesToFetch = rustFiles.slice(0, 10);
    const fileContents: string[] = [];
    for (const file of filesToFetch) {
      setLoadingStatus(`Downloading ${file.path}...`);
      const rawUrl = `https://raw.githubusercontent.com/${parsed.owner}/${parsed.repo}/${usedBranch}/${file.path}`;
      const fileRes = await fetch(rawUrl);
      if (fileRes.ok) { const content = await fileRes.text(); fileContents.push(`// ===== ${file.path} =====\n${content}`); }
    }
    return fileContents.join('\n\n');
  };

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault(); setIsDragging(false);
    const droppedFiles = Array.from(e.dataTransfer.files).filter(f => f.name.endsWith('.rs') || f.name.endsWith('.toml'));
    if (droppedFiles.length > 0) { setFiles(droppedFiles); readFiles(droppedFiles); }
  }, []);

  const readFiles = async (fileList: File[]) => {
    const contents: string[] = [];
    for (const file of fileList) { const text = await file.text(); contents.push(`// ===== ${file.name} =====\n${text}`); }
    setCode(contents.join('\n\n'));
  };

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFiles = Array.from(e.target.files || []).filter(f => f.name.endsWith('.rs') || f.name.endsWith('.toml'));
    if (selectedFiles.length > 0) { setFiles(selectedFiles); readFiles(selectedFiles); }
  };

  const handleAudit = async (e: React.FormEvent) => {
    e.preventDefault(); setIsLoading(true); setResult(null); setLoadingStatus('');
    try {
      let codeToAudit = code;
      if (inputMode === 'github' && githubUrl) { codeToAudit = await fetchGitHubFiles(githubUrl); setCode(codeToAudit); }
      if (!codeToAudit.trim()) throw new Error('No code to audit');
      setLoadingStatus('Running security analysis...');
      const res = await fetch('/api/audit', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ code: codeToAudit }) });
      const data = await res.json();
      setResult(data);
    } catch (err: any) { setResult({ error: err.message || 'Failed to run audit' }); }
    finally { setIsLoading(false); setLoadingStatus(''); }
  };

  const loadExample = (type: 'vulnerable' | 'secure') => {
    setInputMode('paste');
    if (type === 'vulnerable') {
      setCode(`use anchor_lang::prelude::*;

declare_id!("Vuln111111111111111111111111111111111111111");

#[program]
pub mod vulnerable_vault {
    use super::*;

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        // Missing authority verification
        // Integer overflow possible
        vault.balance = vault.balance - amount;
        
        **ctx.accounts.vault_account.try_borrow_mut_lamports()? -= amount;
        **ctx.accounts.recipient.try_borrow_mut_lamports()? += amount;
        
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    
    /// CHECK: No signer constraint
    pub authority: AccountInfo<'info>,
    
    /// CHECK: Recipient
    #[account(mut)]
    pub recipient: AccountInfo<'info>,
    
    /// CHECK: Vault token account
    #[account(mut)]
    pub vault_account: AccountInfo<'info>,
}

#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub balance: u64,
}`);
    } else {
      setCode(`use anchor_lang::prelude::*;

declare_id!("Safe1111111111111111111111111111111111111111");

#[program]
pub mod secure_vault {
    use super::*;

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        require!(
            ctx.accounts.authority.key() == vault.authority,
            VaultError::Unauthorized
        );
        
        vault.balance = vault.balance
            .checked_sub(amount)
            .ok_or(VaultError::InsufficientFunds)?;
        
        **ctx.accounts.vault_account.try_borrow_mut_lamports()? -= amount;
        **ctx.accounts.recipient.try_borrow_mut_lamports()? += amount;
        
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    
    pub authority: Signer<'info>,
    
    /// CHECK: Recipient
    #[account(mut)]
    pub recipient: AccountInfo<'info>,
    
    /// CHECK: Vault token account
    #[account(mut)]
    pub vault_account: AccountInfo<'info>,
}

#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub balance: u64,
}

#[error_code]
pub enum VaultError {
    #[msg("Unauthorized")]
    Unauthorized,
    #[msg("Insufficient funds")]
    InsufficientFunds,
}`);
    }
  };

  // ============================================================
  // RENDER
  // ============================================================
  return (
    <div className="min-h-screen bg-[#0a0a0f] text-zinc-100 relative">
      <ParticleField />
      <div className="bg-grid-cyber fixed inset-0 pointer-events-none z-0" />

      {/* ===== NAV ===== */}
      <header className="border-b border-zinc-800/50 backdrop-blur-md bg-[#0a0a0f]/70 sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
          <Link href="/" className="flex items-center gap-3 group">
            <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-cyan-400 to-cyan-600 flex items-center justify-center relative">
              <svg className="w-5 h-5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
              </svg>
            </div>
            <span className="text-xl font-bold tracking-tight font-[family-name:var(--font-space)]">SolShield</span>
          </Link>

          <nav className="hidden md:flex items-center gap-8">
            <a href="https://www.npmjs.com/package/solshield" target="_blank" rel="noopener noreferrer" className="text-sm text-zinc-400 hover:text-cyan-400 transition-colors">npm</a>
            <a href="https://github.com/oh-ashen-one/solshield" target="_blank" rel="noopener noreferrer" className="text-sm text-zinc-400 hover:text-cyan-400 transition-colors flex items-center gap-1.5">
              <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg>
              GitHub
            </a>
            <Link href="/patterns" className="text-sm text-zinc-400 hover:text-cyan-400 transition-colors">Patterns</Link>
          </nav>

          <a href="#audit" className="hidden md:inline-flex px-5 py-2.5 btn-shimmer rounded-lg text-sm transition-all">
            Audit Now
          </a>
        </div>
      </header>

      {/* ===== HERO ===== */}
      <section className="relative overflow-hidden z-10">
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[1000px] h-[500px] bg-cyan-500/8 blur-[150px] rounded-full" />

        <div className="relative max-w-7xl mx-auto px-6 pt-20 pb-8">
          <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.6 }} className="text-center">
            <div className="inline-flex items-center gap-2 px-4 py-1.5 bg-cyan-500/10 border border-cyan-500/20 rounded-full text-cyan-400 text-sm font-medium mb-8">
              <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
              The seatbelt for vibe-coded crypto
            </div>

            <h1 className="text-5xl md:text-6xl lg:text-7xl font-bold tracking-tight mb-6 font-[family-name:var(--font-space)]">
              Security for
              <br />
              <span className="text-gradient-cyan">Vibe-Coded Solana Programs</span>
            </h1>

            <p className="text-xl text-zinc-400 max-w-2xl mx-auto mb-4">
              AI writes your code in seconds. SolShield catches what it missed.
              <br className="hidden sm:block" />
              7,000+ vulnerability patterns. Instant analysis. Always free.
            </p>

            <p className="text-zinc-600 text-lg mb-10 font-medium">Vibe code it. SolShield it. Ship it.</p>

            <div className="flex flex-col sm:flex-row items-center justify-center gap-4 mb-16">
              <a href="#audit" className="w-full sm:w-auto px-8 py-4 btn-shimmer rounded-xl text-base transition-all relative pulse-ring">
                Paste Your Code →
              </a>
              <a href="https://github.com/oh-ashen-one/solshield" target="_blank" rel="noopener noreferrer"
                className="w-full sm:w-auto px-8 py-4 border border-zinc-700 hover:border-cyan-500/50 hover:bg-cyan-500/5 rounded-xl transition-all flex items-center justify-center gap-2 text-zinc-300">
                <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 24 24"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg>
                View Source
              </a>
            </div>
          </motion.div>

          {/* Animated code scanner */}
          <motion.div initial={{ opacity: 0, y: 30 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.8, delay: 0.3 }}
            className="max-w-2xl mx-auto">
            <CodeScanner />
          </motion.div>
        </div>
      </section>

      {/* ===== SOCIAL PROOF BAR ===== */}
      <Section className="border-y border-zinc-800/50 bg-zinc-900/30 relative z-10">
        <div className="max-w-7xl mx-auto px-6 py-10">
          <motion.div variants={staggerContainer} initial="hidden" whileInView="visible" viewport={{ once: true }}
            className="grid grid-cols-2 md:grid-cols-5 gap-6 text-center">
            {[
              { val: 7000, suffix: '+', label: 'Patterns' },
              { val: 600, prefix: '$', suffix: 'M+', label: 'Exploits Covered' },
              { val: 1, prefix: '<', suffix: 's', label: 'Analysis Time' },
              { val: 100, suffix: '%', label: 'Free' },
              { val: 0, label: 'Built by AI', custom: 'Built by AI' },
            ].map((s, i) => (
              <motion.div key={i} variants={scaleIn} className="flex flex-col items-center">
                <div className="text-2xl md:text-3xl font-bold text-white font-[family-name:var(--font-space)]">
                  {s.custom || <Counter end={s.val} prefix={s.prefix} suffix={s.suffix} />}
                </div>
                <div className="text-xs text-zinc-500 mt-1">{s.label}</div>
              </motion.div>
            ))}
          </motion.div>
        </div>
      </Section>

      {/* ===== PROBLEM SECTION ===== */}
      <Section className="relative z-10">
        <div className="max-w-4xl mx-auto px-6 py-24 text-center">
          <h2 className="text-3xl md:text-4xl font-bold mb-6 font-[family-name:var(--font-space)]">
            Vibe Coding Changed Everything
          </h2>
          <p className="text-lg text-zinc-400 mb-10 max-w-2xl mx-auto leading-relaxed">
            AI writes Solana programs in minutes. Developers ship faster than ever.
            But AI doesn&apos;t think about security — it optimizes for &quot;it compiles.&quot;
            The result? Code that works perfectly... until someone drains it.
          </p>
          <div className="grid md:grid-cols-3 gap-6">
            {[
              { icon: '🤖', title: 'AI Writes Code', desc: 'Cursor, Copilot, ChatGPT — generating Anchor programs in seconds' },
              { icon: '🕳️', title: 'Nobody Checks Security', desc: 'Missing signer checks, integer overflows, unchecked CPIs ship to mainnet' },
              { icon: '🛡️', title: 'SolShield Fills the Gap', desc: '7,000+ patterns from real exploits catch what AI missed — instantly' },
            ].map((item, i) => (
              <motion.div key={i} variants={fadeUp}
                className="p-6 bg-zinc-900/50 border border-zinc-800 rounded-xl hover:border-cyan-500/20 transition-all glow-card">
                <div className="text-4xl mb-4">{item.icon}</div>
                <h3 className="text-lg font-semibold mb-2">{item.title}</h3>
                <p className="text-sm text-zinc-400">{item.desc}</p>
              </motion.div>
            ))}
          </div>
        </div>
      </Section>

      {/* ===== HOW IT WORKS ===== */}
      <Section className="relative z-10 border-t border-zinc-800/50">
        <div className="max-w-5xl mx-auto px-6 py-24">
          <h2 className="text-3xl md:text-4xl font-bold text-center mb-16 font-[family-name:var(--font-space)]">
            Three Steps to Ship Secure
          </h2>
          <motion.div variants={staggerContainer} initial="hidden" whileInView="visible" viewport={{ once: true }}
            className="grid md:grid-cols-3 gap-8">
            {[
              { step: '01', icon: '📋', title: 'Paste Code', desc: 'Drop your Anchor program, GitHub URL, or upload .rs files', color: 'from-cyan-500 to-blue-500' },
              { step: '02', icon: '⚡', title: 'Instant Scan', desc: '7,000+ patterns from Wormhole, Mango, Cashio & more run in <1s', color: 'from-purple-500 to-pink-500' },
              { step: '03', icon: '🚀', title: 'Ship Secure', desc: 'Get findings with severity, location, and fix suggestions', color: 'from-green-500 to-emerald-500' },
            ].map((s, i) => (
              <motion.div key={i} variants={fadeUp}
                className="relative p-8 bg-zinc-900/50 border border-zinc-800 rounded-2xl group hover:border-cyan-500/30 transition-all glow-card text-center">
                <div className={`inline-flex w-14 h-14 rounded-xl bg-gradient-to-br ${s.color} items-center justify-center text-2xl mb-5`}>
                  {s.icon}
                </div>
                <div className="text-xs font-mono text-cyan-400 mb-2">STEP {s.step}</div>
                <h3 className="text-xl font-bold mb-3">{s.title}</h3>
                <p className="text-sm text-zinc-400">{s.desc}</p>
              </motion.div>
            ))}
          </motion.div>
        </div>
      </Section>

      {/* ===== WHAT WE DETECT ===== */}
      <Section id="features" className="relative z-10 bg-zinc-900/20 border-t border-zinc-800/50">
        <div className="max-w-7xl mx-auto px-6 py-24">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold mb-4 font-[family-name:var(--font-space)]">What Your AI Missed</h2>
            <p className="text-zinc-400 max-w-2xl mx-auto">
              Every vulnerability class that&apos;s cost real money on Solana — checked in milliseconds.
            </p>
          </div>

          <motion.div variants={staggerContainer} initial="hidden" whileInView="visible" viewport={{ once: true }}
            className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4">
            {[
              { title: 'Missing Signer Checks', desc: 'Authority accounts without cryptographic verification — the #1 Solana exploit', severity: 'Critical' },
              { title: 'Owner Validation', desc: 'Accounts without proper ownership constraints allow spoofing', severity: 'Critical' },
              { title: 'Type Cosplay', desc: 'Missing discriminator validation lets attackers forge account data', severity: 'Critical' },
              { title: 'Closing Accounts', desc: 'Account revival attacks and rent theft from improper closing', severity: 'Critical' },
              { title: 'Integer Overflow', desc: 'Unchecked arithmetic that wraps around — leads to infinite mints', severity: 'High' },
              { title: 'PDA Validation', desc: 'Program Derived Addresses without bump seed verification', severity: 'High' },
              { title: 'CPI Vulnerabilities', desc: 'Cross-program invocations without proper program ID checks', severity: 'High' },
              { title: 'Account Confusion', desc: 'Swappable accounts of the same type enable privilege escalation', severity: 'High' },
              { title: 'Reentrancy', desc: 'State changes after cross-program calls create exploit windows', severity: 'High' },
            ].map((f, i) => (
              <motion.div key={i} variants={fadeUp}
                className="group p-5 bg-zinc-900/50 border border-zinc-800 rounded-xl hover:border-cyan-500/30 transition-all glow-card cursor-default">
                <div className="flex items-start justify-between mb-3">
                  <h3 className="font-semibold text-white">{f.title}</h3>
                  <span className={`text-xs px-2.5 py-1 rounded-full font-medium ${
                    f.severity === 'Critical' ? 'badge-critical' : 'badge-high'
                  }`}>{f.severity}</span>
                </div>
                <p className="text-sm text-zinc-400 leading-relaxed">{f.desc}</p>
              </motion.div>
            ))}
          </motion.div>

          <div className="text-center mt-10">
            <Link href="/patterns" className="inline-flex items-center gap-2 text-cyan-400 hover:text-cyan-300 transition-colors font-medium">
              View all 7,000+ patterns
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M13.5 4.5L21 12m0 0l-7.5 7.5M21 12H3" /></svg>
            </Link>
          </div>
        </div>
      </Section>

      {/* ===== LIVE TERMINAL DEMO ===== */}
      <Section className="relative z-10">
        <div className="max-w-5xl mx-auto px-6 py-24">
          <h2 className="text-3xl md:text-4xl font-bold text-center mb-4 font-[family-name:var(--font-space)]">
            See It In Action
          </h2>
          <p className="text-zinc-400 text-center mb-12 max-w-xl mx-auto">
            Watch SolShield tear through a Solana program and surface vulnerabilities in real time.
          </p>
          <LiveTerminal />
        </div>
      </Section>

      {/* ===== CLI SECTION ===== */}
      <Section className="relative z-10 border-t border-zinc-800/50">
        <div className="max-w-6xl mx-auto px-6 py-24">
          <div className="grid lg:grid-cols-2 gap-16 items-center">
            <div>
              <h2 className="text-3xl md:text-4xl font-bold mb-6 font-[family-name:var(--font-space)]">
                Built for the<br />AI-Coding Era
              </h2>
              <p className="text-zinc-400 mb-8 leading-relaxed">
                Drop SolShield into your workflow — CLI, CI/CD, or right here in the browser.
                Not replacing professional audits. We&apos;re the seatbelt before you drive.
              </p>

              {/* Install command */}
              <div className="flex items-center gap-3 px-5 py-3.5 bg-zinc-900 border border-zinc-800 rounded-xl mb-8 max-w-md">
                <span className="text-zinc-500">$</span>
                <code className="text-cyan-400 font-mono text-base flex-1">npm install solshield</code>
                <button onClick={() => navigator.clipboard.writeText('npm install solshield')}
                  className="p-1.5 hover:bg-zinc-800 rounded-lg transition-colors text-zinc-500 hover:text-white" title="Copy">
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                  </svg>
                </button>
              </div>

              <div className="space-y-4">
                {[
                  { icon: '🔍', text: 'Audit GitHub repos directly' },
                  { icon: '👁️', text: 'Watch mode — scan on every save' },
                  { icon: '🔄', text: 'CI/CD integration with SARIF output' },
                  { icon: '📋', text: 'GitHub PR security checks' },
                ].map((item, i) => (
                  <div key={i} className="flex items-center gap-3 text-zinc-300">
                    <span className="text-lg">{item.icon}</span>
                    <span>{item.text}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="rounded-xl overflow-hidden border border-zinc-800 bg-zinc-950/80">
              <div className="flex items-center gap-2 px-4 py-2.5 bg-zinc-900/80 border-b border-zinc-800">
                <div className="flex gap-1.5">
                  <div className="w-3 h-3 rounded-full bg-red-500/70" />
                  <div className="w-3 h-3 rounded-full bg-yellow-500/70" />
                  <div className="w-3 h-3 rounded-full bg-green-500/70" />
                </div>
                <span className="ml-2 text-zinc-500 text-xs font-mono">Terminal</span>
              </div>
              <pre className="p-5 text-sm text-zinc-300 font-mono overflow-x-auto leading-relaxed">
{`$ npx solshield audit ./my-program

  Scanning 12 files...

  `}<span className="text-red-400">✗ Critical: Missing signer check (SOL002)</span>{`
    └─ src/lib.rs:47

  `}<span className="text-orange-400">✗ High: Integer overflow possible (SOL003)</span>{`
    └─ src/lib.rs:52

  Found 2 issues (1 critical, 1 high)

`}<span className="text-cyan-400">$ npx solshield github coral-xyz/anchor</span>{`
  Cloning... Analyzing... Done!

`}<span className="text-cyan-400">$ npx solshield ci . --fail-on high</span>{`
  SARIF output: results.sarif`}
              </pre>
            </div>
          </div>
        </div>
      </Section>

      {/* ===== SCANNER / AUDIT SECTION ===== */}
      <Section id="audit" className="relative z-10 border-t border-zinc-800/50 bg-gradient-to-b from-zinc-900/30 to-transparent">
        <div className="max-w-4xl mx-auto px-6 py-24">
          <div className="text-center mb-12">
            <h2 className="text-3xl md:text-4xl font-bold mb-4 font-[family-name:var(--font-space)]">
              Audit Your Vibe Code
            </h2>
            <p className="text-zinc-400 text-lg">Paste what your AI wrote. See what it missed.</p>
          </div>

          {/* Input Mode Tabs */}
          <div className="flex items-center justify-center gap-1 p-1.5 bg-zinc-800/50 rounded-xl mb-8 max-w-md mx-auto border border-zinc-700/50">
            {([
              { id: 'github' as InputMode, label: 'GitHub URL', icon: <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg> },
              { id: 'upload' as InputMode, label: 'Upload', icon: <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" /></svg> },
              { id: 'paste' as InputMode, label: 'Paste Code', icon: <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" /></svg> },
            ]).map((tab) => (
              <button key={tab.id} onClick={() => setInputMode(tab.id)}
                className={`flex-1 flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg text-sm font-medium transition-all ${
                  inputMode === tab.id ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30' : 'text-zinc-400 hover:text-white'
                }`}>
                {tab.icon}
                <span className="hidden sm:inline">{tab.label}</span>
              </button>
            ))}
          </div>

          <form onSubmit={handleAudit} className="space-y-4">
            {/* GitHub URL Input */}
            {inputMode === 'github' && (
              <div className="space-y-3">
                <input type="url" value={githubUrl} onChange={(e) => setGithubUrl(e.target.value)}
                  placeholder="https://github.com/username/repo"
                  className="w-full px-5 py-4 bg-zinc-900/80 border border-zinc-700 rounded-xl text-white placeholder-zinc-500 font-mono transition-all" />
                <p className="text-xs text-zinc-500 px-1">Public repositories only. We&apos;ll scan all .rs files automatically.</p>
              </div>
            )}

            {/* File Upload */}
            {inputMode === 'upload' && (
              <div onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }} onDragLeave={() => setIsDragging(false)} onDrop={handleDrop}
                className={`relative border-2 border-dashed rounded-xl p-12 text-center transition-all ${
                  isDragging ? 'border-cyan-500 bg-cyan-500/5' : 'border-zinc-700 hover:border-zinc-600'
                }`}>
                <input type="file" accept=".rs,.toml" multiple onChange={handleFileSelect}
                  className="absolute inset-0 w-full h-full opacity-0 cursor-pointer" />
                <div className="flex flex-col items-center gap-3">
                  <div className="w-12 h-12 rounded-full bg-zinc-800 flex items-center justify-center">
                    <svg className="w-6 h-6 text-zinc-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5m-13.5-9L12 3m0 0l4.5 4.5M12 3v13.5" />
                    </svg>
                  </div>
                  <p className="text-zinc-300 font-medium">Drop .rs files here or click to browse</p>
                </div>
                {files.length > 0 && (
                  <div className="mt-6 flex flex-wrap gap-2 justify-center">
                    {files.map((f, i) => (
                      <span key={i} className="px-3 py-1.5 bg-zinc-800 rounded-lg text-sm text-zinc-300">{f.name}</span>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* Code Paste */}
            {inputMode === 'paste' && (
              <div className="space-y-3">
                <div className="flex items-center gap-2">
                  <span className="text-sm text-zinc-500">Load example:</span>
                  <button type="button" onClick={() => loadExample('vulnerable')}
                    className="px-3 py-1.5 text-sm bg-red-500/10 text-red-400 hover:bg-red-500/20 rounded-lg transition-colors border border-red-500/20">
                    Vulnerable
                  </button>
                  <button type="button" onClick={() => loadExample('secure')}
                    className="px-3 py-1.5 text-sm bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20 rounded-lg transition-colors border border-emerald-500/20">
                    Secure
                  </button>
                </div>
                <textarea value={code} onChange={(e) => setCode(e.target.value)}
                  placeholder="// Paste your Anchor program code here..."
                  className="w-full h-80 px-5 py-4 bg-zinc-900/80 border border-zinc-700 rounded-xl font-mono text-sm text-white placeholder-zinc-500 transition-all resize-none" />
              </div>
            )}

            {/* Submit */}
            <button type="submit" disabled={isLoading || (inputMode === 'github' ? !githubUrl.trim() : !code.trim())}
              className="w-full py-4 btn-shimmer disabled:bg-zinc-800 disabled:text-zinc-500 disabled:cursor-not-allowed disabled:animate-none disabled:bg-none rounded-xl transition-all flex items-center justify-center gap-3 text-base">
              {isLoading ? (
                <>
                  <svg className="animate-spin h-5 w-5" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                  </svg>
                  {loadingStatus || 'Analyzing...'}
                </>
              ) : (
                <>
                  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
                  </svg>
                  Run Security Audit
                </>
              )}
            </button>
          </form>

          {/* ===== RESULTS ===== */}
          {result && (
            <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}
              className="mt-10 p-6 bg-zinc-900/50 border border-zinc-800 rounded-2xl">
              {result.error ? (
                <div className="flex items-center gap-3 text-red-400">
                  <svg className="w-5 h-5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" />
                  </svg>
                  {result.error}
                </div>
              ) : (
                <>
                  {/* Disclaimer */}
                  <div className="mb-6 p-4 bg-amber-500/5 border border-amber-500/20 rounded-xl flex items-start gap-3">
                    <svg className="w-5 h-5 text-amber-400 mt-0.5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
                    </svg>
                    <p className="text-sm text-amber-200/80">
                      SolShield uses pattern-matching against known vulnerability signatures. Findings require manual review.
                    </p>
                  </div>

                  {isKnownAuditedProtocol(code, githubUrl) && (
                    <div className="mb-6 p-4 bg-emerald-500/5 border border-emerald-500/20 rounded-xl flex items-start gap-3">
                      <svg className="w-5 h-5 text-emerald-400 mt-0.5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
                      </svg>
                      <p className="text-sm text-emerald-300/90">
                        <span className="font-semibold text-emerald-400">Known Audited Protocol</span> — Findings are informational.
                      </p>
                    </div>
                  )}

                  <div className="flex items-center justify-between mb-8">
                    <h3 className="text-xl font-semibold font-[family-name:var(--font-space)]">Audit Results</h3>
                    <span className={`px-4 py-1.5 rounded-full text-sm font-medium ${
                      result.passed ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' : 'bg-red-500/10 text-red-400 border border-red-500/20'
                    }`}>
                      {result.passed ? 'No Issues Found' : 'Issues Detected'}
                    </span>
                  </div>

                  {result.contextMessages?.length > 0 && (
                    <div className="space-y-3 mb-8">
                      {result.contextMessages.map((msg: string, i: number) => (
                        <div key={i} className={`p-4 rounded-xl border text-sm ${
                          msg.startsWith('⚠️') ? 'bg-yellow-500/5 border-yellow-500/20 text-yellow-300' :
                          msg.startsWith('✅') ? 'bg-emerald-500/5 border-emerald-500/20 text-emerald-300' :
                          'bg-zinc-800/50 border-zinc-700 text-zinc-400'
                        }`}>{msg}</div>
                      ))}
                    </div>
                  )}

                  {/* Summary */}
                  <div className="grid grid-cols-5 gap-3 mb-8 p-4 bg-zinc-800/50 rounded-xl">
                    {[
                      { label: 'Critical', count: result.summary?.critical || 0, color: 'text-red-400', bg: 'bg-red-500/10' },
                      { label: 'High', count: result.summary?.high || 0, color: 'text-orange-400', bg: 'bg-orange-500/10' },
                      { label: 'Medium', count: result.summary?.medium || 0, color: 'text-yellow-400', bg: 'bg-yellow-500/10' },
                      { label: 'Low', count: result.summary?.low || 0, color: 'text-blue-400', bg: 'bg-blue-500/10' },
                      { label: 'Info', count: result.summary?.info || 0, color: 'text-zinc-400', bg: 'bg-zinc-500/10' },
                    ].map((s, i) => (
                      <div key={i} className={`text-center p-3 rounded-lg ${s.bg}`}>
                        <div className={`text-2xl font-bold ${s.color}`}>{s.count}</div>
                        <div className="text-zinc-400 text-xs mt-1">{s.label}</div>
                      </div>
                    ))}
                  </div>

                  {/* Findings */}
                  {result.findings?.length > 0 && (
                    <div className="space-y-4">
                      {result.findings.map((finding: any, i: number) => {
                        const lowConfidence = isCpiWrapperFile(finding);
                        return (
                          <div key={i} className={`p-5 bg-zinc-800/30 rounded-xl border-l-4 ${
                            lowConfidence ? 'border-zinc-500' :
                            finding.severity === 'critical' ? 'border-red-500' :
                            finding.severity === 'high' ? 'border-orange-500' :
                            finding.severity === 'medium' ? 'border-yellow-500' :
                            'border-blue-500'
                          }`}>
                            <div className="flex items-start justify-between gap-4">
                              <div className="flex items-center gap-3">
                                <span className={`px-2.5 py-1 rounded text-xs font-medium ${
                                  lowConfidence ? 'bg-zinc-500/10 text-zinc-400 border border-zinc-500/20' :
                                  finding.severity === 'critical' ? 'badge-critical' :
                                  finding.severity === 'high' ? 'badge-high' :
                                  finding.severity === 'medium' ? 'badge-medium' :
                                  'badge-low'
                                }`}>
                                  {lowConfidence ? 'LOW CONFIDENCE' : finding.severity?.toUpperCase()}
                                </span>
                                <code className="text-xs text-zinc-500 bg-zinc-800 px-2 py-0.5 rounded">{finding.id}</code>
                              </div>
                              {finding.location?.line && <span className="text-zinc-500 text-sm">Line {finding.location.line}</span>}
                            </div>
                            <h4 className="font-semibold mt-3 text-white">{finding.title}</h4>
                            <p className="text-zinc-400 text-sm mt-2 leading-relaxed">{finding.description}</p>
                            {finding.suggestion && (
                              <div className="mt-4 p-4 bg-emerald-500/5 border border-emerald-500/10 rounded-lg">
                                <div className="flex items-start gap-2">
                                  <svg className="w-4 h-4 text-emerald-400 mt-0.5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                    <path strokeLinecap="round" strokeLinejoin="round" d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
                                  </svg>
                                  <div>
                                    <span className="text-emerald-400 text-sm font-medium">Suggested Fix</span>
                                    <p className="text-zinc-300 text-sm mt-1">{finding.suggestion.split('\n')[0]}</p>
                                  </div>
                                </div>
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  )}
                </>
              )}
            </motion.div>
          )}
        </div>
      </Section>

      {/* ===== FOOTER ===== */}
      <footer className="border-t border-zinc-800/50 relative z-10">
        <div className="max-w-7xl mx-auto px-6 py-12">
          <div className="flex flex-col md:flex-row items-center justify-between gap-8">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-cyan-400 to-cyan-600 flex items-center justify-center">
                <svg className="w-5 h-5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
                </svg>
              </div>
              <span className="font-bold font-[family-name:var(--font-space)]">SolShield</span>
            </div>

            <p className="text-zinc-600 text-sm font-medium">Vibe code it. SolShield it. Ship it.</p>

            <div className="flex items-center gap-6 text-sm text-zinc-500">
              <a href="https://github.com/oh-ashen-one/solshield" target="_blank" rel="noopener noreferrer" className="hover:text-cyan-400 transition-colors">GitHub</a>
              <a href="https://www.npmjs.com/package/solshield" target="_blank" rel="noopener noreferrer" className="hover:text-cyan-400 transition-colors">npm</a>
              <a href="https://www.colosseum.org" target="_blank" rel="noopener noreferrer" className="hover:text-cyan-400 transition-colors">Colosseum Hackathon</a>
            </div>
          </div>
          <div className="mt-8 text-center text-xs text-zinc-700">
            Built for Solana Agent Hackathon 2026 • Built by AI, for the AI-coding era
          </div>
        </div>
      </footer>
    </div>
  );
}
