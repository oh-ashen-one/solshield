import Link from 'next/link';

export default function ApiDocs() {
  return (
    <div className="min-h-screen bg-gradient-to-b from-zinc-900 to-black text-white">
      {/* Header */}
      <header className="border-b border-zinc-800">
        <div className="max-w-6xl mx-auto px-4 py-3 flex items-center justify-between">
          <Link href="/" className="flex items-center gap-2">
            <span className="text-xl md:text-2xl">🛡️</span>
            <span className="text-lg md:text-xl font-bold">SolShield</span>
          </Link>
          <nav className="hidden md:flex items-center gap-6">
            <Link href="/" className="text-zinc-400 hover:text-white transition">Home</Link>
            <Link href="/patterns" className="text-zinc-400 hover:text-white transition">Patterns</Link>
            <Link href="/api" className="text-white font-medium">SDK</Link>
            <a 
              href="https://github.com/oh-ashen-one/solshield" 
              target="_blank" 
              rel="noopener noreferrer"
              className="text-zinc-400 hover:text-white transition"
            >
              GitHub
            </a>
          </nav>
          <nav className="flex md:hidden items-center gap-3 text-sm">
            <Link href="/" className="text-zinc-400 hover:text-white">Home</Link>
            <Link href="/api" className="text-white font-medium">SDK</Link>
          </nav>
        </div>
      </header>

      <main className="max-w-4xl mx-auto px-4 py-12">
        <h1 className="text-4xl font-bold mb-2">SDK Documentation</h1>
        <p className="text-zinc-400 mb-8">Install and use SolShield in your JavaScript/TypeScript projects</p>

        {/* Quick Stats */}
        <div className="grid grid-cols-3 gap-4 mb-8">
          <div className="bg-emerald-500/10 border border-emerald-500/20 rounded-lg p-4 text-center">
            <div className="text-2xl font-bold text-emerald-400">150</div>
            <div className="text-sm text-zinc-400">Patterns</div>
          </div>
          <div className="bg-blue-500/10 border border-blue-500/20 rounded-lg p-4 text-center">
            <div className="text-2xl font-bold text-blue-400">Free</div>
            <div className="text-sm text-zinc-400">Open Source</div>
          </div>
          <div className="bg-purple-500/10 border border-purple-500/20 rounded-lg p-4 text-center">
            <div className="text-2xl font-bold text-purple-400">TS</div>
            <div className="text-sm text-zinc-400">Full Types</div>
          </div>
        </div>

        <div className="space-y-8">
          {/* Installation */}
          <section className="bg-zinc-800/50 rounded-xl p-6 border border-zinc-700">
            <h2 className="text-xl font-semibold mb-4">Installation</h2>
            <pre className="bg-zinc-900 px-4 py-3 rounded-lg text-cyan-400 block overflow-x-auto">
npm install solshield
            </pre>
            <a 
              href="https://www.npmjs.com/package/solshield"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-block mt-3 text-sm text-zinc-400 hover:text-white transition"
            >
              View on npm →
            </a>
          </section>

          {/* Quick Start */}
          <section className="bg-zinc-800/50 rounded-xl p-6 border border-zinc-700">
            <h2 className="text-xl font-semibold mb-4">Quick Start</h2>
            <pre className="bg-zinc-900 p-4 rounded-lg overflow-x-auto text-sm border border-zinc-700">
{`import { scan } from 'solshield';

const result = await scan(\`
  pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    vault.balance = vault.balance - amount;  // No overflow check!
    Ok(())
  }
\`);

console.log(result.summary);
// { critical: 0, high: 1, medium: 0, low: 0, info: 0, total: 1 }

console.log(result.passed);
// false (has high severity finding)`}
            </pre>
          </section>

          {/* API Reference */}
          <section className="bg-zinc-800/50 rounded-xl p-6 border border-zinc-700">
            <h2 className="text-xl font-semibold mb-4">API Reference</h2>
            
            <div className="space-y-6">
              <div>
                <h3 className="font-mono text-lg text-emerald-400 mb-2">scan(code, options?)</h3>
                <p className="text-zinc-300 mb-3">Scan Solana/Anchor code for vulnerabilities.</p>
                <pre className="bg-zinc-900 p-4 rounded-lg overflow-x-auto text-sm border border-zinc-700">
{`const result = await scan(code, {
  patterns: ['SOL001', 'SOL002'],  // Only run specific patterns
  minSeverity: 'high',             // Minimum severity to report
  includeInfo: false,              // Include info-level findings
});`}
                </pre>
              </div>

              <div>
                <h3 className="font-mono text-lg text-emerald-400 mb-2">listPatterns()</h3>
                <p className="text-zinc-300 mb-3">Get all 150 vulnerability patterns.</p>
                <pre className="bg-zinc-900 p-4 rounded-lg overflow-x-auto text-sm border border-zinc-700">
{`import { listPatterns } from 'solshield';

const patterns = listPatterns();
console.log(patterns.length); // 150`}
                </pre>
              </div>

              <div>
                <h3 className="font-mono text-lg text-emerald-400 mb-2">getPattern(id)</h3>
                <p className="text-zinc-300 mb-3">Get a specific pattern by ID.</p>
                <pre className="bg-zinc-900 p-4 rounded-lg overflow-x-auto text-sm border border-zinc-700">
{`import { getPattern } from 'solshield';

const pattern = getPattern('SOL001');
// { id: 'SOL001', name: 'Missing Owner Check', severity: 'critical', ... }`}
                </pre>
              </div>
            </div>
          </section>

          {/* Response Types */}
          <section className="bg-zinc-800/50 rounded-xl p-6 border border-zinc-700">
            <h2 className="text-xl font-semibold mb-4">Response Types</h2>
            <pre className="bg-zinc-900 p-4 rounded-lg overflow-x-auto text-sm border border-zinc-700">
{`interface ScanResult {
  timestamp: string;
  findings: Finding[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    total: number;
  };
  passed: boolean;      // True if no critical/high findings
  patternsUsed: number;
}

interface Finding {
  id: string;           // Pattern ID (e.g., SOL001)
  pattern: string;      // Pattern name
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  location: { file: string; line?: number };
  suggestion?: string;
}`}
            </pre>
          </section>

          {/* Use Cases */}
          <section className="bg-zinc-800/50 rounded-xl p-6 border border-zinc-700">
            <h2 className="text-xl font-semibold mb-4">Use Cases</h2>
            
            <div className="space-y-6">
              <div>
                <h3 className="font-semibold text-zinc-200 mb-2">CI/CD Integration</h3>
                <pre className="bg-zinc-900 p-4 rounded-lg overflow-x-auto text-sm border border-zinc-700">
{`import { scan } from 'solshield';
import { readFileSync } from 'fs';

const code = readFileSync('./programs/my_program/src/lib.rs', 'utf8');
const result = await scan(code);

if (!result.passed) {
  console.error('Security audit failed!');
  console.error(result.findings);
  process.exit(1);
}`}
                </pre>
              </div>

              <div>
                <h3 className="font-semibold text-zinc-200 mb-2">IDE/Editor Extension</h3>
                <pre className="bg-zinc-900 p-4 rounded-lg overflow-x-auto text-sm border border-zinc-700">
{`import { scan } from 'solshield';

async function onDocumentChange(code: string) {
  const { findings } = await scan(code, { minSeverity: 'medium' });
  
  return findings.map(f => ({
    line: f.location.line,
    message: \`[\${f.id}] \${f.title}\`,
    severity: f.severity,
  }));
}`}
                </pre>
              </div>
            </div>
          </section>

          {/* Severity Levels */}
          <section className="bg-zinc-800/50 rounded-xl p-6 border border-zinc-700">
            <h2 className="text-xl font-semibold mb-4">Severity Levels</h2>
            <div className="space-y-3">
              <div className="flex items-center gap-3">
                <span className="w-20 text-center px-2 py-1 bg-red-500/20 text-red-400 rounded text-sm font-medium">critical</span>
                <span className="text-zinc-300">Immediate exploit risk, potential fund loss</span>
              </div>
              <div className="flex items-center gap-3">
                <span className="w-20 text-center px-2 py-1 bg-orange-500/20 text-orange-400 rounded text-sm font-medium">high</span>
                <span className="text-zinc-300">Significant vulnerability, exploitation likely</span>
              </div>
              <div className="flex items-center gap-3">
                <span className="w-20 text-center px-2 py-1 bg-yellow-500/20 text-yellow-400 rounded text-sm font-medium">medium</span>
                <span className="text-zinc-300">Potential issue under specific conditions</span>
              </div>
              <div className="flex items-center gap-3">
                <span className="w-20 text-center px-2 py-1 bg-blue-500/20 text-blue-400 rounded text-sm font-medium">low</span>
                <span className="text-zinc-300">Best practice violation, minimal risk</span>
              </div>
              <div className="flex items-center gap-3">
                <span className="w-20 text-center px-2 py-1 bg-zinc-500/20 text-zinc-400 rounded text-sm font-medium">info</span>
                <span className="text-zinc-300">Informational finding, no security impact</span>
              </div>
            </div>
          </section>

          {/* Patterns Link */}
          <section className="bg-gradient-to-r from-emerald-500/10 to-cyan-500/10 rounded-xl p-6 border border-emerald-500/20">
            <h2 className="text-xl font-semibold mb-2">150 vulnerability patterns</h2>
            <p className="text-zinc-300 mb-4">
              SolShield detects vulnerabilities across core security, CPI, DeFi, NFT, token, 
              PDA, Anchor, and more categories.
            </p>
            <Link 
              href="/patterns" 
              className="inline-flex items-center gap-2 px-4 py-2 bg-emerald-500 hover:bg-emerald-600 text-black font-semibold rounded-lg transition"
            >
              View All Patterns →
            </Link>
          </section>
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-zinc-800 mt-16">
        <div className="max-w-6xl mx-auto px-4 py-8 text-center text-zinc-500 text-sm">
          <p>Built by <span className="text-emerald-400">Midir</span> 🐉 for the Solana Agent Hackathon 2026</p>
          <p className="mt-2">Open source • MIT License • Powered by Claude AI</p>
        </div>
      </footer>
    </div>
  );
}
