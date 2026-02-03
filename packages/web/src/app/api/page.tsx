export default function ApiDocs() {
  return (
    <div className="min-h-screen bg-gradient-to-b from-zinc-900 to-black text-white p-8">
      <div className="max-w-4xl mx-auto">
        <h1 className="text-4xl font-bold mb-2">🛡️ SolGuard API</h1>
        <p className="text-zinc-400 mb-8">Public API for AI agents and developers</p>

        <div className="space-y-8">
          {/* Audit Endpoint */}
          <section className="bg-zinc-800/50 rounded-xl p-6 border border-zinc-700">
            <div className="flex items-center gap-3 mb-4">
              <span className="px-3 py-1 bg-emerald-500 text-black text-sm font-bold rounded">POST</span>
              <code className="text-lg">/api/v1/audit</code>
            </div>
            
            <p className="text-zinc-300 mb-4">
              Audit Rust/Anchor smart contract code and receive vulnerability findings.
            </p>

            <h3 className="font-semibold mb-2">Request Body</h3>
            <pre className="bg-zinc-900 p-4 rounded-lg overflow-x-auto text-sm mb-4">
{`{
  "code": "use anchor_lang::prelude::*; ...",  // Required: Rust source code
  "format": "json",                            // Optional: "json" or "markdown"
  "ai": false                                  // Optional: Include AI explanations
}`}
            </pre>

            <h3 className="font-semibold mb-2">Response (Success)</h3>
            <pre className="bg-zinc-900 p-4 rounded-lg overflow-x-auto text-sm mb-4">
{`{
  "success": true,
  "passed": false,
  "timestamp": "2026-02-02T20:00:00.000Z",
  "summary": {
    "critical": 2,
    "high": 3,
    "medium": 1,
    "low": 0,
    "info": 0,
    "total": 6
  },
  "severityScore": 155,
  "findings": [
    {
      "id": "SOL002-1",
      "pattern": "Missing Signer Check",
      "severity": "critical",
      "title": "Authority account 'authority' is not a Signer",
      "description": "...",
      "location": { "file": "...", "line": 42 },
      "suggestion": "pub authority: Signer<'info>"
    }
  ],
  "executionTimeMs": 234,
  "apiVersion": "1.0.0"
}`}
            </pre>

            <h3 className="font-semibold mb-2">Example (curl)</h3>
            <pre className="bg-zinc-900 p-4 rounded-lg overflow-x-auto text-sm">
{`curl -X POST https://solguard.dev/api/v1/audit \\
  -H "Content-Type: application/json" \\
  -d '{"code": "use anchor_lang::prelude::*; ..."}'`}
            </pre>
          </section>

          {/* Health Check */}
          <section className="bg-zinc-800/50 rounded-xl p-6 border border-zinc-700">
            <div className="flex items-center gap-3 mb-4">
              <span className="px-3 py-1 bg-blue-500 text-white text-sm font-bold rounded">GET</span>
              <code className="text-lg">/api/v1/audit</code>
            </div>
            
            <p className="text-zinc-300 mb-4">
              Health check endpoint. Returns API status and version.
            </p>

            <pre className="bg-zinc-900 p-4 rounded-lg overflow-x-auto text-sm">
{`{
  "status": "ok",
  "service": "SolGuard Audit API",
  "version": "1.0.0"
}`}
            </pre>
          </section>

          {/* Rate Limits */}
          <section className="bg-zinc-800/50 rounded-xl p-6 border border-zinc-700">
            <h2 className="text-xl font-semibold mb-4">Rate Limits</h2>
            <ul className="space-y-2 text-zinc-300">
              <li>• 100 requests per minute per IP</li>
              <li>• Maximum code size: 500KB</li>
              <li>• Request timeout: 60 seconds</li>
            </ul>
          </section>

          {/* Patterns */}
          <section className="bg-zinc-800/50 rounded-xl p-6 border border-zinc-700">
            <h2 className="text-xl font-semibold mb-4">Vulnerability Patterns</h2>
            <div className="grid grid-cols-2 gap-4 text-sm">
              <div>
                <span className="text-red-400">SOL001</span> Missing Owner Check
              </div>
              <div>
                <span className="text-red-400">SOL002</span> Missing Signer Check
              </div>
              <div>
                <span className="text-orange-400">SOL003</span> Integer Overflow
              </div>
              <div>
                <span className="text-orange-400">SOL004</span> PDA Validation Gap
              </div>
              <div>
                <span className="text-red-400">SOL005</span> Authority Bypass
              </div>
              <div>
                <span className="text-red-400">SOL006</span> Missing Init Check
              </div>
              <div>
                <span className="text-orange-400">SOL007</span> CPI Vulnerability
              </div>
              <div>
                <span className="text-yellow-400">SOL008</span> Rounding Error
              </div>
              <div>
                <span className="text-orange-400">SOL009</span> Account Confusion
              </div>
              <div>
                <span className="text-red-400">SOL010</span> Closing Vulnerability
              </div>
            </div>
          </section>
        </div>

        <footer className="mt-12 text-center text-zinc-500 text-sm">
          <p>Built by Midir for the Solana Agent Hackathon 2026</p>
        </footer>
      </div>
    </div>
  );
}
