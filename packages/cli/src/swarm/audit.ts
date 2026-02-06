/**
 * Swarm Audit Entry Point
 * 
 * High-level API for running multi-agent security audits.
 * This is the main entry point for programmatic usage.
 */

import { SwarmOrchestrator, type SwarmConfig, type SwarmResult } from './orchestrator.js';
import { formatSynthesisAsMarkdown } from './synthesizer.js';
import type { AgentType } from './agents.js';

export interface SwarmAuditOptions {
  /** Path to file or directory to audit */
  target: string;
  
  /** Which specialists to use */
  specialists?: AgentType[];
  
  /** Execution mode */
  mode?: 'agent-teams' | 'api' | 'subprocess' | 'auto';
  
  /** Claude model to use */
  model?: string;
  
  /** Output directory for reports */
  outputDir?: string;
  
  /** Generate markdown report */
  markdown?: boolean;
  
  /** Verbose logging */
  verbose?: boolean;
}

export interface SwarmAuditResult extends SwarmResult {
  /** Markdown report if requested */
  markdownReport?: string;
}

/**
 * Run a multi-agent security audit
 * 
 * @example
 * ```typescript
 * import { swarmAudit } from '@solguard/cli/swarm';
 * 
 * const result = await swarmAudit({
 *   target: './programs/my-vault/src/lib.rs',
 *   specialists: ['reentrancy', 'access-control', 'arithmetic'],
 *   mode: 'api', // or 'agent-teams' if running in Claude Code
 *   verbose: true,
 * });
 * 
 * console.log(`Found ${result.findings.length} issues`);
 * console.log(result.markdownReport);
 * ```
 */
export async function swarmAudit(options: SwarmAuditOptions): Promise<SwarmAuditResult> {
  const config: SwarmConfig = {
    mode: options.mode || 'auto',
    specialists: options.specialists,
    model: options.model,
    outputDir: options.outputDir,
    verbose: options.verbose,
    useSynthesis: true,
  };

  const orchestrator = new SwarmOrchestrator(config);
  const result = await orchestrator.audit(options.target);

  // Generate markdown report if requested
  let markdownReport: string | undefined;
  if (options.markdown && result.synthesis) {
    markdownReport = formatSynthesisAsMarkdown(result.synthesis);
  }

  return {
    ...result,
    markdownReport,
  };
}

/**
 * Quick audit with default settings
 * 
 * @example
 * ```typescript
 * const findings = await quickAudit('./programs/vault/src/lib.rs');
 * if (findings.some(f => f.severity === 'critical')) {
 *   process.exit(1);
 * }
 * ```
 */
export async function quickAudit(target: string) {
  const result = await swarmAudit({
    target,
    mode: 'auto',
    verbose: false,
  });
  
  return result.findings;
}

/**
 * CLI command handler for swarm audit
 * 
 * Usage: solguard swarm <path> [options]
 */
export async function swarmCommand(args: string[]): Promise<void> {
  const target = args[0];
  
  if (!target) {
    console.error('Usage: solguard swarm <path> [--mode api|agent-teams] [--verbose]');
    process.exit(1);
  }

  const verbose = args.includes('--verbose') || args.includes('-v');
  const mode = args.includes('--api') ? 'api' 
    : args.includes('--agent-teams') ? 'agent-teams'
    : 'auto';

  console.log('🔍 Starting SolGuard Multi-Agent Security Audit...\n');
  
  const result = await swarmAudit({
    target,
    mode: mode as any,
    verbose,
    markdown: true,
  });

  if (result.markdownReport) {
    console.log(result.markdownReport);
  } else {
    console.log(`\n✅ Audit complete in ${result.duration}ms`);
    console.log(`📊 Mode: ${result.mode}`);
    console.log(`🔎 Total findings: ${result.findings.length}`);
    
    if (result.synthesis) {
      const s = result.synthesis.summary;
      console.log(`   - Critical: ${s.critical}`);
      console.log(`   - High: ${s.high}`);
      console.log(`   - Medium: ${s.medium}`);
      console.log(`   - Low: ${s.low}`);
    }
    
    if (result.errors && result.errors.length > 0) {
      console.log(`\n⚠️  Errors:`);
      for (const err of result.errors) {
        console.log(`   - ${err}`);
      }
    }
  }

  // Exit with error if critical findings
  if (result.synthesis && result.synthesis.summary.critical > 0) {
    process.exit(1);
  }
}

/**
 * Example: How to use Agent Teams mode from within Claude Code
 * 
 * This shows the TeammateTool operations needed for multi-agent auditing.
 * Run this inside a Claude Code session with CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS=1
 */
export const AGENT_TEAMS_EXAMPLE = `
// === STEP 1: Create the team ===
Teammate({
  operation: "spawnTeam",
  team_name: "solguard-audit",
  description: "Security audit of Solana program"
})

// === STEP 2: Create tasks for each specialist ===
TaskCreate({
  subject: "Reentrancy Analysis",
  description: "Analyze for CPI state bugs",
  activeForm: "Checking reentrancy..."
})

TaskCreate({
  subject: "Access Control Analysis", 
  description: "Check permissions and authorities",
  activeForm: "Checking access control..."
})

TaskCreate({
  subject: "Arithmetic Analysis",
  description: "Check for overflow/underflow",
  activeForm: "Checking arithmetic..."
})

TaskCreate({
  subject: "Oracle Analysis",
  description: "Check price oracle usage",
  activeForm: "Checking oracles..."
})

// === STEP 3: Spawn specialist agents ===
Task({
  team_name: "solguard-audit",
  name: "reentrancy-specialist",
  subagent_type: "general-purpose",
  prompt: \`You are a reentrancy specialist. 
  Claim task #1. Analyze the code for CPI state bugs.
  Send findings to team-lead when done.\`,
  run_in_background: true
})

Task({
  team_name: "solguard-audit",
  name: "access-control-specialist",
  subagent_type: "general-purpose",
  prompt: \`You are an access control specialist.
  Claim task #2. Check permissions and authorities.
  Send findings to team-lead when done.\`,
  run_in_background: true
})

// ... spawn other specialists ...

// === STEP 4: Wait for results ===
// Specialists will send findings via Teammate.write()
// Check inbox: ~/.claude/teams/solguard-audit/inboxes/team-lead.json

// === STEP 5: Synthesize and cleanup ===
Teammate({ operation: "requestShutdown", target_agent_id: "reentrancy-specialist" })
Teammate({ operation: "requestShutdown", target_agent_id: "access-control-specialist" })
// Wait for approvals...
Teammate({ operation: "cleanup" })
`;
