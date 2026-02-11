/**
 * SolShield Multi-Agent Security Swarm
 * 
 * Integrates with Claude Code's Agent Teams (Opus 4.6+) or Claude API directly
 * for parallel, specialized security auditing of Solana/Anchor programs.
 * 
 * ## Architecture
 * 
 * The swarm consists of specialist agents that each focus on a specific
 * vulnerability category:
 * 
 * - Reentrancy Specialist: Cross-program invocation state bugs
 * - Access Control Specialist: Permission, ownership, authority issues  
 * - Arithmetic Specialist: Overflow, underflow, precision loss
 * - Oracle Specialist: Price manipulation, staleness, TWAP issues
 * 
 * ## Usage Modes
 * 
 * 1. **Claude Code Agent Teams** (requires CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS=1)
 *    Uses TeammateTool to spawn parallel Claude instances in tmux/iTerm2 panes.
 *    Best for interactive debugging and seeing agent work in real-time.
 * 
 * 2. **Claude API Direct** (requires ANTHROPIC_API_KEY)
 *    Calls Claude API directly with specialized prompts per agent.
 *    Best for CI/CD, automation, and programmatic usage.
 * 
 * 3. **Subprocess Claude Code** 
 *    Spawns `claude` CLI as subprocesses with --print mode.
 *    Fallback when Agent Teams not available.
 * 
 * @module swarm
 * @author Midir (AI)
 * @see https://code.claude.com/docs/en/agent-teams
 */

export { SwarmOrchestrator, type SwarmConfig, type SwarmResult } from './orchestrator.js';
export { SpecialistAgent, type AgentConfig, type AgentType } from './agents.js';
export { 
  REENTRANCY_SPECIALIST,
  ACCESS_CONTROL_SPECIALIST,
  ARITHMETIC_SPECIALIST,
  ORACLE_SPECIALIST,
  COMPREHENSIVE_SPECIALIST,
  ALL_SPECIALISTS
} from './specialists.js';
export { synthesizeFindings, type SynthesisResult } from './synthesizer.js';
export { swarmAudit } from './audit.js';
