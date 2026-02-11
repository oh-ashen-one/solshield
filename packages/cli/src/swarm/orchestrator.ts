/**
 * Swarm Orchestrator
 * 
 * Coordinates multiple specialist agents for parallel security auditing.
 * Supports three execution modes:
 * 
 * 1. Claude Code Agent Teams (TeammateTool)
 * 2. Claude API direct calls
 * 3. Claude CLI subprocess
 */

import { spawn, execSync } from 'child_process';
import { readFileSync, existsSync, writeFileSync, mkdirSync } from 'fs';
import { join, basename } from 'path';
import { createAgent, SpecialistAgent, type AgentFinding, type AgentType } from './agents.js';
import { ALL_SPECIALISTS, getSpecialist, COMPREHENSIVE_SPECIALIST } from './specialists.js';
import { synthesizeFindings, type SynthesisResult } from './synthesizer.js';

export interface SwarmConfig {
  /** Execution mode */
  mode: 'agent-teams' | 'api' | 'subprocess' | 'auto';
  
  /** Which specialists to use (default: all) */
  specialists?: AgentType[];
  
  /** Claude model to use */
  model?: string;
  
  /** Maximum parallel agents */
  maxParallel?: number;
  
  /** Timeout per agent (ms) */
  timeout?: number;
  
  /** Team name for agent-teams mode */
  teamName?: string;
  
  /** Whether to use comprehensive agent as synthesis */
  useSynthesis?: boolean;
  
  /** Output directory for reports */
  outputDir?: string;
  
  /** Verbose logging */
  verbose?: boolean;
}

export interface SwarmResult {
  success: boolean;
  mode: string;
  duration: number;
  findings: AgentFinding[];
  agentResults: AgentResult[];
  synthesis?: SynthesisResult;
  errors?: string[];
}

interface AgentResult {
  agentId: AgentType;
  agentName: string;
  success: boolean;
  findings: AgentFinding[];
  duration: number;
  error?: string;
}

/**
 * Check if Agent Teams feature is available
 */
function isAgentTeamsAvailable(): boolean {
  // Check environment variable
  const envEnabled = process.env.CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS === '1';
  
  // Check if running inside Claude Code with teams support
  const insideClaudeCode = !!process.env.CLAUDE_CODE_AGENT_ID;
  
  return envEnabled || insideClaudeCode;
}

/**
 * Check if Claude CLI is available
 */
function isClaudeCliAvailable(): boolean {
  try {
    execSync('claude --version', { stdio: 'pipe' });
    return true;
  } catch {
    return false;
  }
}

/**
 * Check if Anthropic API key is available
 */
function isApiAvailable(): boolean {
  return !!process.env.ANTHROPIC_API_KEY;
}

/**
 * Determine the best execution mode
 */
function detectMode(config: SwarmConfig): 'agent-teams' | 'api' | 'subprocess' {
  if (config.mode !== 'auto') {
    return config.mode as 'agent-teams' | 'api' | 'subprocess';
  }
  
  // Priority: Agent Teams > API > Subprocess
  if (isAgentTeamsAvailable()) return 'agent-teams';
  if (isApiAvailable()) return 'api';
  if (isClaudeCliAvailable()) return 'subprocess';
  
  throw new Error(
    'No Claude execution method available. Enable one of:\n' +
    '  1. Set CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS=1 for Agent Teams\n' +
    '  2. Set ANTHROPIC_API_KEY for direct API calls\n' +
    '  3. Install Claude CLI for subprocess mode'
  );
}

/**
 * Main Swarm Orchestrator
 */
export class SwarmOrchestrator {
  private config: Required<SwarmConfig>;
  private agents: SpecialistAgent[];

  constructor(config: SwarmConfig) {
    this.config = {
      mode: config.mode || 'auto',
      specialists: config.specialists || ALL_SPECIALISTS.map(s => s.id),
      model: config.model || 'claude-sonnet-4-20250514',
      maxParallel: config.maxParallel || 4,
      timeout: config.timeout || 120000, // 2 minutes
      teamName: config.teamName || `solshield-audit-${Date.now()}`,
      useSynthesis: config.useSynthesis ?? true,
      outputDir: config.outputDir || './solshield-reports',
      verbose: config.verbose || false,
    };

    // Initialize specialist agents
    this.agents = this.config.specialists.map(id => 
      createAgent(getSpecialist(id))
    );
  }

  /**
   * Run the swarm audit on a file or directory
   */
  async audit(targetPath: string): Promise<SwarmResult> {
    const startTime = Date.now();
    const errors: string[] = [];
    
    // Detect execution mode
    let mode: 'agent-teams' | 'api' | 'subprocess';
    try {
      mode = detectMode(this.config);
    } catch (e: any) {
      return {
        success: false,
        mode: 'none',
        duration: 0,
        findings: [],
        agentResults: [],
        errors: [e.message],
      };
    }

    this.log(`Starting swarm audit in ${mode} mode`);
    this.log(`Target: ${targetPath}`);
    this.log(`Specialists: ${this.agents.map(a => a.config.name).join(', ')}`);

    // Read the code to analyze
    const code = this.readCode(targetPath);
    if (!code) {
      return {
        success: false,
        mode,
        duration: Date.now() - startTime,
        findings: [],
        agentResults: [],
        errors: [`Failed to read code from: ${targetPath}`],
      };
    }

    // Run agents based on mode
    let agentResults: AgentResult[];
    switch (mode) {
      case 'agent-teams':
        agentResults = await this.runWithAgentTeams(code, targetPath);
        break;
      case 'api':
        agentResults = await this.runWithApi(code, targetPath);
        break;
      case 'subprocess':
        agentResults = await this.runWithSubprocess(code, targetPath);
        break;
    }

    // Collect all findings
    const allFindings = agentResults.flatMap(r => r.findings);

    // Synthesize if enabled
    let synthesis: SynthesisResult | undefined;
    if (this.config.useSynthesis && allFindings.length > 0) {
      try {
        synthesis = await synthesizeFindings(allFindings, code, targetPath);
      } catch (e: any) {
        errors.push(`Synthesis failed: ${e.message}`);
      }
    }

    // Collect errors
    for (const result of agentResults) {
      if (result.error) {
        errors.push(`${result.agentName}: ${result.error}`);
      }
    }

    const duration = Date.now() - startTime;
    this.log(`Audit complete in ${duration}ms. Found ${allFindings.length} issues.`);

    // Save report if output dir specified
    if (this.config.outputDir) {
      this.saveReport({
        targetPath,
        timestamp: new Date().toISOString(),
        mode,
        duration,
        findings: allFindings,
        agentResults,
        synthesis,
      });
    }

    return {
      success: errors.length === 0,
      mode,
      duration,
      findings: synthesis?.deduplicatedFindings || allFindings,
      agentResults,
      synthesis,
      errors: errors.length > 0 ? errors : undefined,
    };
  }

  /**
   * Read code from file or directory
   */
  private readCode(targetPath: string): string | null {
    try {
      if (!existsSync(targetPath)) {
        return null;
      }
      
      // For now, handle single file. Directory support can be added.
      const content = readFileSync(targetPath, 'utf-8');
      return content;
    } catch {
      return null;
    }
  }

  /**
   * Run with Claude Code Agent Teams (TeammateTool)
   * 
   * This generates instructions for the TeammateTool - in practice,
   * this would be called from within Claude Code with access to the tool.
   */
  private async runWithAgentTeams(code: string, filePath: string): Promise<AgentResult[]> {
    this.log('Agent Teams mode: Generating team configuration...');
    
    // In real usage, this would invoke TeammateTool operations
    // For the PoC, we generate the team structure and fall back to API
    
    const teamConfig = this.generateTeamConfig(code, filePath);
    this.log('Team config generated. In live usage, spawn via TeammateTool.');
    
    // For PoC, we can still run via API if available
    if (isApiAvailable()) {
      this.log('Falling back to API mode for execution...');
      return this.runWithApi(code, filePath);
    }
    
    // Return placeholder showing what would be spawned
    return this.agents.map(agent => ({
      agentId: agent.config.id,
      agentName: agent.config.name,
      success: false,
      findings: [],
      duration: 0,
      error: 'Agent Teams mode requires running inside Claude Code. See team config in output.',
    }));
  }

  /**
   * Generate Team configuration for Agent Teams mode
   */
  private generateTeamConfig(code: string, filePath: string) {
    return {
      teamName: this.config.teamName,
      description: `Security audit of ${basename(filePath)}`,
      teammates: this.agents.map(agent => ({
        name: agent.config.id,
        type: 'security-specialist',
        prompt: agent.getAnalysisPrompt(code, filePath),
        model: this.config.model,
        runInBackground: true,
      })),
      // TeammateTool operations needed:
      operations: [
        { operation: 'spawnTeam', team_name: this.config.teamName },
        ...this.agents.map(agent => ({
          operation: 'Task',
          team_name: this.config.teamName,
          name: agent.config.id,
          prompt: agent.getAnalysisPrompt(code, filePath),
          run_in_background: true,
        })),
      ],
    };
  }

  /**
   * Run with direct Claude API calls
   */
  private async runWithApi(code: string, filePath: string): Promise<AgentResult[]> {
    this.log('Running with Claude API...');
    
    const apiKey = process.env.ANTHROPIC_API_KEY;
    if (!apiKey) {
      throw new Error('ANTHROPIC_API_KEY not set');
    }

    // Run agents in parallel (up to maxParallel)
    const results: AgentResult[] = [];
    const chunks = this.chunkArray(this.agents, this.config.maxParallel);

    for (const chunk of chunks) {
      const chunkResults = await Promise.all(
        chunk.map(agent => this.callApiForAgent(agent, code, filePath, apiKey))
      );
      results.push(...chunkResults);
    }

    return results;
  }

  /**
   * Call Claude API for a single agent
   */
  private async callApiForAgent(
    agent: SpecialistAgent,
    code: string,
    filePath: string,
    apiKey: string
  ): Promise<AgentResult> {
    const startTime = Date.now();
    const prompt = agent.getAnalysisPrompt(code, filePath);

    try {
      const response = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': apiKey,
          'anthropic-version': '2023-06-01',
        },
        body: JSON.stringify({
          model: this.config.model,
          max_tokens: 4096,
          messages: [{ role: 'user', content: prompt }],
        }),
      });

      if (!response.ok) {
        throw new Error(`API error: ${response.status} ${response.statusText}`);
      }

      const data = await response.json() as any;
      const content = data.content?.[0]?.text || '';
      
      const findings = agent.parseResponse(content).map(f => ({
        ...f,
        agent: agent.config.id,
      }));

      return {
        agentId: agent.config.id,
        agentName: agent.config.name,
        success: true,
        findings,
        duration: Date.now() - startTime,
      };
    } catch (e: any) {
      return {
        agentId: agent.config.id,
        agentName: agent.config.name,
        success: false,
        findings: [],
        duration: Date.now() - startTime,
        error: e.message,
      };
    }
  }

  /**
   * Run with Claude CLI subprocess
   */
  private async runWithSubprocess(code: string, filePath: string): Promise<AgentResult[]> {
    this.log('Running with Claude CLI subprocess...');

    const results: AgentResult[] = [];
    
    // Run sequentially to avoid rate limits
    for (const agent of this.agents) {
      const result = await this.callCliForAgent(agent, code, filePath);
      results.push(result);
    }

    return results;
  }

  /**
   * Call Claude CLI for a single agent
   */
  private callCliForAgent(
    agent: SpecialistAgent,
    code: string,
    filePath: string
  ): Promise<AgentResult> {
    return new Promise((resolve) => {
      const startTime = Date.now();
      const prompt = agent.getAnalysisPrompt(code, filePath);

      try {
        // Write prompt to temp file to avoid shell escaping issues
        const tempDir = join(this.config.outputDir, '.temp');
        if (!existsSync(tempDir)) mkdirSync(tempDir, { recursive: true });
        
        const promptFile = join(tempDir, `${agent.config.id}-prompt.txt`);
        writeFileSync(promptFile, prompt);

        // Use --print for non-interactive mode
        const result = execSync(
          `claude --print --model ${this.config.model} < "${promptFile}"`,
          { 
            timeout: this.config.timeout,
            encoding: 'utf-8',
            stdio: ['pipe', 'pipe', 'pipe'],
          }
        );

        const findings = agent.parseResponse(result).map(f => ({
          ...f,
          agent: agent.config.id,
        }));

        resolve({
          agentId: agent.config.id,
          agentName: agent.config.name,
          success: true,
          findings,
          duration: Date.now() - startTime,
        });
      } catch (e: any) {
        resolve({
          agentId: agent.config.id,
          agentName: agent.config.name,
          success: false,
          findings: [],
          duration: Date.now() - startTime,
          error: e.message,
        });
      }
    });
  }

  /**
   * Save report to output directory
   */
  private saveReport(report: any): void {
    try {
      if (!existsSync(this.config.outputDir)) {
        mkdirSync(this.config.outputDir, { recursive: true });
      }

      const filename = `swarm-audit-${Date.now()}.json`;
      const reportPath = join(this.config.outputDir, filename);
      writeFileSync(reportPath, JSON.stringify(report, null, 2));
      
      this.log(`Report saved to: ${reportPath}`);
    } catch (e: any) {
      this.log(`Failed to save report: ${e.message}`);
    }
  }

  /**
   * Utility: chunk array for parallel processing
   */
  private chunkArray<T>(array: T[], size: number): T[][] {
    const chunks: T[][] = [];
    for (let i = 0; i < array.length; i += size) {
      chunks.push(array.slice(i, i + size));
    }
    return chunks;
  }

  /**
   * Logging utility
   */
  private log(message: string): void {
    if (this.config.verbose) {
      console.log(`[SolShield Swarm] ${message}`);
    }
  }
}
