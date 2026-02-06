/**
 * Specialist Agent Definitions
 * 
 * Each agent is configured with:
 * - A focused security domain
 * - Specialized system prompt with Solana/Anchor expertise
 * - Relevant patterns to prioritize
 * - Output format specification
 */

export type AgentType = 
  | 'reentrancy'
  | 'access-control'
  | 'arithmetic'
  | 'oracle'
  | 'comprehensive';

export interface AgentConfig {
  id: AgentType;
  name: string;
  description: string;
  systemPrompt: string;
  patterns: string[];  // Pattern IDs this agent focuses on
  model?: string;      // Override model (default: claude-sonnet-4-20250514)
  temperature?: number;
}

/**
 * Base template for all security specialist agents
 */
const BASE_SECURITY_CONTEXT = `You are a security auditor specializing in Solana and Anchor programs.

## Solana Security Context
- Solana uses a single-threaded runtime - no traditional reentrancy
- BUT cross-program invocations (CPIs) can cause reentrancy-like bugs
- All accounts must be validated: ownership, signer, PDA derivation
- Integer arithmetic can overflow/underflow silently in release builds
- Oracles can be manipulated via flash loans or low liquidity

## Output Format
Return findings as JSON array:
\`\`\`json
[
  {
    "id": "SWARM-001",
    "severity": "critical|high|medium|low|info",
    "title": "Brief title",
    "description": "Detailed explanation",
    "location": {"file": "path", "line": 123},
    "code": "relevant code snippet",
    "suggestion": "How to fix",
    "references": ["link1", "link2"]
  }
]
\`\`\`

Focus ONLY on your specialty. Be thorough but precise - no false positives.`;

/**
 * Specialist Agent class for interacting with Claude
 */
export class SpecialistAgent {
  public readonly config: AgentConfig;

  constructor(config: AgentConfig) {
    this.config = config;
  }

  /**
   * Generate the full prompt for analyzing code
   */
  getAnalysisPrompt(code: string, filePath: string): string {
    return `${this.config.systemPrompt}

## File to Analyze
Path: ${filePath}

\`\`\`rust
${code}
\`\`\`

Analyze this code for ${this.config.name.toLowerCase()} vulnerabilities.
Return your findings as a JSON array. If no issues found, return empty array: []`;
  }

  /**
   * Parse agent response into structured findings
   */
  parseResponse(response: string): AgentFinding[] {
    // Extract JSON from response (may be wrapped in markdown)
    const jsonMatch = response.match(/```(?:json)?\s*([\s\S]*?)```/) ||
                      response.match(/\[\s*\{[\s\S]*\}\s*\]/);
    
    if (!jsonMatch) {
      // Try direct parse
      try {
        const direct = JSON.parse(response);
        if (Array.isArray(direct)) return direct;
      } catch {
        return [];
      }
      return [];
    }

    try {
      const parsed = JSON.parse(jsonMatch[1] || jsonMatch[0]);
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return [];
    }
  }
}

export interface AgentFinding {
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  location: {
    file: string;
    line?: number;
  };
  code?: string;
  suggestion?: string;
  references?: string[];
  agent?: AgentType; // Added during synthesis
}

/**
 * Create a specialist agent from config
 */
export function createAgent(config: AgentConfig): SpecialistAgent {
  return new SpecialistAgent({
    ...config,
    systemPrompt: `${BASE_SECURITY_CONTEXT}\n\n${config.systemPrompt}`,
  });
}
