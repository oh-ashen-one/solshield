/**
 * Finding Synthesizer
 * 
 * Combines and deduplicates findings from multiple specialist agents.
 * Uses heuristics and optionally a synthesis agent to create a unified report.
 */

import type { AgentFinding, AgentType } from './agents.js';

export interface SynthesisResult {
  /** Original findings count */
  originalCount: number;
  
  /** Deduplicated findings count */
  deduplicatedCount: number;
  
  /** Findings after synthesis */
  deduplicatedFindings: AgentFinding[];
  
  /** Findings grouped by file */
  byFile: Record<string, AgentFinding[]>;
  
  /** Findings grouped by severity */
  bySeverity: Record<string, AgentFinding[]>;
  
  /** Findings grouped by agent */
  byAgent: Record<AgentType, AgentFinding[]>;
  
  /** Executive summary */
  summary: SynthesisSummary;
  
  /** Cross-references between related findings */
  crossReferences: CrossReference[];
}

export interface SynthesisSummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total: number;
  topRisks: string[];
  recommendations: string[];
}

export interface CrossReference {
  findingIds: string[];
  relationship: 'duplicate' | 'related' | 'cascading';
  description: string;
}

/**
 * Synthesize findings from multiple agents into a unified report
 */
export async function synthesizeFindings(
  findings: AgentFinding[],
  code: string,
  filePath: string
): Promise<SynthesisResult> {
  // Step 1: Deduplicate
  const deduplicated = deduplicateFindings(findings);
  
  // Step 2: Find cross-references
  const crossReferences = findCrossReferences(deduplicated);
  
  // Step 3: Group by various dimensions
  const byFile = groupByFile(deduplicated);
  const bySeverity = groupBySeverity(deduplicated);
  const byAgent = groupByAgent(deduplicated);
  
  // Step 4: Generate summary
  const summary = generateSummary(deduplicated, crossReferences);
  
  return {
    originalCount: findings.length,
    deduplicatedCount: deduplicated.length,
    deduplicatedFindings: deduplicated,
    byFile,
    bySeverity,
    byAgent,
    summary,
    crossReferences,
  };
}

/**
 * Deduplicate findings using similarity heuristics
 */
function deduplicateFindings(findings: AgentFinding[]): AgentFinding[] {
  const seen = new Map<string, AgentFinding>();
  
  for (const finding of findings) {
    // Create a fingerprint based on location and type
    const fingerprint = createFingerprint(finding);
    
    if (seen.has(fingerprint)) {
      // Merge with existing finding
      const existing = seen.get(fingerprint)!;
      mergeFinding(existing, finding);
    } else {
      seen.set(fingerprint, { ...finding });
    }
  }
  
  return Array.from(seen.values());
}

/**
 * Create a fingerprint for deduplication
 */
function createFingerprint(finding: AgentFinding): string {
  const parts = [
    finding.location.file,
    finding.location.line?.toString() || 'unknown',
    finding.severity,
    // Normalize title for comparison
    normalizeTitle(finding.title),
  ];
  
  return parts.join('::');
}

/**
 * Normalize title for comparison
 */
function normalizeTitle(title: string): string {
  return title
    .toLowerCase()
    .replace(/[^a-z0-9]/g, '')
    .slice(0, 50);
}

/**
 * Merge two findings (keep the more detailed one)
 */
function mergeFinding(existing: AgentFinding, incoming: AgentFinding): void {
  // Keep higher severity
  const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
  if (severityOrder.indexOf(incoming.severity) < severityOrder.indexOf(existing.severity)) {
    existing.severity = incoming.severity;
  }
  
  // Merge descriptions if different
  if (incoming.description && 
      !existing.description.includes(incoming.description) &&
      incoming.description.length > existing.description.length) {
    existing.description = incoming.description;
  }
  
  // Merge suggestions
  if (incoming.suggestion && !existing.suggestion?.includes(incoming.suggestion)) {
    existing.suggestion = existing.suggestion 
      ? `${existing.suggestion}\n\nAlternative: ${incoming.suggestion}`
      : incoming.suggestion;
  }
  
  // Track which agents found this
  if (incoming.agent && existing.agent !== incoming.agent) {
    (existing as any).foundBy = (existing as any).foundBy || [existing.agent];
    if (!(existing as any).foundBy.includes(incoming.agent)) {
      (existing as any).foundBy.push(incoming.agent);
    }
  }
}

/**
 * Find cross-references between related findings
 */
function findCrossReferences(findings: AgentFinding[]): CrossReference[] {
  const crossRefs: CrossReference[] = [];
  
  // Find findings at the same location
  const byLocation = new Map<string, AgentFinding[]>();
  for (const f of findings) {
    const loc = `${f.location.file}:${f.location.line || 0}`;
    if (!byLocation.has(loc)) byLocation.set(loc, []);
    byLocation.get(loc)!.push(f);
  }
  
  for (const [loc, group] of byLocation) {
    if (group.length > 1) {
      crossRefs.push({
        findingIds: group.map(f => f.id),
        relationship: 'related',
        description: `Multiple issues at ${loc}`,
      });
    }
  }
  
  // Find cascading vulnerabilities (e.g., oracle issue leading to math issue)
  const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
  const criticalHighFindings = findings.filter(f => 
    ['critical', 'high'].includes(f.severity)
  );
  
  for (const critical of criticalHighFindings) {
    // Find potentially cascading issues
    const related = findings.filter(f => 
      f !== critical &&
      f.location.file === critical.location.file &&
      Math.abs((f.location.line || 0) - (critical.location.line || 0)) < 20
    );
    
    if (related.length > 0) {
      crossRefs.push({
        findingIds: [critical.id, ...related.map(r => r.id)],
        relationship: 'cascading',
        description: `Issues near critical finding "${critical.title}"`,
      });
    }
  }
  
  return crossRefs;
}

/**
 * Group findings by file
 */
function groupByFile(findings: AgentFinding[]): Record<string, AgentFinding[]> {
  const groups: Record<string, AgentFinding[]> = {};
  
  for (const f of findings) {
    const file = f.location.file;
    if (!groups[file]) groups[file] = [];
    groups[file].push(f);
  }
  
  return groups;
}

/**
 * Group findings by severity
 */
function groupBySeverity(findings: AgentFinding[]): Record<string, AgentFinding[]> {
  const groups: Record<string, AgentFinding[]> = {
    critical: [],
    high: [],
    medium: [],
    low: [],
    info: [],
  };
  
  for (const f of findings) {
    groups[f.severity].push(f);
  }
  
  return groups;
}

/**
 * Group findings by agent
 */
function groupByAgent(findings: AgentFinding[]): Record<AgentType, AgentFinding[]> {
  const groups: Record<string, AgentFinding[]> = {};
  
  for (const f of findings) {
    const agent = f.agent || 'unknown';
    if (!groups[agent]) groups[agent] = [];
    groups[agent].push(f);
  }
  
  return groups as Record<AgentType, AgentFinding[]>;
}

/**
 * Generate executive summary
 */
function generateSummary(
  findings: AgentFinding[],
  crossRefs: CrossReference[]
): SynthesisSummary {
  const severity = {
    critical: findings.filter(f => f.severity === 'critical').length,
    high: findings.filter(f => f.severity === 'high').length,
    medium: findings.filter(f => f.severity === 'medium').length,
    low: findings.filter(f => f.severity === 'low').length,
    info: findings.filter(f => f.severity === 'info').length,
  };
  
  // Identify top risks
  const topRisks: string[] = [];
  const criticalFindings = findings.filter(f => f.severity === 'critical');
  const highFindings = findings.filter(f => f.severity === 'high');
  
  if (criticalFindings.length > 0) {
    topRisks.push(...criticalFindings.slice(0, 3).map(f => f.title));
  }
  if (topRisks.length < 3 && highFindings.length > 0) {
    topRisks.push(...highFindings.slice(0, 3 - topRisks.length).map(f => f.title));
  }
  
  // Generate recommendations
  const recommendations: string[] = [];
  
  if (severity.critical > 0) {
    recommendations.push('URGENT: Address all critical vulnerabilities before deployment');
  }
  
  if (severity.high > 0) {
    recommendations.push('Fix high-severity issues in the next release');
  }
  
  // Check for patterns
  const hasAccessControl = findings.some(f => 
    f.agent === 'access-control' || f.title.toLowerCase().includes('access')
  );
  if (hasAccessControl) {
    recommendations.push('Conduct thorough access control review');
  }
  
  const hasArithmetic = findings.some(f => 
    f.agent === 'arithmetic' || f.title.toLowerCase().includes('overflow')
  );
  if (hasArithmetic) {
    recommendations.push('Implement checked arithmetic throughout codebase');
  }
  
  if (crossRefs.some(r => r.relationship === 'cascading')) {
    recommendations.push('Investigate cascading vulnerability chains');
  }
  
  if (recommendations.length === 0) {
    recommendations.push('Continue monitoring for emerging vulnerability patterns');
  }
  
  return {
    ...severity,
    total: findings.length,
    topRisks,
    recommendations,
  };
}

/**
 * Format synthesis result as Markdown report
 */
export function formatSynthesisAsMarkdown(result: SynthesisResult): string {
  const lines: string[] = [];
  
  lines.push('# SolShield Multi-Agent Security Audit Report\n');
  lines.push(`Generated: ${new Date().toISOString()}\n`);
  
  // Summary
  lines.push('## Executive Summary\n');
  lines.push(`| Severity | Count |`);
  lines.push(`|----------|-------|`);
  lines.push(`| Critical | ${result.summary.critical} |`);
  lines.push(`| High | ${result.summary.high} |`);
  lines.push(`| Medium | ${result.summary.medium} |`);
  lines.push(`| Low | ${result.summary.low} |`);
  lines.push(`| Info | ${result.summary.info} |`);
  lines.push(`| **Total** | **${result.summary.total}** |`);
  lines.push('');
  
  if (result.summary.topRisks.length > 0) {
    lines.push('### Top Risks\n');
    for (const risk of result.summary.topRisks) {
      lines.push(`- ${risk}`);
    }
    lines.push('');
  }
  
  if (result.summary.recommendations.length > 0) {
    lines.push('### Recommendations\n');
    for (const rec of result.summary.recommendations) {
      lines.push(`- ${rec}`);
    }
    lines.push('');
  }
  
  // Findings by severity
  lines.push('## Findings\n');
  
  for (const severity of ['critical', 'high', 'medium', 'low', 'info']) {
    const findings = result.bySeverity[severity];
    if (findings.length === 0) continue;
    
    lines.push(`### ${severity.charAt(0).toUpperCase() + severity.slice(1)} (${findings.length})\n`);
    
    for (const f of findings) {
      lines.push(`#### ${f.id}: ${f.title}\n`);
      lines.push(`- **Location**: ${f.location.file}:${f.location.line || '?'}`);
      lines.push(`- **Agent**: ${f.agent || 'unknown'}`);
      lines.push(`- **Description**: ${f.description}`);
      
      if (f.code) {
        lines.push('\n```rust');
        lines.push(f.code);
        lines.push('```\n');
      }
      
      if (f.suggestion) {
        lines.push(`- **Suggestion**: ${f.suggestion}`);
      }
      
      lines.push('');
    }
  }
  
  // Cross-references
  if (result.crossReferences.length > 0) {
    lines.push('## Related Findings\n');
    for (const ref of result.crossReferences) {
      lines.push(`- **${ref.relationship}**: ${ref.description}`);
      lines.push(`  - Findings: ${ref.findingIds.join(', ')}`);
    }
  }
  
  return lines.join('\n');
}
