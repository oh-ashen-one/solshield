import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL104: Authority Scope
 * Detects overly permissive or missing authority scoping
 */
export function checkAuthorityScope(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;

  if (!rust || !rust.content) return findings;

  // Check for single authority controlling everything
  const authorityRefs = (rust.content.match(/authority|admin|owner/gi) || []).length;
  const uniqueAuthorities = new Set(rust.content.match(/\w+_authority|\w+_admin|\w+_owner/gi) || []);
  
  if (authorityRefs > 10 && uniqueAuthorities.size <= 1) {
    findings.push({
      id: 'SOL104',
      severity: 'medium',
      title: 'Single Authority Pattern',
      description: 'One authority controls all operations - consider role separation',
      location: input.path,
      recommendation: 'Implement role-based access: admin, operator, emergency, etc.',
    });
  }

  // Check for missing authority on state-changing functions
  const pubFns = rust.content.match(/pub\s+fn\s+\w+/g) || [];
  for (const fn of pubFns) {
    const fnName = fn.match(/fn\s+(\w+)/)?.[1] || '';
    if (['update', 'set', 'modify', 'change'].some(w => fnName.toLowerCase().includes(w))) {
      // Check if this fn's context has authority
      if (!rust.content.includes(`${fnName}`) || !rust.content.includes('Signer')) {
        findings.push({
          id: 'SOL104',
          severity: 'high',
          title: `State-Changing Function May Lack Authority: ${fnName}`,
          description: 'Function modifies state but may not require authority',
          location: input.path,
          recommendation: 'Add Signer<\'info> authority check',
        });
        break;
      }
    }
  }

  return findings;
}
