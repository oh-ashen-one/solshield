import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL063: Privilege Escalation
 * Paths to gaining unauthorized privileges.
 */
export function checkPrivilegeEscalation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (!input.rust || !input.rust.files) return findings;

  for (const file of input.rust.files) {
    const lines = file.lines;

    lines.forEach((line, index) => {
      const lineNum = index + 1;

      // Pattern 1: Role/permission set from user input
      if ((line.includes('role') || line.includes('permission') || line.includes('level')) &&
          (line.includes('args.') || line.includes('params.'))) {
        findings.push({
          id: `SOL063-${findings.length + 1}`,
          pattern: 'Privilege Escalation',
          severity: 'critical',
          title: 'Role/permission from user input',
          description: 'User can set their own role/permission level.',
          location: { file: file.path, line: lineNum },
          suggestion: 'Validate caller has permission to assign the requested role.',
        });
      }

      // Pattern 2: Self-promotion check missing
      if (line.includes('add_admin') || line.includes('grant_role') || line.includes('set_operator')) {
        const fnEnd = Math.min(lines.length, index + 15);
        const fnBody = lines.slice(index, fnEnd).join('\n');

        if (!fnBody.includes('!=') && !fnBody.includes('require') && 
            !fnBody.includes('caller')) {
          findings.push({
            id: `SOL063-${findings.length + 1}`,
            pattern: 'Privilege Escalation',
            severity: 'high',
            title: 'Role grant without self-assignment check',
            description: 'User might be able to grant role to themselves.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Check: require!(grantee != caller) or restrict to higher role.',
          });
        }
      }

      // Pattern 3: Bypassing role hierarchy
      if (line.includes('admin') && line.includes('operator')) {
        const contextStart = Math.max(0, index - 5);
        const context = lines.slice(contextStart, index + 5).join('\n');

        if (!context.includes('>=') && !context.includes('hierarchy') && 
            !context.includes('level')) {
          findings.push({
            id: `SOL063-${findings.length + 1}`,
            pattern: 'Privilege Escalation',
            severity: 'medium',
            title: 'Role hierarchy may not be enforced',
            description: 'Multiple roles without clear hierarchy enforcement.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Implement role levels: require!(caller_role >= required_role)',
          });
        }
      }
    });
  }

  return findings;
}
