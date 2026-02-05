import type { Finding } from '../commands/audit.js';
import type { ParsedRust } from '../parsers/rust.js';

/**
 * Break Statement Logic Bug
 * Based on: Jet Protocol vulnerability discovered by Jayne
 * 
 * Unintended use of 'break' in loops can cause logic errors.
 * In Jet's case, a break statement caused early loop exit,
 * allowing unlimited borrowing.
 */
export function checkJetBreakBug(parsed: ParsedRust): Finding[] {
  const findings: Finding[] = [];
  const content = parsed.content;

  // Detect break statements in loops that handle multiple accounts/assets
  const loopPatterns = [
    /for\s+\w+\s+in\s+.*?(accounts?|assets?|positions?|obligations?)/gi,
    /while\s+.*?(position|obligation|asset)/gi,
    /loop\s*\{[^}]*?(withdraw|borrow|liquidate)/gi,
  ];

  for (const pattern of loopPatterns) {
    const matches = content.match(pattern);
    if (matches) {
      // Check for break statements within these loops
      // This is a heuristic - we look for break within a reasonable distance
      for (const match of matches) {
        const idx = content.indexOf(match);
        const loopEnd = content.indexOf('}', idx + match.length);
        if (loopEnd > idx) {
          const loopBody = content.slice(idx, Math.min(loopEnd + 500, content.length));
          
          if (/\bbreak\b/.test(loopBody)) {
            findings.push({
              severity: 'high',
              category: 'logic-bug',
              title: 'Break Statement in Financial Loop',
              description: `Loop "${match.slice(0, 50)}..." contains a break statement. ` +
                'Early loop exit in financial calculations can cause incomplete processing ' +
                '(Jet Protocol bug pattern - allowed unlimited borrowing).',
              recommendation: 'Review break statement logic carefully. ' +
                'Ensure all items are processed and early exit is intentional. ' +
                'Consider using continue instead of break where appropriate.',
              location: parsed.path,
            });
            break;
          }
        }
      }
    }
  }

  // Detect early return in iteration over obligations/positions
  if (/iter.*?(obligation|position|account)/i.test(content)) {
    if (/return\s+(Ok|Err|Some|None)/i.test(content)) {
      const hasFullIteration = /for_each|fold|collect|all\(|any\(/i.test(content);
      if (!hasFullIteration) {
        findings.push({
          severity: 'medium',
          category: 'logic-bug',
          title: 'Early Return in Position/Obligation Iteration',
          description: 'Early return while iterating over positions or obligations. ' +
            'This could cause incomplete processing of all items.',
          recommendation: 'Ensure iteration processes all items before returning. ' +
            'Use collect() or fold() for complete iteration, then check results.',
          location: parsed.path,
        });
      }
    }
  }

  // Detect loops with complex exit conditions
  const complexLoops = /for\s+[^{]+\{[^}]*?(if[^}]*break|break[^}]*if)/s;
  if (complexLoops.test(content)) {
    findings.push({
      severity: 'medium',
      category: 'logic-bug',
      title: 'Complex Loop Exit Conditions',
      description: 'Loop contains conditional break statements. ' +
        'Complex exit conditions increase risk of logic errors.',
      recommendation: 'Simplify loop logic. Consider extracting into separate functions ' +
        'with clear return conditions.',
      location: parsed.path,
    });
  }

  // Detect iteration limit without reaching all items
  if (/iter\(\)\.take\(|\.skip\(/i.test(content)) {
    findings.push({
      severity: 'low',
      category: 'logic-bug',
      title: 'Iteration Limit May Skip Items',
      description: 'Using take() or skip() on iteration. ' +
        'Ensure this intentionally limits processing and doesn\'t miss critical items.',
      recommendation: 'Verify that skipped/limited items don\'t affect financial calculations.',
      location: parsed.path,
    });
  }

  return findings;
}
