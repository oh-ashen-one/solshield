/**
 * Fix Engine — applies auto-patches for detected vulnerabilities
 */

import chalk from 'chalk';
import { writeFileSync, readFileSync } from 'fs';
import { basename, dirname, join, extname } from 'path';

export interface FixRule {
  id: string;
  description: string;
  search: RegExp;
  replace: string | ((match: string, ...args: any[]) => string);
}

/**
 * Built-in fix rules for the top SOL patterns
 */
export const FIX_RULES: FixRule[] = [
  {
    id: 'SOL001',
    description: 'Add owner check to unchecked AccountInfo',
    search: /(\/\/\/\s*CHECK:.*\n\s*)(pub\s+\w+:\s*AccountInfo<'info>)/g,
    replace: (match, comment, field) => {
      const name = field.match(/pub\s+(\w+)/)?.[1] || 'account';
      return `${comment}#[account(owner = crate::ID)]\n    ${field}`;
    },
  },
  {
    id: 'SOL002',
    description: 'Replace unchecked AccountInfo with Signer for authority accounts',
    search: /(\/\/\/\s*CHECK:.*\n\s*pub\s+(authority|admin|owner|caller):\s*)AccountInfo<'info>/g,
    replace: '$1Signer<\'info>',
  },
  {
    id: 'SOL003',
    description: 'Replace unsafe arithmetic with checked operations',
    search: /(\w+\.\w+)\s*=\s*(\w+\.\w+)\s*\+\s*(\w+)/g,
    replace: '$1 = $2.checked_add($3).unwrap()',
  },
  {
    id: 'SOL003-sub',
    description: 'Replace unsafe subtraction with checked_sub',
    search: /(\w+\.\w+)\s*=\s*(\w+\.\w+)\s*-\s*(\w+)/g,
    replace: '$1 = $2.checked_sub($3).unwrap()',
  },
  {
    id: 'SOL005',
    description: 'Add has_one constraint to vault/state accounts near authority',
    search: /(#\[account\(\s*(?:mut\s*,?\s*)?seeds\s*=.*?\n\s*bump\s*\n\s*\)\])\n(\s*pub vault:)/gs,
    replace: '$1\n    // FIXED: Added authority constraint\n    #[account(\n        has_one = authority,\n    )]\n$2',
  },
  {
    id: 'SOL006',
    description: 'Add initialization guard',
    search: /(\/\/\s*SOL006:.*\n\s*)(let\s+vault\s*=\s*&mut\s+ctx\.accounts\.vault;)/g,
    replace: '$1// FIXED: Add init check\n        require!(!vault.is_initialized, ErrorCode::AlreadyInitialized);\n        $2',
  },
  {
    id: 'SOL010',
    description: 'Zero out data before closing account',
    search: /(\/\/\s*Data NOT zeroed.*)\n/g,
    replace: '// FIXED: Zero out account data to prevent revival\n        ctx.accounts.vault.authority = Pubkey::default();\n        ctx.accounts.vault.token_account = Pubkey::default();\n        ctx.accounts.vault.total_deposited = 0;\n',
  },
  {
    id: 'SOL013',
    description: 'Add constraint ensuring accounts are different',
    search: /(#\[account\(mut\)\]\s*\n\s*pub from_account:)/g,
    replace: '// FIXED: Ensure from != to\n    #[account(mut, constraint = from_account.key() != to_account.key() @ ErrorCode::DuplicateAccount)]\n    pub from_account:',
  },
];

export interface FixResult {
  filePath: string;
  outputPath: string;
  changes: { rule: string; description: string; line: number; before: string; after: string }[];
  totalFixes: number;
}

/**
 * Apply fixes to source files based on findings
 */
export function applyFixes(
  findings: { id: string; location: any }[],
  options: { fixOutput?: string } = {}
): FixResult[] {
  // Group findings by file
  const fileFindings = new Map<string, Set<string>>();
  for (const f of findings) {
    const file = typeof f.location === 'string' ? f.location : f.location?.file;
    if (!file) continue;
    if (!fileFindings.has(file)) fileFindings.set(file, new Set());
    // Extract base pattern ID (e.g. SOL003 from SOL003-5)
    const baseId = f.id.replace(/-\d+$/, '');
    fileFindings.get(file)!.add(baseId);
  }

  const results: FixResult[] = [];

  for (const [filePath, patternIds] of fileFindings) {
    let source: string;
    try {
      source = readFileSync(filePath, 'utf-8');
    } catch {
      continue;
    }

    let patched = source;
    const changes: FixResult['changes'] = [];

    for (const rule of FIX_RULES) {
      const ruleBaseId = rule.id.replace(/-\w+$/, '');
      // Apply rule if any matching pattern was found
      if (!patternIds.has(ruleBaseId) && !patternIds.has(rule.id)) continue;

      const before = patched;
      if (typeof rule.replace === 'string') {
        patched = patched.replace(rule.search, rule.replace);
      } else {
        patched = patched.replace(rule.search, rule.replace as any);
      }

      if (patched !== before) {
        // Find approximate line of change
        const beforeLines = before.split('\n');
        const afterLines = patched.split('\n');
        let changeLine = 1;
        for (let i = 0; i < Math.min(beforeLines.length, afterLines.length); i++) {
          if (beforeLines[i] !== afterLines[i]) {
            changeLine = i + 1;
            break;
          }
        }

        changes.push({
          rule: rule.id,
          description: rule.description,
          line: changeLine,
          before: getContext(before, changeLine),
          after: getContext(patched, changeLine),
        });
      }
    }

    if (changes.length === 0) continue;

    // Determine output path
    const ext = extname(filePath);
    const base = filePath.slice(0, -ext.length);
    const outputPath = options.fixOutput || `${base}.fixed${ext}`;

    writeFileSync(outputPath, patched, 'utf-8');

    results.push({
      filePath,
      outputPath,
      changes,
      totalFixes: changes.length,
    });
  }

  return results;
}

function getContext(source: string, line: number): string {
  const lines = source.split('\n');
  const start = Math.max(0, line - 2);
  const end = Math.min(lines.length, line + 2);
  return lines.slice(start, end).join('\n');
}

/**
 * Display fix results
 */
export function displayFixResults(results: FixResult[]) {
  if (results.length === 0) {
    console.log(chalk.yellow('\n🔧 No auto-fixes could be applied.'));
    return;
  }

  const totalFixes = results.reduce((sum, r) => sum + r.totalFixes, 0);
  console.log(chalk.green(`\n🔧 Applied ${totalFixes} auto-fix(es) across ${results.length} file(s):\n`));

  for (const result of results) {
    console.log(chalk.bold(`  📄 ${result.filePath}`));
    console.log(chalk.gray(`     → ${result.outputPath}\n`));

    for (const change of result.changes) {
      console.log(chalk.cyan(`  [${change.rule}] ${change.description} (line ~${change.line})`));
      // Show mini diff
      const beforeLines = change.before.split('\n');
      const afterLines = change.after.split('\n');
      for (const l of beforeLines) {
        if (!afterLines.includes(l)) {
          console.log(chalk.red(`    - ${l.trim()}`));
        }
      }
      for (const l of afterLines) {
        if (!beforeLines.includes(l)) {
          console.log(chalk.green(`    + ${l.trim()}`));
        }
      }
      console.log();
    }
  }
}
