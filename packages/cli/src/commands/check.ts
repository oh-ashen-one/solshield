/**
 * Quick Check Command
 * 
 * Fast pass/fail check for scripting and pre-commit hooks
 * Outputs minimal info, exits with appropriate code
 */

import { existsSync, readdirSync, statSync } from 'fs';
import { join } from 'path';
import { parseRustFiles } from '../parsers/rust.js';
import { runPatterns } from '../patterns/index.js';

interface CheckOptions {
  failOn?: 'critical' | 'high' | 'medium' | 'low' | 'any';
  quiet?: boolean;
}

/**
 * Run a quick security check
 * Returns exit code: 0 = pass, 1 = fail
 */
export async function checkCommand(path: string, options: CheckOptions = {}) {
  const failOn = options.failOn || 'critical';
  const quiet = options.quiet || false;
  
  if (!existsSync(path)) {
    if (!quiet) console.error(`Path not found: ${path}`);
    process.exit(2);
  }
  
  // Find Rust files
  const rustFiles = findRustFiles(path);
  
  if (rustFiles.length === 0) {
    if (!quiet) console.log('No Rust files found');
    process.exit(0);
  }
  
  // Parse and audit
  const parsed = await parseRustFiles(rustFiles);
  let criticalCount = 0;
  let highCount = 0;
  let mediumCount = 0;
  let lowCount = 0;
  
  if (parsed && parsed.files) {
    for (const file of parsed.files) {
      const findings = await runPatterns({
        path: file.path,
        rust: {
          files: [file],
          functions: parsed.functions.filter(f => f.file === file.path),
          structs: parsed.structs.filter(s => s.file === file.path),
          implBlocks: parsed.implBlocks.filter(i => i.file === file.path),
          content: file.content,
        } as any,
        idl: null,
      });
      
      for (const f of findings) {
        if (f.severity === 'critical') criticalCount++;
        else if (f.severity === 'high') highCount++;
        else if (f.severity === 'medium') mediumCount++;
        else if (f.severity === 'low') lowCount++;
      }
    }
  }
  
  // Determine pass/fail
  let failed = false;
  
  switch (failOn) {
    case 'any':
      failed = criticalCount + highCount + mediumCount + lowCount > 0;
      break;
    case 'low':
      failed = criticalCount + highCount + mediumCount + lowCount > 0;
      break;
    case 'medium':
      failed = criticalCount + highCount + mediumCount > 0;
      break;
    case 'high':
      failed = criticalCount + highCount > 0;
      break;
    case 'critical':
    default:
      failed = criticalCount > 0;
      break;
  }
  
  if (!quiet) {
    const total = criticalCount + highCount + mediumCount + lowCount;
    if (failed) {
      console.log(`FAIL: ${total} issue(s) found (${criticalCount} critical, ${highCount} high)`);
    } else {
      console.log(`PASS: ${total} issue(s), none at ${failOn} level or above`);
    }
  }
  
  process.exit(failed ? 1 : 0);
}

function findRustFiles(path: string): string[] {
  if (statSync(path).isFile()) {
    return path.endsWith('.rs') ? [path] : [];
  }
  
  const files: string[] = [];
  
  function scan(dir: string) {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = join(dir, entry.name);
      if (entry.isDirectory() && !['node_modules', 'target', '.git'].includes(entry.name)) {
        scan(full);
      } else if (entry.name.endsWith('.rs')) {
        files.push(full);
      }
    }
  }
  
  scan(path);
  return files;
}
