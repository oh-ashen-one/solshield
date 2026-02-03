import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL066: Account Data Borrowing Vulnerability
 * Detects unsafe borrow patterns that can cause runtime panics
 */
export function checkAccountBorrowing(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;

  if (!rust || !rust.content) return findings;

  // Check for multiple mutable borrows
  const multipleBorrows = /(\w+)\.try_borrow_mut_data\(\)[\s\S]*?\1\.try_borrow_mut_data\(\)/g;
  let match;
  while ((match = multipleBorrows.exec(rust.content)) !== null) {
    findings.push({
      id: 'SOL066',
      severity: 'high',
      title: 'Multiple Mutable Borrows',
      description: 'Multiple mutable borrows of the same account data can cause runtime panics',
      location: input.path,
      recommendation: 'Use a single mutable borrow and pass references to functions that need the data',
    });
  }

  // Check for borrow without drop
  if (rust.content.includes('try_borrow_mut_data') && !rust.content.includes('drop(')) {
    const longLivedBorrow = /let\s+\w+\s*=\s*\w+\.try_borrow_mut_data\(\)[^;]*;[\s\S]{200,}(try_borrow|data\(\))/;
    if (longLivedBorrow.test(rust.content)) {
      findings.push({
        id: 'SOL066',
        severity: 'medium',
        title: 'Long-lived Mutable Borrow',
        description: 'Mutable borrow held for too long may conflict with other operations',
        location: input.path,
        recommendation: 'Drop the borrow explicitly with drop() before performing other operations',
      });
    }
  }

  // Check for unchecked borrow
  if (rust.content.includes('.borrow()') && !rust.content.includes('.try_borrow()')) {
    findings.push({
      id: 'SOL066',
      severity: 'medium',
      title: 'Unchecked Borrow Pattern',
      description: 'Using borrow() instead of try_borrow() will panic on failure',
      location: input.path,
      recommendation: 'Use try_borrow() or try_borrow_mut() and handle the error gracefully',
    });
  }

  // Check for RefCell patterns without proper error handling
  if (rust.content.includes('RefCell') && rust.content.includes('.borrow_mut()')) {
    if (!rust.content.includes('try_borrow_mut')) {
      findings.push({
        id: 'SOL066',
        severity: 'medium',
        title: 'RefCell Borrow Without Error Handling',
        description: 'RefCell borrow_mut() will panic if already borrowed',
        location: input.path,
        recommendation: 'Use try_borrow_mut() and handle BorrowMutError appropriately',
      });
    }
  }

  return findings;
}
