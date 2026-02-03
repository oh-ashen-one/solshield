import chalk from 'chalk';
import { listPatterns } from '../patterns/index.js';

/**
 * Show SolGuard statistics and capabilities
 */
export function statsCommand() {
  const patterns = listPatterns();
  
  console.log('');
  console.log(chalk.bold('  📊 SolGuard Statistics'));
  console.log(chalk.gray('  ─'.repeat(25)));
  console.log('');
  
  // Version info
  console.log(chalk.cyan('  Version:'), '0.1.0');
  console.log(chalk.cyan('  Patterns:'), patterns.length);
  console.log('');
  
  // Pattern breakdown by severity
  const bySeverity = {
    critical: patterns.filter(p => p.severity === 'critical'),
    high: patterns.filter(p => p.severity === 'high'),
    medium: patterns.filter(p => p.severity === 'medium'),
    low: patterns.filter(p => p.severity === 'low'),
  };
  
  console.log(chalk.bold('  Vulnerability Patterns:'));
  console.log('');
  
  // Critical patterns
  if (bySeverity.critical.length > 0) {
    console.log(chalk.red('  🔴 Critical:'));
    for (const p of bySeverity.critical) {
      console.log(chalk.gray(`     ${p.id}: ${p.name}`));
    }
    console.log('');
  }
  
  // High patterns
  if (bySeverity.high.length > 0) {
    console.log(chalk.yellow('  🟠 High:'));
    for (const p of bySeverity.high) {
      console.log(chalk.gray(`     ${p.id}: ${p.name}`));
    }
    console.log('');
  }
  
  // Medium patterns
  if (bySeverity.medium.length > 0) {
    console.log(chalk.blue('  🟡 Medium:'));
    for (const p of bySeverity.medium) {
      console.log(chalk.gray(`     ${p.id}: ${p.name}`));
    }
    console.log('');
  }
  
  // Capabilities
  console.log(chalk.bold('  Capabilities:'));
  console.log('');
  console.log(chalk.green('  ✓'), 'Anchor IDL parsing');
  console.log(chalk.green('  ✓'), 'Rust source code analysis');
  console.log(chalk.green('  ✓'), 'AI-powered explanations');
  console.log(chalk.green('  ✓'), 'On-chain program fetching');
  console.log(chalk.green('  ✓'), 'NFT certificate generation');
  console.log(chalk.green('  ✓'), 'Watch mode for development');
  console.log(chalk.green('  ✓'), 'JSON/Markdown output');
  console.log('');
  
  // Commands
  console.log(chalk.bold('  Available Commands:'));
  console.log('');
  console.log(chalk.cyan('  solguard audit <path>'), '      Audit a program');
  console.log(chalk.cyan('  solguard fetch <program-id>'), 'Fetch and audit on-chain');
  console.log(chalk.cyan('  solguard certificate <path>'), 'Generate NFT certificate');
  console.log(chalk.cyan('  solguard watch <path>'), '      Watch and auto-audit');
  console.log(chalk.cyan('  solguard programs'), '          List known programs');
  console.log(chalk.cyan('  solguard stats'), '             Show this info');
  console.log('');
  
  // Footer
  console.log(chalk.gray('  Built by Midir for Solana Agent Hackathon 2026'));
  console.log(chalk.gray('  https://github.com/oh-ashen-one/solguard'));
  console.log('');
}
