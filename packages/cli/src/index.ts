#!/usr/bin/env node
/**
 * SolShield CLI
 * 
 * AI-powered smart contract security scanner for Solana
 */

import { Command } from 'commander';
import chalk from 'chalk';
import { checkCommand } from './commands/check.js';
import { listCommand } from './commands/list.js';
import { statsCommand } from './commands/stats.js';

const program = new Command();

program
  .name('solshield')
  .description('AI-powered smart contract security scanner for Solana')
  .version('0.1.0');

program
  .command('audit <path>')
  .description('Audit a Solana program for vulnerabilities')
  .option('-o, --output <format>', 'Output format (text, json, sarif)', 'text')
  .option('-v, --verbose', 'Show detailed output')
  .option('--fail-on <severity>', 'Fail on severity level (critical, high, medium, low)', 'critical')
  .action(async (path, options) => {
    await checkCommand(path, { 
      failOn: options.failOn,
      quiet: !options.verbose 
    });
  });

program
  .command('check <path>')
  .description('Quick pass/fail security check')
  .option('--fail-on <severity>', 'Fail on severity level', 'critical')
  .option('-q, --quiet', 'Minimal output')
  .action(async (path, options) => {
    await checkCommand(path, {
      failOn: options.failOn,
      quiet: options.quiet,
    });
  });

program
  .command('patterns')
  .alias('list')
  .description('List all vulnerability patterns')
  .option('-s, --severity <level>', 'Filter by severity')
  .option('-c, --category <cat>', 'Filter by category')
  .action(async (options) => {
    await listCommand(options);
  });

program
  .command('stats')
  .description('Show pattern statistics')
  .action(async () => {
    await statsCommand();
  });

// Parse and execute
program.parse();
