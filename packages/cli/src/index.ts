#!/usr/bin/env node
/**
 * SolShield CLI - AI-Powered Smart Contract Security Auditor for Solana
 * 
 * 6,800+ security patterns covering real-world exploits and common vulnerabilities.
 * 
 * Usage:
 *   solshield audit ./programs/my-vault
 *   solshield github owner/repo
 *   solshield fetch <PROGRAM_ID>
 *   solshield watch ./programs/my-vault
 *   solshield ci ./programs/my-vault --fail-on high
 *   solshield certificate ./programs/my-vault
 *   solshield learn SOL001
 *   solshield stats
 *   solshield list
 */

import { Command } from 'commander';
import { scan, type ScanOptions } from './sdk.js';
import { checkCommand } from './commands/check.js';
import { listPatterns, getPatternById } from './patterns/index.js';
import { auditGithub, formatGithubAuditResult } from './commands/github.js';
import { fetchAndAuditCommand, listKnownPrograms } from './commands/fetch.js';
import { watchCommand } from './commands/watch.js';
import { ciCommand } from './commands/ci.js';
import { certificateCommand } from './commands/certificate.js';
import { learnCommand } from './commands/learn.js';
import { statsCommand } from './commands/stats.js';
import { listCommand } from './commands/list.js';
import { swarmAudit } from './swarm/audit.js';
import chalk from 'chalk';

const program = new Command();

program
  .name('solshield')
  .description('AI-Powered Smart Contract Security Auditor for Solana — 6,800+ patterns')
  .version('0.1.0');

// ─── audit ───────────────────────────────────────────────────────────
program
  .command('audit')
  .description('Run a full security audit on a Solana program')
  .argument('<path>', 'Path to program directory or Rust file')
  .option('-f, --format <format>', 'Output format (text|json|markdown)', 'text')
  .option('--ai', 'Include AI-powered explanations')
  .option('--fail-on <severity>', 'Exit with error on severity level (critical|high|medium|low|any)', 'critical')
  .action(async (path: string, options: any) => {
    try {
      console.log(chalk.blue('🛡️  SolShield Security Audit'));
      console.log(chalk.gray(`Scanning: ${path}\n`));
      
      const results = await scan(path, {
        format: options.format === 'json' ? 'json' : 'object',
        ai: options.ai,
        failOn: options.failOn,
      } as ScanOptions);
      
      if (results.findings.length === 0) {
        console.log(chalk.green('✅ No vulnerabilities found!'));
      } else {
        console.log(chalk.yellow(`⚠️  Found ${results.findings.length} potential issues:\n`));
        
        for (const finding of results.findings) {
          const severityColor = 
            finding.severity === 'critical' ? chalk.red :
            finding.severity === 'high' ? chalk.yellow :
            finding.severity === 'medium' ? chalk.cyan :
            chalk.gray;
          
          console.log(`${severityColor(`[${finding.severity.toUpperCase()}]`)} ${finding.id}: ${finding.title}`);
          console.log(chalk.gray(`  └─ ${finding.location.file}${finding.location.line ? `:${finding.location.line}` : ''}`));
          console.log(chalk.gray(`     ${finding.description}`));
          if (finding.suggestion) {
            console.log(chalk.green(`     💡 ${finding.suggestion}`));
          }
          console.log();
        }
      }
      
      console.log(chalk.bold('\n📊 Summary:'));
      console.log(`  ${chalk.red('Critical:')} ${results.summary.critical}`);
      console.log(`  ${chalk.yellow('High:')} ${results.summary.high}`);
      console.log(`  ${chalk.cyan('Medium:')} ${results.summary.medium}`);
      console.log(`  ${chalk.gray('Low:')} ${results.summary.low}`);
      console.log(`  ${chalk.blue('Total:')} ${results.summary.total}`);
      console.log(chalk.gray(`  Duration: ${results.duration}ms\n`));
      
      if (!results.passed) {
        process.exit(1);
      }
    } catch (error: any) {
      console.error(chalk.red(`Error: ${error.message}`));
      process.exit(2);
    }
  });

// ─── github ──────────────────────────────────────────────────────────
program
  .command('github')
  .description('Audit a Solana program directly from a GitHub repo')
  .argument('<repo>', 'GitHub repo (owner/repo or full URL)')
  .option('--pr <number>', 'Audit a specific pull request')
  .option('--branch <name>', 'Audit a specific branch')
  .option('-f, --format <format>', 'Output format (text|json|markdown)', 'text')
  .option('-v, --verbose', 'Verbose output')
  .action(async (repo: string, options: any) => {
    try {
      console.log(chalk.blue('🛡️  SolShield GitHub Audit'));
      console.log(chalk.gray(`Repository: ${repo}\n`));
      
      const result = await auditGithub(repo, {
        pr: options.pr ? parseInt(options.pr) : undefined,
        branch: options.branch,
        output: options.format,
        verbose: options.verbose,
      });

      console.log(formatGithubAuditResult(result, options.format));

      if (result.findings.length > 0) {
        const criticals = result.findings.filter(f => f.severity === 'critical').length;
        if (criticals > 0) process.exit(1);
      }
    } catch (error: any) {
      console.error(chalk.red(`Error: ${error.message}`));
      process.exit(2);
    }
  });

// ─── fetch ───────────────────────────────────────────────────────────
program
  .command('fetch')
  .description('Fetch an on-chain Solana program and audit its IDL')
  .argument('<program_id>', 'Solana program ID (base58 public key)')
  .option('--rpc <url>', 'Solana RPC endpoint URL')
  .option('-f, --format <format>', 'Output format (terminal|json|markdown)', 'terminal')
  .option('--ai', 'Include AI-powered explanations')
  .option('-v, --verbose', 'Verbose output')
  .action(async (programId: string, options: any) => {
    await fetchAndAuditCommand(programId, {
      rpc: options.rpc,
      output: options.format,
      ai: options.ai,
      verbose: options.verbose,
    });
  });

// ─── programs ────────────────────────────────────────────────────────
program
  .command('programs')
  .description('List well-known Solana programs you can fetch and audit')
  .action(() => {
    listKnownPrograms();
  });

// ─── watch ───────────────────────────────────────────────────────────
program
  .command('watch')
  .description('Watch a directory and re-audit on every file change')
  .argument('<path>', 'Path to program directory')
  .option('-f, --format <format>', 'Output format (terminal|json|markdown)', 'terminal')
  .option('--ai', 'Include AI-powered explanations')
  .action(async (path: string, options: any) => {
    await watchCommand(path, {
      output: options.format,
      ai: options.ai,
    });
  });

// ─── ci ──────────────────────────────────────────────────────────────
program
  .command('ci')
  .description('CI mode — GitHub Actions annotations, SARIF output, exit codes')
  .argument('<path>', 'Path to program directory')
  .option('--fail-on <severity>', 'Fail threshold (critical|high|medium|low|any)', 'critical')
  .option('--sarif <file>', 'Write SARIF report to file')
  .option('--summary <file>', 'Write markdown summary to file')
  .action(async (path: string, options: any) => {
    await ciCommand(path, {
      failOn: options.failOn,
      sarif: options.sarif,
      summary: options.summary,
    });
  });

// ─── certificate ─────────────────────────────────────────────────────
program
  .command('certificate')
  .description('Generate an NFT-ready audit certificate (SVG + Metaplex metadata)')
  .argument('<path>', 'Path to program directory')
  .option('-o, --output <dir>', 'Output directory', '.')
  .option('--program-id <id>', 'On-chain program ID for the certificate')
  .action(async (path: string, options: any) => {
    await certificateCommand(path, {
      output: options.output,
      programId: options.programId,
    });
  });

// ─── learn ───────────────────────────────────────────────────────────
program
  .command('learn')
  .description('Learn about a vulnerability pattern or Solana topic with official docs')
  .argument('[query]', 'Pattern ID (SOL001) or topic (pda, cpi, tokens...)')
  .option('--urls', 'Show only documentation URLs')
  .option('--brief', 'Show summary only (no full content)')
  .option('--raw', 'Output raw markdown (for piping to LLMs)')
  .action(async (query: string | undefined, options: any) => {
    await learnCommand(query || '', {
      urls: options.urls,
      brief: options.brief,
      raw: options.raw,
    });
  });

// ─── stats ───────────────────────────────────────────────────────────
program
  .command('stats')
  .description('Show SolShield statistics and capabilities')
  .action(() => {
    statsCommand();
  });

// ─── list ────────────────────────────────────────────────────────────
program
  .command('list')
  .description('List all vulnerability patterns')
  .option('-s, --severity <severity>', 'Filter by severity (critical|high|medium|low)')
  .option('-f, --format <format>', 'Output format (terminal|json|markdown)', 'terminal')
  .action((options: any) => {
    listCommand({
      severity: options.severity,
      output: options.format,
    });
  });

// ─── check (quick pass/fail) ────────────────────────────────────────
program
  .command('check')
  .description('Quick security check (pass/fail)')
  .argument('<path>', 'Path to program directory')
  .option('--fail-on <severity>', 'Fail on severity level', 'critical')
  .option('-q, --quiet', 'Minimal output')
  .action(async (path: string, options: any) => {
    await checkCommand(path, {
      failOn: options.failOn,
      quiet: options.quiet,
    });
  });

// ─── patterns (alias for list) ──────────────────────────────────────
program
  .command('patterns')
  .description('List all available security patterns (alias for "list")')
  .option('--json', 'Output as JSON')
  .option('-s, --severity <severity>', 'Filter by severity')
  .action((options: any) => {
    const patterns = listPatterns();
    
    let filtered = patterns;
    if (options.severity) {
      filtered = patterns.filter(p => p.severity === options.severity);
    }
    
    if (options.json) {
      console.log(JSON.stringify(filtered, null, 2));
    } else {
      console.log(chalk.blue(`\n🛡️  SolShield Security Patterns (${filtered.length} total)\n`));
      
      const bySeverity = {
        critical: filtered.filter(p => p.severity === 'critical'),
        high: filtered.filter(p => p.severity === 'high'),
        medium: filtered.filter(p => p.severity === 'medium'),
        low: filtered.filter(p => p.severity === 'low'),
        info: filtered.filter(p => p.severity === 'info'),
      };
      
      console.log(chalk.red(`Critical (${bySeverity.critical.length}):`));
      bySeverity.critical.slice(0, 10).forEach(p => console.log(`  ${p.id}: ${p.name}`));
      if (bySeverity.critical.length > 10) console.log(chalk.gray(`  ... and ${bySeverity.critical.length - 10} more`));
      
      console.log(chalk.yellow(`\nHigh (${bySeverity.high.length}):`));
      bySeverity.high.slice(0, 10).forEach(p => console.log(`  ${p.id}: ${p.name}`));
      if (bySeverity.high.length > 10) console.log(chalk.gray(`  ... and ${bySeverity.high.length - 10} more`));
      
      console.log(chalk.cyan(`\nMedium (${bySeverity.medium.length}):`));
      bySeverity.medium.slice(0, 10).forEach(p => console.log(`  ${p.id}: ${p.name}`));
      if (bySeverity.medium.length > 10) console.log(chalk.gray(`  ... and ${bySeverity.medium.length - 10} more`));
      
      console.log(chalk.gray(`\nLow (${bySeverity.low.length}):`));
      bySeverity.low.slice(0, 5).forEach(p => console.log(`  ${p.id}: ${p.name}`));
      if (bySeverity.low.length > 5) console.log(chalk.gray(`  ... and ${bySeverity.low.length - 5} more`));
    }
  });

// ─── swarm (multi-agent audit) ──────────────────────────────────────
program
  .command('swarm')
  .description('Run multi-agent security audit with specialized AI agents')
  .argument('<path>', 'Path to program directory or Rust file')
  .option('--mode <mode>', 'Execution mode (api|agent-teams|subprocess|auto)', 'auto')
  .option('--specialists <list>', 'Comma-separated specialists (reentrancy,access-control,arithmetic,oracle)', '')
  .option('-v, --verbose', 'Verbose output')
  .option('--markdown', 'Output as markdown report')
  .action(async (path: string, options: any) => {
    try {
      console.log(chalk.blue('🐝 SolShield Multi-Agent Security Swarm'));
      console.log(chalk.gray(`Target: ${path}`));
      console.log(chalk.gray(`Mode: ${options.mode}\n`));
      
      const specialists = options.specialists 
        ? options.specialists.split(',').map((s: string) => s.trim())
        : undefined;
      
      const result = await swarmAudit({
        target: path,
        mode: options.mode,
        specialists,
        verbose: options.verbose,
        markdown: options.markdown,
      });
      
      if (result.markdownReport) {
        console.log(result.markdownReport);
      } else {
        console.log(chalk.bold(`\n✅ Swarm Audit Complete`));
        console.log(chalk.gray(`  Mode: ${result.mode}`));
        console.log(chalk.gray(`  Duration: ${result.duration}ms`));
        console.log(chalk.gray(`  Agents: ${result.agentResults.length}`));
        
        if (result.synthesis) {
          const s = result.synthesis.summary;
          console.log(chalk.bold('\n📊 Findings Summary:'));
          console.log(`  ${chalk.red('Critical:')} ${s.critical}`);
          console.log(`  ${chalk.yellow('High:')} ${s.high}`);
          console.log(`  ${chalk.cyan('Medium:')} ${s.medium}`);
          console.log(`  ${chalk.gray('Low:')} ${s.low}`);
          console.log(`  ${chalk.blue('Total:')} ${result.findings.length}`);
        }
        
        if (result.errors && result.errors.length > 0) {
          console.log(chalk.yellow('\n⚠️  Warnings:'));
          result.errors.forEach(err => console.log(chalk.gray(`  - ${err}`)));
        }
      }
      
      if (result.synthesis && result.synthesis.summary.critical > 0) {
        process.exit(1);
      }
    } catch (error: any) {
      console.error(chalk.red(`Error: ${error.message}`));
      if (options.verbose && error.stack) {
        console.error(chalk.gray(error.stack));
      }
      process.exit(2);
    }
  });

// ─── version ─────────────────────────────────────────────────────────
program
  .command('version')
  .description('Show version and pattern count')
  .action(() => {
    console.log('solshield v0.1.0');
    console.log(`${listPatterns().length}+ security patterns`);
  });

program.parse();

// Export SDK for programmatic use
export { scan, type ScanOptions, type ScanResult, type Finding } from './sdk.js';
export { listPatterns, getPatternById } from './patterns/index.js';
