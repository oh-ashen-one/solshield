import chalk from 'chalk';
import ora from 'ora';
import { writeFileSync } from 'fs';
import { join } from 'path';
import { auditCommand, type AuditResult } from './audit.js';
import { 
  generateCertificateMetadata, 
  generateCertificateSvg, 
  calculateSeverityScore 
} from '../certificate/metadata.js';

interface CertificateOptions {
  output?: string;
  programId?: string;
}

/**
 * Generate a certificate for an audit
 */
export async function certificateCommand(path: string, options: CertificateOptions) {
  const spinner = ora('Running audit...').start();

  try {
    // Suppress audit display output — we just need the result
    const originalLog = console.log;
    console.log = () => {};
    let result: AuditResult;
    try {
      result = await auditCommand(path, { output: 'json', verbose: false });
    } finally {
      console.log = originalLog;
    }

    // Generate certificate
    spinner.text = 'Generating certificate...';
    
    const programId = options.programId || 'Unknown';
    const severityScore = calculateSeverityScore(result);
    const metadata = generateCertificateMetadata(result, programId);
    const svg = generateCertificateSvg(programId, result.passed, result.summary, result.timestamp);

    // Output files
    const outputDir = options.output || '.';
    const metadataPath = join(outputDir, 'certificate-metadata.json');
    const svgPath = join(outputDir, 'certificate.svg');

    writeFileSync(metadataPath, JSON.stringify(metadata, null, 2));
    writeFileSync(svgPath, svg);

    spinner.succeed('Certificate generated!');

    // Display summary
    console.log('');
    console.log(chalk.bold('  Certificate Summary'));
    console.log(chalk.gray('  ─'.repeat(25)));
    console.log('');
    console.log(`  Status: ${result.passed ? chalk.green('✅ PASSED') : chalk.red('❌ FAILED')}`);
    console.log(`  Severity Score: ${chalk.yellow(severityScore + '/100')} ${severityScore === 0 ? '(Perfect!)' : ''}`);
    console.log('');
    console.log(`  Findings:`);
    console.log(`    ${chalk.red('Critical:')} ${result.summary.critical}`);
    console.log(`    ${chalk.yellow('High:')} ${result.summary.high}`);
    console.log(`    ${chalk.blue('Medium:')} ${result.summary.medium}`);
    console.log(`    ${chalk.gray('Low:')} ${result.summary.low}`);
    console.log('');
    console.log(chalk.gray(`  Metadata: ${metadataPath}`));
    console.log(chalk.gray(`  SVG: ${svgPath}`));
    console.log('');

    if (result.passed) {
      console.log(chalk.green('  🏆 This program is ready for NFT certificate minting!'));
    } else {
      console.log(chalk.yellow('  ⚠️  Fix the issues above before minting a certificate.'));
    }
    console.log('');

  } catch (error: any) {
    spinner.fail(`Certificate generation failed: ${error.message}`);
    process.exit(1);
  }
}
