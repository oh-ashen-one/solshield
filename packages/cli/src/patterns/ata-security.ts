import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL072: Associated Token Account Security
 * Detects vulnerabilities in ATA handling
 */
export function checkAtaSecurity(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;

  if (!rust || !rust.content) return findings;

  const hasAta = rust.content.includes('associated_token') ||
                 rust.content.includes('AssociatedToken') ||
                 rust.content.includes('get_associated_token_address');

  if (!hasAta && !rust.content.includes('token_account')) return findings;

  // Check for ATA derivation validation
  if (rust.content.includes('token_account') && rust.content.includes('owner')) {
    if (!rust.content.includes('get_associated_token_address') &&
        !rust.content.includes('associated_token::ID')) {
      findings.push({
        id: 'SOL072',
        severity: 'high',
        title: 'Token Account Without ATA Validation',
        description: 'Token account used without verifying it is the expected ATA',
        location: input.path,
        recommendation: 'Derive expected ATA address and compare with provided account',
      });
    }
  }

  // Check for ATA creation without existence check
  if (rust.content.includes('create_associated_token_account') ||
      rust.content.includes('init_if_needed')) {
    if (!rust.content.includes('try_accounts') && !rust.content.includes('if_needed')) {
      if (!rust.content.includes('is_initialized') && !rust.content.includes('data_len')) {
        findings.push({
          id: 'SOL072',
          severity: 'medium',
          title: 'ATA Creation Without Existence Check',
          description: 'Creating ATA without checking if it already exists',
          location: input.path,
          recommendation: 'Use init_if_needed constraint or check account existence first',
        });
      }
    }
  }

  // Check for hardcoded token program assumption
  if (rust.content.includes('token_account') && rust.content.includes('TokenAccount')) {
    if (!rust.content.includes('Token::ID') && 
        !rust.content.includes('Token2022') &&
        !rust.content.includes('spl_token::')) {
      findings.push({
        id: 'SOL072',
        severity: 'medium',
        title: 'Missing Token Program Validation',
        description: 'Token account used without validating which token program owns it',
        location: input.path,
        recommendation: 'Verify token account owner matches expected token program (SPL or Token-2022)',
      });
    }
  }

  // Check for token account owner trust
  const ownerTrust = /token_account[\s\S]*?\.owner\s*(?!==|!=|\.key)/;
  if (ownerTrust.test(rust.content)) {
    findings.push({
      id: 'SOL072',
      severity: 'high',
      title: 'Token Account Owner Trust',
      description: 'Token account owner field used without validation against expected value',
      location: input.path,
      recommendation: 'Compare token_account.owner with the expected owner pubkey',
    });
  }

  // Check for delegate authority risks
  if (rust.content.includes('delegate') && rust.content.includes('token')) {
    if (!rust.content.includes('delegated_amount') && !rust.content.includes('delegate.is_none')) {
      findings.push({
        id: 'SOL072',
        severity: 'medium',
        title: 'Token Delegate Not Checked',
        description: 'Token operations without checking for active delegate authority',
        location: input.path,
        recommendation: 'Check if token account has delegate set and handle appropriately',
      });
    }
  }

  // Check for close authority risks
  if (rust.content.includes('close') && rust.content.includes('token_account')) {
    if (!rust.content.includes('close_authority')) {
      findings.push({
        id: 'SOL072',
        severity: 'medium',
        title: 'Token Close Authority Not Checked',
        description: 'Token account close without checking close_authority',
        location: input.path,
        recommendation: 'Verify close_authority before closing token accounts',
      });
    }
  }

  // Check for amount validation before transfer
  const transferWithoutCheck = /transfer[\s\S]*?amount[\s\S]*?(?!<=|>=|<|>|==)/;
  if (rust.content.includes('Transfer') && !rust.content.includes('amount <=')) {
    if (!rust.content.includes('checked_') && !rust.content.includes('balance')) {
      findings.push({
        id: 'SOL072',
        severity: 'medium',
        title: 'Transfer Without Balance Check',
        description: 'Token transfer without checking sufficient balance',
        location: input.path,
        recommendation: 'Verify token_account.amount >= transfer_amount before transfer',
      });
    }
  }

  return findings;
}
