import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL082: Token Account Ownership
 * Detects improper token account ownership validation
 */
export function checkTokenOwnership(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;

  if (!rust || !rust.content) return findings;

  const hasTokenAccount = rust.content.includes('TokenAccount') ||
                          rust.content.includes('token_account') ||
                          rust.content.includes('Account<\'info, TokenAccount>');

  if (!hasTokenAccount) return findings;

  // Check for token account without owner constraint
  if (rust.content.includes('TokenAccount') && 
      !rust.content.includes('token::authority') &&
      !rust.content.includes('has_one')) {
    findings.push({
      id: 'SOL082',
      severity: 'critical',
      title: 'Token Account Without Owner Constraint',
      description: 'Token account used without validating owner/authority relationship',
      location: input.path,
      recommendation: 'Add token::authority or has_one constraint to verify ownership',
    });
  }

  // Check for token account mint validation
  if (rust.content.includes('TokenAccount')) {
    if (!rust.content.includes('token::mint') && !rust.content.includes('.mint')) {
      findings.push({
        id: 'SOL082',
        severity: 'high',
        title: 'Token Account Without Mint Validation',
        description: 'Token account used without verifying expected mint',
        location: input.path,
        recommendation: 'Add token::mint constraint or explicitly check .mint field',
      });
    }
  }

  // Check for token transfer without ownership check
  const transferPattern = /(?:Transfer|transfer)\s*{[\s\S]*?from[\s\S]*?to/;
  if (transferPattern.test(rust.content)) {
    if (!rust.content.includes('owner') && !rust.content.includes('authority')) {
      findings.push({
        id: 'SOL082',
        severity: 'critical',
        title: 'Token Transfer Without Authority Check',
        description: 'Token transfer without verifying source account authority',
        location: input.path,
        recommendation: 'Verify authority/owner has permission to transfer from source',
      });
    }
  }

  // Check for escrow patterns
  if (rust.content.includes('escrow') || rust.content.includes('vault')) {
    if (rust.content.includes('TokenAccount')) {
      if (!rust.content.includes('seeds') && !rust.content.includes('PDA')) {
        findings.push({
          id: 'SOL082',
          severity: 'high',
          title: 'Escrow Token Account Not PDA',
          description: 'Escrow/vault token account should be PDA-owned for security',
          location: input.path,
          recommendation: 'Use PDA as token account authority for escrow patterns',
        });
      }
    }
  }

  // Check for token account owner comparison
  const ownerComparison = /token_account[\s\S]*?owner\s*!=|owner\s*!=[\s\S]*?token_account/;
  if (!ownerComparison.test(rust.content) && !rust.content.includes('token::authority')) {
    // Check if there's token operations without owner check
    if (rust.content.includes('Transfer') || rust.content.includes('Burn')) {
      findings.push({
        id: 'SOL082',
        severity: 'high',
        title: 'Token Operations Without Owner Verification',
        description: 'Token transfer/burn without explicit owner verification',
        location: input.path,
        recommendation: 'Verify token_account.owner == expected_owner before operations',
      });
    }
  }

  return findings;
}
