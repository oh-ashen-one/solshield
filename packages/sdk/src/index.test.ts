/**
 * SolShield SDK Tests
 */

import { describe, it, expect } from 'vitest';
import { scan, listPatterns, getPattern, getPatternsBySeverity, getPatternCount, version } from './index';

describe('SolShield SDK', () => {
  describe('listPatterns', () => {
    it('should return an array of patterns', () => {
      const patterns = listPatterns();
      expect(Array.isArray(patterns)).toBe(true);
      expect(patterns.length).toBeGreaterThan(0);
    });

    it('should have patterns with required fields', () => {
      const patterns = listPatterns();
      const pattern = patterns[0];
      expect(pattern).toHaveProperty('id');
      expect(pattern).toHaveProperty('name');
      expect(pattern).toHaveProperty('severity');
      expect(pattern).toHaveProperty('description');
    });
  });

  describe('getPattern', () => {
    it('should return pattern by ID', () => {
      const pattern = getPattern('SOL001');
      expect(pattern).toBeDefined();
      expect(pattern?.id).toBe('SOL001');
    });

    it('should return undefined for non-existent pattern', () => {
      const pattern = getPattern('SOL999');
      expect(pattern).toBeUndefined();
    });
  });

  describe('getPatternsBySeverity', () => {
    it('should return patterns by severity', () => {
      const criticalPatterns = getPatternsBySeverity('critical');
      expect(Array.isArray(criticalPatterns)).toBe(true);
      criticalPatterns.forEach(p => {
        expect(p.severity).toBe('critical');
      });
    });
  });

  describe('getPatternCount', () => {
    it('should return number of patterns', () => {
      const count = getPatternCount();
      expect(typeof count).toBe('number');
      expect(count).toBeGreaterThan(100); // We have 150+ patterns
    });
  });

  describe('version', () => {
    it('should return version string', () => {
      const v = version();
      expect(typeof v).toBe('string');
      expect(v).toMatch(/^\d+\.\d+\.\d+$/);
    });
  });

  describe('scan', () => {
    it('should detect missing owner check', async () => {
      const code = `
        pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
            let vault = &mut ctx.accounts.vault;
            // Missing: if vault.owner != ctx.accounts.authority.key()
            **vault.to_account_info().try_borrow_mut_lamports()? -= amount;
            Ok(())
        }
      `;
      const result = await scan(code);
      expect(result.findings.length).toBeGreaterThan(0);
      expect(result.summary.total).toBeGreaterThan(0);
    });

    it('should detect missing signer check', async () => {
      const code = `
        pub fn transfer(ctx: Context<Transfer>) -> Result<()> {
            // Missing: require!(ctx.accounts.authority.is_signer)
            let from = &ctx.accounts.from;
            let to = &ctx.accounts.to;
            Ok(())
        }
      `;
      const result = await scan(code);
      expect(result.findings.length).toBeGreaterThan(0);
    });

    it('should detect potential issues in arithmetic', async () => {
      const code = `
        pub fn add_balance(ctx: Context<Add>, amount: u64) -> Result<()> {
            let vault = &mut ctx.accounts.vault;
            vault.balance = vault.balance + amount; // Potential overflow
            // Missing owner check, missing signer check
            Ok(())
        }
      `;
      const result = await scan(code);
      // Should find at least missing checks
      expect(result.findings.length).toBeGreaterThan(0);
    });

    it('should scan code with proper checks', async () => {
      const code = `
        use anchor_lang::prelude::*;
        
        pub fn safe_transfer(ctx: Context<SafeTransfer>, amount: u64) -> Result<()> {
            require!(ctx.accounts.authority.is_signer, ErrorCode::Unauthorized);
            require!(ctx.accounts.vault.owner == ctx.accounts.authority.key(), ErrorCode::InvalidOwner);
            let vault = &mut ctx.accounts.vault;
            vault.balance = vault.balance.checked_sub(amount).ok_or(ErrorCode::Overflow)?;
            Ok(())
        }
      `;
      const result = await scan(code);
      // Should return valid result structure
      expect(result).toHaveProperty('findings');
      expect(result).toHaveProperty('summary');
    });

    it('should return proper structure', async () => {
      const result = await scan('pub fn test() {}');
      expect(result).toHaveProperty('timestamp');
      expect(result).toHaveProperty('findings');
      expect(result).toHaveProperty('summary');
      expect(result).toHaveProperty('passed');
      expect(result).toHaveProperty('patternsUsed');
    });
  });
});
