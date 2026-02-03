use anchor_lang::prelude::*;

declare_id!("SoLGUARD1111111111111111111111111111111111");

#[program]
pub mod solguard {
    use super::*;

    /// Register a new audit for a program
    pub fn create_audit(
        ctx: Context<CreateAudit>,
        program_id: Pubkey,
        findings_hash: [u8; 32],
        severity_score: u8,
        critical_count: u8,
        high_count: u8,
        medium_count: u8,
        low_count: u8,
        passed: bool,
    ) -> Result<()> {
        let audit = &mut ctx.accounts.audit;
        let clock = Clock::get()?;
        
        audit.program_id = program_id;
        audit.auditor = ctx.accounts.auditor.key();
        audit.timestamp = clock.unix_timestamp;
        audit.findings_hash = findings_hash;
        audit.severity_score = severity_score;
        audit.critical_count = critical_count;
        audit.high_count = high_count;
        audit.medium_count = medium_count;
        audit.low_count = low_count;
        audit.passed = passed;
        audit.version = 1;
        audit.bump = ctx.bumps.audit;
        
        emit!(AuditCreated {
            program_id,
            auditor: ctx.accounts.auditor.key(),
            passed,
            severity_score,
            timestamp: clock.unix_timestamp,
        });
        
        Ok(())
    }

    /// Verify if a program has a passing audit
    /// Can be called via CPI by other programs
    pub fn verify_audit(ctx: Context<VerifyAudit>) -> Result<bool> {
        let audit = &ctx.accounts.audit;
        
        emit!(AuditVerified {
            program_id: audit.program_id,
            passed: audit.passed,
            verifier: ctx.accounts.verifier.key(),
        });
        
        Ok(audit.passed)
    }

    /// Update registry stats (admin only)
    pub fn initialize_registry(ctx: Context<InitializeRegistry>) -> Result<()> {
        let registry = &mut ctx.accounts.registry;
        registry.authority = ctx.accounts.authority.key();
        registry.total_audits = 0;
        registry.programs_audited = 0;
        registry.bump = ctx.bumps.registry;
        Ok(())
    }

    /// Increment registry counters after audit
    pub fn increment_registry(ctx: Context<IncrementRegistry>) -> Result<()> {
        let registry = &mut ctx.accounts.registry;
        registry.total_audits = registry.total_audits.checked_add(1).unwrap();
        // programs_audited only increments for first audit of a program
        // (would need additional tracking for accurate count)
        Ok(())
    }
}

#[derive(Accounts)]
#[instruction(program_id: Pubkey)]
pub struct CreateAudit<'info> {
    #[account(
        init,
        payer = auditor,
        space = 8 + AuditReport::INIT_SPACE,
        seeds = [b"audit", program_id.as_ref()],
        bump
    )]
    pub audit: Account<'info, AuditReport>,
    
    #[account(mut)]
    pub auditor: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct VerifyAudit<'info> {
    #[account(
        seeds = [b"audit", audit.program_id.as_ref()],
        bump = audit.bump
    )]
    pub audit: Account<'info, AuditReport>,
    
    /// Anyone can verify
    pub verifier: Signer<'info>,
}

#[derive(Accounts)]
pub struct InitializeRegistry<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + AuditRegistry::INIT_SPACE,
        seeds = [b"registry"],
        bump
    )]
    pub registry: Account<'info, AuditRegistry>,
    
    #[account(mut)]
    pub authority: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct IncrementRegistry<'info> {
    #[account(
        mut,
        seeds = [b"registry"],
        bump = registry.bump,
        has_one = authority
    )]
    pub registry: Account<'info, AuditRegistry>,
    
    pub authority: Signer<'info>,
}

#[account]
#[derive(InitSpace)]
pub struct AuditReport {
    /// The program that was audited
    pub program_id: Pubkey,
    /// The agent/account that performed the audit
    pub auditor: Pubkey,
    /// Unix timestamp of the audit
    pub timestamp: i64,
    /// SHA256 hash of the full findings JSON
    pub findings_hash: [u8; 32],
    /// Overall severity score (0-100, lower is better)
    pub severity_score: u8,
    /// Count of critical findings
    pub critical_count: u8,
    /// Count of high severity findings
    pub high_count: u8,
    /// Count of medium severity findings
    pub medium_count: u8,
    /// Count of low severity findings
    pub low_count: u8,
    /// Whether the audit passed (no critical/high issues)
    pub passed: bool,
    /// Audit version (for future upgrades)
    pub version: u8,
    /// PDA bump
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct AuditRegistry {
    /// Registry admin
    pub authority: Pubkey,
    /// Total audits performed
    pub total_audits: u64,
    /// Unique programs audited
    pub programs_audited: u64,
    /// PDA bump
    pub bump: u8,
}

#[event]
pub struct AuditCreated {
    pub program_id: Pubkey,
    pub auditor: Pubkey,
    pub passed: bool,
    pub severity_score: u8,
    pub timestamp: i64,
}

#[event]
pub struct AuditVerified {
    pub program_id: Pubkey,
    pub passed: bool,
    pub verifier: Pubkey,
}
