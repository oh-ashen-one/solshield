import { VulnerabilityPattern } from '../types';

/**
 * Batch 53: Advanced Anchor Framework Patterns
 * SOL7426-SOL7475 (50 patterns)
 * Focus: Anchor-specific vulnerabilities and best practices
 */
export const anchorAdvancedPatterns: VulnerabilityPattern[] = [
  // Account Constraint Vulnerabilities
  {
    id: 'SOL7426',
    name: 'Missing Init Constraint',
    description: 'Account creation without init constraint allows reinitialization',
    severity: 'critical',
    category: 'anchor',
    pattern: /Account<.*>(?!.*init)|account(?!.*#\[account\(init)/gi,
    recommendation: 'Use init constraint for new account creation'
  },
  {
    id: 'SOL7427',
    name: 'Init Without Payer',
    description: 'Init constraint without payer specification',
    severity: 'high',
    category: 'anchor',
    pattern: /init(?!.*payer)|init.*space(?!.*payer)/gi,
    recommendation: 'Always specify payer with init constraint'
  },
  {
    id: 'SOL7428',
    name: 'Incorrect Space Calculation',
    description: 'Account space calculation doesnt match struct size',
    severity: 'high',
    category: 'anchor',
    pattern: /space\s*=\s*\d+(?!.*size_of)|init.*space.*hardcoded/gi,
    recommendation: 'Use size_of or calculate space dynamically'
  },
  {
    id: 'SOL7429',
    name: 'Missing Mut Constraint',
    description: 'Account modified without mut constraint',
    severity: 'high',
    category: 'anchor',
    pattern: /save\(|serialize\((?!.*mut)|borrow_mut(?!.*#\[account\(mut)/gi,
    recommendation: 'Add mut constraint to accounts being modified'
  },
  {
    id: 'SOL7430',
    name: 'Redundant Mut on Read-Only',
    description: 'Mut constraint on account that is only read',
    severity: 'low',
    category: 'anchor',
    pattern: /mut.*(?!.*save|serialize|modify|update|set)/gi,
    recommendation: 'Remove mut from read-only accounts'
  },

  // Signer and Authority Issues
  {
    id: 'SOL7431',
    name: 'Missing Signer Constraint',
    description: 'Authority account lacks Signer constraint',
    severity: 'critical',
    category: 'anchor',
    pattern: /authority.*AccountInfo(?!.*Signer)|admin.*Account(?!.*Signer)/gi,
    recommendation: 'Use Signer type for authority accounts'
  },
  {
    id: 'SOL7432',
    name: 'Signer Without Has_One',
    description: 'Signer not validated against stored authority',
    severity: 'critical',
    category: 'anchor',
    pattern: /Signer(?!.*has_one)|signer(?!.*constraint)/gi,
    recommendation: 'Add has_one constraint to verify signer matches stored authority'
  },
  {
    id: 'SOL7433',
    name: 'Has_One Target Mismatch',
    description: 'has_one constraint targets wrong field',
    severity: 'critical',
    category: 'anchor',
    pattern: /has_one\s*=\s*\w+(?!.*verify)/gi,
    recommendation: 'Verify has_one constraint matches correct stored field'
  },
  {
    id: 'SOL7434',
    name: 'Multiple Authority Confusion',
    description: 'Multiple authority fields create confusion',
    severity: 'high',
    category: 'anchor',
    pattern: /authority.*authority|admin.*owner|multiple.*signer/gi,
    recommendation: 'Use single, clear authority field'
  },
  {
    id: 'SOL7435',
    name: 'Authority Update Without Check',
    description: 'Authority field updateable without current authority check',
    severity: 'critical',
    category: 'anchor',
    pattern: /authority\s*=|set.*authority(?!.*has_one)/gi,
    recommendation: 'Require current authority signature to update authority'
  },

  // PDA Constraint Issues
  {
    id: 'SOL7436',
    name: 'Seeds Without Bump',
    description: 'Seeds constraint missing bump parameter',
    severity: 'critical',
    category: 'anchor',
    pattern: /seeds\s*=\s*\[(?!.*bump)/gi,
    recommendation: 'Always include bump in seeds constraint'
  },
  {
    id: 'SOL7437',
    name: 'Hardcoded Bump Value',
    description: 'Bump hardcoded instead of derived',
    severity: 'high',
    category: 'anchor',
    pattern: /bump\s*=\s*\d+|bump\s*=\s*ctx\.bumps/gi,
    recommendation: 'Store and verify bump from initial derivation'
  },
  {
    id: 'SOL7438',
    name: 'Dynamic Seeds From User',
    description: 'PDA seeds include unvalidated user input',
    severity: 'high',
    category: 'anchor',
    pattern: /seeds.*ctx\.accounts|seeds.*instruction.*data/gi,
    recommendation: 'Validate and sanitize all user-provided seed components'
  },
  {
    id: 'SOL7439',
    name: 'Missing Seeds Constraint',
    description: 'PDA account without seeds constraint',
    severity: 'high',
    category: 'anchor',
    pattern: /pda.*Account(?!.*seeds)|find_program_address(?!.*constraint)/gi,
    recommendation: 'Use seeds constraint for PDA validation'
  },
  {
    id: 'SOL7440',
    name: 'Seeds Program ID Mismatch',
    description: 'Seeds derived with wrong program ID',
    severity: 'critical',
    category: 'anchor',
    pattern: /seeds.*program_id.*other|cross.*program.*seeds/gi,
    recommendation: 'Verify program ID used in seed derivation'
  },

  // Close Constraint Issues
  {
    id: 'SOL7441',
    name: 'Close Without Destination',
    description: 'Close constraint without specified destination',
    severity: 'high',
    category: 'anchor',
    pattern: /close(?!.*=\s*\w+)/gi,
    recommendation: 'Always specify destination for closed account lamports'
  },
  {
    id: 'SOL7442',
    name: 'Close Destination Mismatch',
    description: 'Close destination is not the expected recipient',
    severity: 'high',
    category: 'anchor',
    pattern: /close\s*=\s*(?!.*authority|owner|payer)/gi,
    recommendation: 'Verify close destination is appropriate recipient'
  },
  {
    id: 'SOL7443',
    name: 'Close Without Zero',
    description: 'Account closed without zeroing data',
    severity: 'critical',
    category: 'anchor',
    pattern: /close(?!.*zero)|close.*account.*data(?!.*clear)/gi,
    recommendation: 'Anchor close should zero discriminator automatically, verify'
  },
  {
    id: 'SOL7444',
    name: 'Premature Account Close',
    description: 'Account closed while still referenced elsewhere',
    severity: 'high',
    category: 'anchor',
    pattern: /close.*reference|close.*before.*complete/gi,
    recommendation: 'Ensure account is not needed before closing'
  },
  {
    id: 'SOL7445',
    name: 'Close Authority Confusion',
    description: 'Wrong authority can close account',
    severity: 'critical',
    category: 'anchor',
    pattern: /close(?!.*has_one)|close.*(?!.*authority.*check)/gi,
    recommendation: 'Add has_one or constraint to verify close authority'
  },

  // Realloc Constraint Issues
  {
    id: 'SOL7446',
    name: 'Realloc Without Payer',
    description: 'Realloc constraint without payer for additional lamports',
    severity: 'high',
    category: 'anchor',
    pattern: /realloc(?!.*payer)|realloc.*space(?!.*payer)/gi,
    recommendation: 'Specify payer for realloc operations'
  },
  {
    id: 'SOL7447',
    name: 'Realloc Size Overflow',
    description: 'Realloc size calculation can overflow',
    severity: 'high',
    category: 'anchor',
    pattern: /realloc.*\+.*unchecked|realloc.*size.*overflow/gi,
    recommendation: 'Use checked arithmetic for realloc calculations'
  },
  {
    id: 'SOL7448',
    name: 'Realloc Zero Check',
    description: 'Realloc constraint without zero option consideration',
    severity: 'medium',
    category: 'anchor',
    pattern: /realloc(?!.*zero\s*=)/gi,
    recommendation: 'Consider realloc::zero for security-sensitive data'
  },
  {
    id: 'SOL7449',
    name: 'Unbounded Realloc',
    description: 'Realloc size not bounded, allowing DoS',
    severity: 'high',
    category: 'anchor',
    pattern: /realloc.*user.*input|realloc.*unbounded/gi,
    recommendation: 'Bound realloc sizes to prevent DoS'
  },
  {
    id: 'SOL7450',
    name: 'Realloc Without Authority',
    description: 'Anyone can trigger realloc on account',
    severity: 'high',
    category: 'anchor',
    pattern: /realloc(?!.*has_one|authority|signer)/gi,
    recommendation: 'Require authority for realloc operations'
  },

  // Token Account Constraints
  {
    id: 'SOL7451',
    name: 'Token Account Mint Mismatch',
    description: 'Token account mint not verified',
    severity: 'critical',
    category: 'anchor',
    pattern: /TokenAccount(?!.*mint)|token.*account(?!.*constraint.*mint)/gi,
    recommendation: 'Add mint constraint to token account'
  },
  {
    id: 'SOL7452',
    name: 'Token Account Authority Skip',
    description: 'Token account authority not verified',
    severity: 'critical',
    category: 'anchor',
    pattern: /TokenAccount(?!.*authority)|token(?!.*owner.*check)/gi,
    recommendation: 'Verify token account authority matches expected'
  },
  {
    id: 'SOL7453',
    name: 'Associated Token Without Init',
    description: 'ATA used without init_if_needed or explicit init',
    severity: 'high',
    category: 'anchor',
    pattern: /associated_token(?!.*init)/gi,
    recommendation: 'Use init_if_needed for associated token accounts'
  },
  {
    id: 'SOL7454',
    name: 'Token Delegate Unchecked',
    description: 'Token delegate authority not verified',
    severity: 'high',
    category: 'anchor',
    pattern: /delegate(?!.*verify)|token.*delegate(?!.*check)/gi,
    recommendation: 'Verify token delegate if using delegated transfers'
  },
  {
    id: 'SOL7455',
    name: 'Token Close Authority',
    description: 'Token close authority not properly set',
    severity: 'medium',
    category: 'anchor',
    pattern: /close_authority(?!.*verify)|token.*close(?!.*owner)/gi,
    recommendation: 'Set and verify close authority appropriately'
  },

  // Error Handling
  {
    id: 'SOL7456',
    name: 'Unwrap Without Error Context',
    description: 'Unwrap used without meaningful error',
    severity: 'medium',
    category: 'anchor',
    pattern: /\.unwrap\(\)(?!.*expect|ok_or)/gi,
    recommendation: 'Use expect() or ok_or() with descriptive error'
  },
  {
    id: 'SOL7457',
    name: 'Error Code Collision',
    description: 'Custom error codes may collide',
    severity: 'low',
    category: 'anchor',
    pattern: /#\[error_code\](?!.*unique)/gi,
    recommendation: 'Ensure error codes are unique and documented'
  },
  {
    id: 'SOL7458',
    name: 'Swallowed Error',
    description: 'Error result ignored or converted to default',
    severity: 'high',
    category: 'anchor',
    pattern: /unwrap_or_default|ok\(\)|result.*ignore/gi,
    recommendation: 'Handle errors explicitly, do not swallow'
  },
  {
    id: 'SOL7459',
    name: 'Require Without Message',
    description: 'Require statement without descriptive error',
    severity: 'low',
    category: 'anchor',
    pattern: /require!\s*\(\s*\w+\s*,\s*\w+\s*\)(?!.*message)/gi,
    recommendation: 'Add descriptive error messages to require statements'
  },
  {
    id: 'SOL7460',
    name: 'Constraint Error Generic',
    description: 'Constraint uses generic error instead of specific',
    severity: 'low',
    category: 'anchor',
    pattern: /constraint\s*=.*ConstraintError|generic.*constraint.*error/gi,
    recommendation: 'Use specific error codes for debugging'
  },

  // State Management
  {
    id: 'SOL7461',
    name: 'State Version Missing',
    description: 'Account state lacks version field for upgrades',
    severity: 'medium',
    category: 'anchor',
    pattern: /#\[account\](?!.*version)|struct.*State(?!.*version)/gi,
    recommendation: 'Include version field for future upgrades'
  },
  {
    id: 'SOL7462',
    name: 'Discriminator Collision Risk',
    description: 'Multiple account types risk discriminator collision',
    severity: 'high',
    category: 'anchor',
    pattern: /#\[account\].*#\[account\]|multiple.*account.*types/gi,
    recommendation: 'Verify Anchor discriminators are unique'
  },
  {
    id: 'SOL7463',
    name: 'Account Size Limit',
    description: 'Account size approaching Solana limits',
    severity: 'medium',
    category: 'anchor',
    pattern: /space.*=.*\d{5,}|large.*account.*size/gi,
    recommendation: 'Consider account splitting if approaching 10MB limit'
  },
  {
    id: 'SOL7464',
    name: 'Nested Account Data',
    description: 'Deeply nested data structures in account',
    severity: 'medium',
    category: 'anchor',
    pattern: /Vec<Vec|nested.*struct.*account/gi,
    recommendation: 'Flatten data structures where possible'
  },
  {
    id: 'SOL7465',
    name: 'Optional Field Serialization',
    description: 'Option fields may not serialize as expected',
    severity: 'medium',
    category: 'anchor',
    pattern: /Option<Pubkey>|Option<.*>.*account/gi,
    recommendation: 'Verify Option field serialization behavior'
  },

  // CPI with Anchor
  {
    id: 'SOL7466',
    name: 'CPI Without Signer Seeds',
    description: 'PDA CPI without proper signer seeds',
    severity: 'critical',
    category: 'anchor',
    pattern: /CpiContext::new(?!.*signer_seeds)|cpi(?!.*with_signer)/gi,
    recommendation: 'Use with_signer for PDA-authorized CPIs'
  },
  {
    id: 'SOL7467',
    name: 'CPI Account Mismatch',
    description: 'CPI accounts dont match target program expectations',
    severity: 'high',
    category: 'anchor',
    pattern: /cpi.*accounts.*mismatch|invoke.*wrong.*accounts/gi,
    recommendation: 'Verify CPI account structure matches target program'
  },
  {
    id: 'SOL7468',
    name: 'CPI Program Verification',
    description: 'CPI target program not verified',
    severity: 'critical',
    category: 'anchor',
    pattern: /CpiContext.*program(?!.*verify)|invoke.*program.*unchecked/gi,
    recommendation: 'Verify CPI target program ID'
  },
  {
    id: 'SOL7469',
    name: 'CPI Remaining Accounts',
    description: 'Remaining accounts passed to CPI without validation',
    severity: 'high',
    category: 'anchor',
    pattern: /remaining_accounts.*cpi|extra.*accounts.*invoke/gi,
    recommendation: 'Validate all remaining accounts before CPI'
  },
  {
    id: 'SOL7470',
    name: 'CPI Return Data',
    description: 'CPI return data not validated',
    severity: 'high',
    category: 'anchor',
    pattern: /get_return_data(?!.*validate)|cpi.*result(?!.*check)/gi,
    recommendation: 'Validate CPI return data format and content'
  },

  // Event and Logging
  {
    id: 'SOL7471',
    name: 'Missing State Change Event',
    description: 'Significant state change without event emission',
    severity: 'medium',
    category: 'anchor',
    pattern: /save\(|modify(?!.*emit)/gi,
    recommendation: 'Emit events for significant state changes'
  },
  {
    id: 'SOL7472',
    name: 'Sensitive Data in Event',
    description: 'Sensitive data exposed in event emission',
    severity: 'medium',
    category: 'anchor',
    pattern: /emit!.*secret|event.*private.*key/gi,
    recommendation: 'Never emit sensitive data in events'
  },
  {
    id: 'SOL7473',
    name: 'Event Size Limit',
    description: 'Event data exceeds practical size limits',
    severity: 'low',
    category: 'anchor',
    pattern: /emit!.*large|event.*vec.*unbounded/gi,
    recommendation: 'Keep event data concise for indexing'
  },
  {
    id: 'SOL7474',
    name: 'Missing Critical Event',
    description: 'Critical operation lacks event for auditability',
    severity: 'medium',
    category: 'anchor',
    pattern: /transfer(?!.*emit)|authority.*change(?!.*event)/gi,
    recommendation: 'Emit events for all critical operations'
  },
  {
    id: 'SOL7475',
    name: 'Event Discriminator',
    description: 'Custom event lacks proper discriminator',
    severity: 'low',
    category: 'anchor',
    pattern: /#\[event\](?!.*discriminator)/gi,
    recommendation: 'Anchor events have automatic discriminators, verify uniqueness'
  }
];

export default anchorAdvancedPatterns;
