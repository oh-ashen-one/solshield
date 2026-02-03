import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL071: Metaplex/NFT Metadata Security
 * Detects vulnerabilities in Metaplex NFT handling
 */
export function checkMetaplexSecurity(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;

  if (!rust || !rust.content) return findings;

  const hasMetaplex = rust.content.includes('mpl_token_metadata') ||
                      rust.content.includes('Metadata') ||
                      rust.content.includes('metaplex') ||
                      rust.content.includes('metadata_program');

  if (!hasMetaplex) return findings;

  // Check for metadata account validation
  if (rust.content.includes('Metadata') && !rust.content.includes('metadata::ID')) {
    if (!rust.content.includes('mpl_token_metadata::ID') && 
        !rust.content.includes('TOKEN_METADATA_PROGRAM_ID')) {
      findings.push({
        id: 'SOL071',
        severity: 'critical',
        title: 'Missing Metadata Program Validation',
        description: 'Metadata account used without validating owner is Metaplex Token Metadata program',
        location: input.path,
        recommendation: 'Verify metadata.owner == mpl_token_metadata::ID',
      });
    }
  }

  // Check for edition validation
  if (rust.content.includes('Edition') || rust.content.includes('MasterEdition')) {
    if (!rust.content.includes('edition_bump') && !rust.content.includes('find_master_edition')) {
      findings.push({
        id: 'SOL071',
        severity: 'high',
        title: 'Missing Edition PDA Validation',
        description: 'Edition account used without validating PDA derivation',
        location: input.path,
        recommendation: 'Derive expected edition PDA and compare with provided account',
      });
    }
  }

  // Check for creator verification
  if (rust.content.includes('creators') || rust.content.includes('Creator')) {
    if (!rust.content.includes('verified') && !rust.content.includes('is_verified')) {
      findings.push({
        id: 'SOL071',
        severity: 'high',
        title: 'Unchecked Creator Verification',
        description: 'Creator field accessed without checking verified status',
        location: input.path,
        recommendation: 'Check creator.verified == true before trusting creator identity',
      });
    }
  }

  // Check for collection verification
  if (rust.content.includes('collection')) {
    if (!rust.content.includes('collection.verified') && 
        !rust.content.includes('is_collection_verified')) {
      findings.push({
        id: 'SOL071',
        severity: 'high',
        title: 'Unchecked Collection Verification',
        description: 'Collection field used without verifying it is authenticated',
        location: input.path,
        recommendation: 'Verify collection.verified == true before trusting collection membership',
      });
    }
  }

  // Check for metadata parsing without validation
  if (rust.content.includes('try_from_slice') && rust.content.includes('Metadata')) {
    if (!rust.content.includes('key ==') && !rust.content.includes('discriminator')) {
      findings.push({
        id: 'SOL071',
        severity: 'medium',
        title: 'Metadata Parsing Without Type Check',
        description: 'Deserializing Metadata without checking discriminator/key',
        location: input.path,
        recommendation: 'Use Metadata::from_account_info which validates the account type',
      });
    }
  }

  // Check for primary sale handling
  if (rust.content.includes('primary_sale') || rust.content.includes('seller_fee')) {
    if (rust.content.includes('royalt') && !rust.content.includes('primary_sale_happened')) {
      findings.push({
        id: 'SOL071',
        severity: 'medium',
        title: 'Missing Primary Sale Check',
        description: 'Royalty logic without checking primary_sale_happened flag',
        location: input.path,
        recommendation: 'Check primary_sale_happened before applying royalty calculations',
      });
    }
  }

  // Check for token standard handling
  if (rust.content.includes('TokenStandard') || rust.content.includes('pNFT')) {
    if (!rust.content.includes('ProgrammableNonFungible') && 
        rust.content.includes('transfer')) {
      findings.push({
        id: 'SOL071',
        severity: 'medium',
        title: 'pNFT Transfer Rules',
        description: 'NFT transfer may not account for programmable NFT rules',
        location: input.path,
        recommendation: 'Check TokenStandard and use appropriate transfer method for pNFTs',
      });
    }
  }

  return findings;
}
