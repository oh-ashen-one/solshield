import type { Finding } from '../commands/audit.js';
import type { ParsedRust } from '../parsers/rust.js';

/**
 * Signature Set Spoofing Vulnerabilities
 * Based on: Wormhole $320M exploit
 * 
 * When verifying signatures through delegation chains, each step must be validated.
 * Wormhole was exploited because it didn't verify the SignatureSet account was created
 * by the legitimate Secp256k1 program.
 * 
 * Attack pattern:
 * 1. Create fake SignatureSet account with attacker's data
 * 2. Pass fake SignatureSet to verification function
 * 3. Verification trusts the SignatureSet without checking its origin
 * 4. Attacker bypasses guardian signature verification
 */
export function checkSignatureSetSpoofing(parsed: ParsedRust): Finding[] {
  const findings: Finding[] = [];
  const content = parsed.content;

  // Detect signature verification patterns
  const signaturePatterns = [
    /signature.*?set|guardian.*?signatures?|multi.*?sig.*?verify/gi,
    /secp256k1.*?verify|ed25519.*?verify|sig.*?verification/gi,
    /verify.*?signatures?.*?account/gi,
  ];

  for (const pattern of signaturePatterns) {
    const matches = content.match(pattern);
    if (matches) {
      // Check if signature account origin is verified
      const hasOriginCheck = /owner\s*==.*?secp256k1|owner\s*==.*?ed25519|constraint.*?owner/i.test(content);
      const hasProgramCheck = /program.*?id.*?check|verify.*?program.*?id/i.test(content);

      if (!hasOriginCheck && !hasProgramCheck) {
        findings.push({
          severity: 'critical',
          category: 'signature-spoofing',
          title: 'Signature Set Account Origin Not Verified',
          description: `Signature verification pattern "${matches[0]}" detected but signature set account origin is not verified. ` +
            'Attackers can create fake signature set accounts to bypass verification (Wormhole exploit pattern).',
          recommendation: 'Verify that signature set accounts are owned by the legitimate Secp256k1 or Ed25519 program. ' +
            'Check: account.owner == expected_program_id',
          location: parsed.path,
        });
      }
    }
  }

  // Detect guardian set verification without initialization check
  if (/guardian.*?set|validator.*?set/i.test(content)) {
    const hasInitCheck = /is_initialized|initialized\s*==\s*true|init\s*=\s*true/i.test(content);
    if (!hasInitCheck) {
      findings.push({
        severity: 'high',
        category: 'signature-spoofing',
        title: 'Guardian/Validator Set Initialization Not Checked',
        description: 'Guardian or validator set used without verifying initialization state. ' +
          'Uninitialized accounts could be manipulated.',
        recommendation: 'Always verify guardian/validator set accounts are properly initialized. ' +
          'Check the is_initialized flag before trusting the data.',
        location: parsed.path,
      });
    }
  }

  // Detect delegation of signature verification
  if (/delegate.*?verify|verify.*?delegate|chain.*?verify/i.test(content)) {
    findings.push({
      severity: 'high',
      category: 'signature-spoofing',
      title: 'Delegated Signature Verification Chain',
      description: 'Signature verification is delegated. Each step in the delegation chain must be validated ' +
        'to prevent spoofing of intermediate verification results.',
      recommendation: 'Verify each component in the signature delegation chain: ' +
        '1. Verify the verifier program ID, 2. Verify the result account owner, ' +
        '3. Verify the result data integrity.',
      location: parsed.path,
    });
  }

  // Detect cross-program signature verification
  if (/cpi.*?verify.*?signature|invoke.*?secp256k1|invoke.*?ed25519/i.test(content)) {
    findings.push({
      severity: 'medium',
      category: 'signature-spoofing',
      title: 'Cross-Program Signature Verification',
      description: 'Signature verification uses CPI. Ensure the target program ID is hardcoded ' +
        'and results are validated.',
      recommendation: 'Hardcode the signature verification program ID. ' +
        'Never accept program ID as an instruction argument for security-critical operations.',
      location: parsed.path,
    });
  }

  // Detect secp256k1 usage without proper instruction introspection
  if (/secp256k1|ed25519/i.test(content) && !/instructions_sysvar|instruction.*?introspection/i.test(content)) {
    findings.push({
      severity: 'medium',
      category: 'signature-spoofing',
      title: 'Signature Program Without Instruction Introspection',
      description: 'Secp256k1/Ed25519 operations detected without instruction introspection. ' +
        'Cannot verify that signature verification actually occurred.',
      recommendation: 'Use instruction introspection to verify signature verification instructions ' +
        'were included in the same transaction.',
      location: parsed.path,
    });
  }

  return findings;
}
