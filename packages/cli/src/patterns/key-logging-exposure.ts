import type { Finding } from '../commands/audit.js';
import type { ParsedRust } from '../parsers/rust.js';

/**
 * Key Logging Exposure Patterns
 * 
 * Based on Slope Wallet exploit (Aug 2022) where the mobile app
 * transmitted encrypted seed phrases to a central logging server,
 * leading to $8M stolen from 9,000+ wallets.
 * 
 * Detects:
 * - Seed phrase/private key logging
 * - Sensitive data transmission
 * - Insecure key storage patterns
 * - Wallet security anti-patterns
 */

export function checkKeyLoggingExposure(parsed: ParsedRust): Finding[] {
  const findings: Finding[] = [];
  const content = parsed.content;

  // Pattern 1: Logging private keys or seeds
  if (/log|print|debug|trace|info!/i.test(content) && /private.*key|secret.*key|seed.*phrase|mnemonic|keypair/i.test(content)) {
    findings.push({
      id: 'PRIVATE_KEY_LOGGING',
      severity: 'critical',
      title: 'Private Key or Seed Phrase May Be Logged',
      description: 'Code appears to log private keys or seed phrases. Slope Wallet lost $8M because seed phrases were sent to logging servers.',
      location: parsed.path,
      recommendation: 'NEVER log private keys, seed phrases, or any secret material. Remove all logging of sensitive data immediately.'
    });
  }

  // Pattern 2: Transmitting secrets to external servers
  if (/http|https|api|server|endpoint|remote/i.test(content) && /key|secret|seed|mnemonic|password/i.test(content)) {
    if (!/encrypt.*before|hash.*before|never.*transmit/i.test(content)) {
      findings.push({
        id: 'SECRET_TRANSMISSION_RISK',
        severity: 'critical',
        title: 'Secrets May Be Transmitted to External Server',
        description: 'Code may transmit secrets to external servers. Even encrypted transmission is dangerous - Slope encrypted seeds but they were still compromised.',
        location: parsed.path,
        recommendation: 'Never transmit private keys or seed phrases to any server. All cryptographic operations should happen client-side.'
      });
    }
  }

  // Pattern 3: Storing keys in plaintext
  if (/store|save|persist|write.*file/i.test(content) && /private.*key|secret|seed|mnemonic/i.test(content)) {
    if (!/encrypt|cipher|protected|keychain|secure.*enclave/i.test(content)) {
      findings.push({
        id: 'PLAINTEXT_KEY_STORAGE',
        severity: 'critical',
        title: 'Keys May Be Stored in Plaintext',
        description: 'Private keys or seeds may be stored without encryption. Compromised storage leads to total fund loss.',
        location: parsed.path,
        recommendation: 'Always encrypt keys at rest using secure key derivation. Use platform secure storage (Keychain, Secure Enclave).'
      });
    }
  }

  // Pattern 4: Seed phrase in memory too long
  if (/seed|mnemonic|phrase/i.test(content) && /string|vec|buffer|array/i.test(content)) {
    if (!/zeroize|clear|wipe|secure.*drop/i.test(content)) {
      findings.push({
        id: 'SEED_NOT_ZEROIZED',
        severity: 'high',
        title: 'Seed Phrase May Not Be Zeroized After Use',
        description: 'Seed phrases should be cleared from memory immediately after use to prevent memory dump attacks.',
        location: parsed.path,
        recommendation: 'Use zeroize crate to securely clear sensitive data from memory. Minimize time secrets exist in memory.'
      });
    }
  }

  // Pattern 5: Error messages exposing secrets
  if (/error|err!|panic|unwrap|expect/i.test(content) && /key|secret|seed|password/i.test(content)) {
    if (/format!.*key|format!.*secret|display.*key/i.test(content)) {
      findings.push({
        id: 'ERROR_EXPOSES_SECRET',
        severity: 'high',
        title: 'Error Messages May Expose Secrets',
        description: 'Error messages may include secret data which could be logged or displayed to users.',
        location: parsed.path,
        recommendation: 'Never include secrets in error messages. Use generic error messages for secret-related failures.'
      });
    }
  }

  // Pattern 6: Clipboard access with secrets
  if (/clipboard|copy|paste/i.test(content) && /key|secret|seed|address/i.test(content)) {
    findings.push({
      id: 'CLIPBOARD_SECRET_RISK',
      severity: 'medium',
      title: 'Clipboard Used With Sensitive Data',
      description: 'Clipboard operations with secrets are risky. Malware can monitor clipboard. Seeds copied to clipboard can persist.',
      location: parsed.path,
      recommendation: 'Avoid clipboard for private keys/seeds. If necessary, clear clipboard after short timeout and warn users.'
    });
  }

  // Pattern 7: Telemetry/analytics with sensitive context
  if (/telemetry|analytics|tracking|metrics|sentry|crashlytics/i.test(content)) {
    if (!/redact|sanitize|filter.*sensitive|exclude.*secret/i.test(content)) {
      findings.push({
        id: 'TELEMETRY_SECRET_LEAK',
        severity: 'high',
        title: 'Telemetry May Leak Sensitive Information',
        description: 'Analytics/telemetry systems can accidentally capture sensitive data in stack traces or context.',
        location: parsed.path,
        recommendation: 'Implement strict data sanitization before sending telemetry. Never include wallet addresses or transaction data.'
      });
    }
  }

  // Pattern 8: Backup/export without encryption
  if (/backup|export|dump|serialize/i.test(content) && /wallet|account|key/i.test(content)) {
    if (!/password.*protect|encrypt.*export|secure.*backup/i.test(content)) {
      findings.push({
        id: 'BACKUP_NOT_ENCRYPTED',
        severity: 'high',
        title: 'Wallet Backup May Not Be Encrypted',
        description: 'Wallet exports/backups should always be encrypted. Unencrypted backups are easy targets.',
        location: parsed.path,
        recommendation: 'Always require password encryption for wallet backups. Use strong key derivation (Argon2, scrypt).'
      });
    }
  }

  // Pattern 9: Key derivation from weak source
  if (/derive.*key|key.*from|generate.*from/i.test(content)) {
    if (/timestamp|user.*id|email|username|predictable/i.test(content)) {
      findings.push({
        id: 'WEAK_KEY_DERIVATION',
        severity: 'critical',
        title: 'Keys Derived From Weak/Predictable Source',
        description: 'Keys appear to be derived from predictable sources. Attackers can brute-force weak derivation inputs.',
        location: parsed.path,
        recommendation: 'Use cryptographically secure random number generators. Never derive keys from predictable data.'
      });
    }
  }

  // Pattern 10: Debug mode exposing secrets
  if (/debug|dev.*mode|development/i.test(content) && /key|secret|seed/i.test(content)) {
    if (!/cfg.*not.*debug|#\[cfg\(not\(debug/i.test(content)) {
      findings.push({
        id: 'DEBUG_MODE_SECRET_EXPOSURE',
        severity: 'high',
        title: 'Debug Mode May Expose Secrets',
        description: 'Secret handling may differ in debug mode. Ensure debug features never expose real secrets.',
        location: parsed.path,
        recommendation: 'Use conditional compilation to remove all secret logging in release builds. Test with production configs.'
      });
    }
  }

  return findings;
}
