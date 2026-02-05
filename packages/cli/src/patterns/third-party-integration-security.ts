import type { Finding } from '../commands/audit.js';
import type { ParsedRust } from '../parsers/rust.js';

/**
 * Third Party Integration Security Patterns
 * 
 * Based on Thunder Terminal exploit (Dec 2023) where a compromised
 * MongoDB connection URL allowed attackers to steal $240K.
 * Also covers Web3.js supply chain attack and general dependency risks.
 * 
 * Detects:
 * - Database connection string exposure
 * - Third-party service vulnerabilities
 * - Dependency injection risks
 * - Supply chain attack vectors
 */

export function checkThirdPartyIntegrationSecurity(parsed: ParsedRust): Finding[] {
  const findings: Finding[] = [];
  const content = parsed.content;

  // Pattern 1: Database connection strings in code
  if (/mongodb|postgres|mysql|redis|database.*url|connection.*string/i.test(content)) {
    if (/mongodb:\/\/|postgres:\/\/|mysql:\/\/|redis:\/\//i.test(content)) {
      findings.push({
        id: 'DATABASE_URL_HARDCODED',
        severity: 'critical',
        title: 'Database Connection String in Code',
        description: 'Database URLs should never be in code. Thunder Terminal lost $240K when MongoDB connection was compromised.',
        location: parsed.path,
        recommendation: 'Use environment variables for all connection strings. Rotate credentials regularly. Use secrets management.'
      });
    }
  }

  // Pattern 2: API keys in source code
  if (/api_key|apikey|secret_key|access_token/i.test(content)) {
    if (/=\s*["'][A-Za-z0-9]{20,}["']/i.test(content)) {
      findings.push({
        id: 'API_KEY_HARDCODED',
        severity: 'critical',
        title: 'API Key Hardcoded in Source',
        description: 'API keys in source code can be extracted and abused. Supply chain attacks can exfiltrate these keys.',
        location: parsed.path,
        recommendation: 'Move all API keys to environment variables or secure secrets management. Never commit secrets to git.'
      });
    }
  }

  // Pattern 3: Third-party URL without validation
  if (/http.*client|fetch|request|axios|reqwest/i.test(content) && /external|third.*party|api\./i.test(content)) {
    if (!/verify.*ssl|validate.*cert|allowlist.*domain/i.test(content)) {
      findings.push({
        id: 'THIRD_PARTY_URL_NOT_VALIDATED',
        severity: 'high',
        title: 'Third-Party URLs Not Validated',
        description: 'External API calls without domain validation. Man-in-the-middle attacks possible if attacker controls DNS.',
        location: parsed.path,
        recommendation: 'Whitelist allowed external domains. Verify SSL certificates. Use certificate pinning for critical services.'
      });
    }
  }

  // Pattern 4: npm/cargo dependency without version pinning
  if (/dependencies|package\.json|Cargo\.toml/i.test(content)) {
    if (/[*]|latest|>=|~|\^[0-9]/i.test(content) && !/lock/i.test(content)) {
      findings.push({
        id: 'DEPENDENCY_NOT_PINNED',
        severity: 'high',
        title: 'Dependencies Not Version-Pinned',
        description: 'Unpinned dependencies allow supply chain attacks. Web3.js attack (Dec 2024) compromised unpinned versions.',
        location: parsed.path,
        recommendation: 'Pin exact dependency versions. Use lockfiles. Audit dependency updates before merging.'
      });
    }
  }

  // Pattern 5: External service without fallback
  if (/external.*service|third.*party|api.*call/i.test(content)) {
    if (!/fallback|backup|retry|circuit.*breaker/i.test(content)) {
      findings.push({
        id: 'NO_EXTERNAL_SERVICE_FALLBACK',
        severity: 'medium',
        title: 'No Fallback for External Service Failure',
        description: 'Critical external service without fallback. Service compromise or outage could affect protocol.',
        location: parsed.path,
        recommendation: 'Implement fallback providers. Add circuit breakers. Design for external service unavailability.'
      });
    }
  }

  // Pattern 6: Webhook/callback URL injection
  if (/webhook|callback.*url|notify.*url|postback/i.test(content)) {
    if (!/validate.*url|whitelist.*callback|verify.*origin/i.test(content)) {
      findings.push({
        id: 'WEBHOOK_URL_INJECTION',
        severity: 'high',
        title: 'Webhook URL May Be Injectable',
        description: 'User-controlled callback URLs without validation. Attackers could intercept sensitive data.',
        location: parsed.path,
        recommendation: 'Whitelist allowed callback domains. Validate URL format and destination. Use signed webhooks.'
      });
    }
  }

  // Pattern 7: Insecure deserialization from external source
  if (/deserialize|parse.*json|from.*bytes|decode/i.test(content) && /external|api|response/i.test(content)) {
    if (!/validate.*schema|verify.*structure|sanitize/i.test(content)) {
      findings.push({
        id: 'INSECURE_EXTERNAL_DESERIALIZATION',
        severity: 'high',
        title: 'Insecure Deserialization of External Data',
        description: 'Data from external sources deserialized without validation. Could lead to injection attacks.',
        location: parsed.path,
        recommendation: 'Validate all external data against expected schema. Sanitize before processing. Reject malformed data.'
      });
    }
  }

  // Pattern 8: CDN/external script loading
  if (/cdn|script.*src|external.*js|load.*script/i.test(content)) {
    if (!/integrity|sri|hash.*check|subresource/i.test(content)) {
      findings.push({
        id: 'CDN_NO_INTEGRITY_CHECK',
        severity: 'medium',
        title: 'External Scripts Without Integrity Check',
        description: 'Loading scripts from CDN without SRI (Subresource Integrity). CDN compromise could inject malicious code.',
        location: parsed.path,
        recommendation: 'Use Subresource Integrity (SRI) for all external scripts. Self-host critical dependencies when possible.'
      });
    }
  }

  // Pattern 9: RPC provider without validation
  if (/rpc.*provider|rpc.*url|endpoint.*url/i.test(content) && /solana|ethereum|web3/i.test(content)) {
    if (!/verify.*response|validate.*rpc|check.*chain.*id/i.test(content)) {
      findings.push({
        id: 'RPC_PROVIDER_NOT_VALIDATED',
        severity: 'high',
        title: 'RPC Provider Responses Not Validated',
        description: 'Malicious RPC providers can return false data. Validate RPC responses and use multiple providers.',
        location: parsed.path,
        recommendation: 'Use multiple RPC providers and compare responses. Validate critical data against on-chain state.'
      });
    }
  }

  // Pattern 10: OAuth/SSO without state validation
  if (/oauth|sso|openid|auth.*callback/i.test(content)) {
    if (!/state.*param|csrf|nonce.*verify/i.test(content)) {
      findings.push({
        id: 'OAUTH_NO_STATE_VALIDATION',
        severity: 'high',
        title: 'OAuth Without State Parameter Validation',
        description: 'OAuth flow without CSRF protection. Attackers could hijack authentication flow.',
        location: parsed.path,
        recommendation: 'Always validate OAuth state parameter. Use secure random nonces. Verify redirect URIs.'
      });
    }
  }

  return findings;
}
