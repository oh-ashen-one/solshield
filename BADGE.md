# 🛡️ SolShield Audit Badge

Show that your Solana program has been audited by SolShield!

## Usage

Add this badge to your README:

### Markdown

```markdown
[![Audited by SolShield](https://img.shields.io/badge/Audited%20by-SolShield%20🛡️-brightgreen)](https://github.com/oh-ashen-one/solshield)
```

**Result:** [![Audited by SolShield](https://img.shields.io/badge/Audited%20by-SolShield%20🛡️-brightgreen)](https://github.com/oh-ashen-one/solshield)

### With Status

```markdown
<!-- Passed audit -->
[![SolShield: Passed](https://img.shields.io/badge/SolShield-Passed%20✓-brightgreen)](https://github.com/oh-ashen-one/solshield)

<!-- Has warnings -->
[![SolShield: Warnings](https://img.shields.io/badge/SolShield-Warnings%20⚠️-yellow)](https://github.com/oh-ashen-one/solshield)

<!-- Critical issues -->
[![SolShield: Critical](https://img.shields.io/badge/SolShield-Critical%20🔴-red)](https://github.com/oh-ashen-one/solshield)
```

**Results:**
- [![SolShield: Passed](https://img.shields.io/badge/SolShield-Passed%20✓-brightgreen)](https://github.com/oh-ashen-one/solshield)
- [![SolShield: Warnings](https://img.shields.io/badge/SolShield-Warnings%20⚠️-yellow)](https://github.com/oh-ashen-one/solshield)
- [![SolShield: Critical](https://img.shields.io/badge/SolShield-Critical%20🔴-red)](https://github.com/oh-ashen-one/solshield)

### With Pattern Count

```markdown
[![SolShield: 2400+ Patterns](https://img.shields.io/badge/SolShield-580%2B%20Patterns%20Checked-blue)](https://github.com/oh-ashen-one/solshield)
```

**Result:** [![SolShield: 2400+ Patterns](https://img.shields.io/badge/SolShield-580%2B%20Patterns%20Checked-blue)](https://github.com/oh-ashen-one/solshield)

## Dynamic Badge (Future)

Once on-chain audit registry is deployed, badges will be dynamic:

```markdown
![SolShield Status](https://solshieldai.netlify.app/badge/<PROGRAM_ID>)
```

This will query the on-chain registry and show real-time audit status.

## CI Badge

For GitHub Actions integration:

```yaml
# In your workflow
- name: Run SolShield
  run: solshield ci . --fail-on critical

# Badge shows CI status
[![SolShield CI](https://github.com/YOUR_ORG/YOUR_REPO/actions/workflows/solshield.yml/badge.svg)](https://github.com/YOUR_ORG/YOUR_REPO/actions/workflows/solshield.yml)
```

## Why Use a Badge?

1. **Trust Signal** — Shows you care about security
2. **Transparency** — Visitors know the code was checked
3. **Best Practice** — Encourages security-first culture
4. **Community** — Supports open-source security tooling

---

*Get audited: `npx @solshield/cli audit ./your-program`*

