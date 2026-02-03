# Contributing to SolGuard

Thank you for your interest in contributing to SolGuard! This project was built by AI agents for the Solana Agent Hackathon, but we welcome contributions from both humans and agents.

## Project Structure

```
solguard/
├── packages/
│   ├── cli/        # Command-line auditor
│   ├── web/        # Next.js web interface
│   └── program/    # Anchor on-chain registry
└── examples/       # Test programs
```

## Development Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/oh-ashen-one/solguard.git
   cd solguard
   ```

2. **Install dependencies**
   ```bash
   # CLI
   cd packages/cli
   pnpm install
   pnpm build

   # Web
   cd ../web
   pnpm install
   pnpm dev
   ```

3. **Run tests**
   ```bash
   cd packages/cli
   pnpm test
   ```

## Adding New Vulnerability Patterns

Patterns are located in `packages/cli/src/patterns/`. To add a new pattern:

1. Create a new file `packages/cli/src/patterns/your-pattern.ts`
2. Implement the pattern function:
   ```typescript
   import type { Finding } from '../commands/audit.js';
   import type { PatternInput } from './index.js';

   export function checkYourPattern(input: PatternInput): Finding[] {
     const findings: Finding[] = [];
     // Your detection logic here
     return findings;
   }
   ```
3. Register it in `packages/cli/src/patterns/index.ts`
4. Add tests in `packages/cli/src/test/`

## Pattern Guidelines

- **Minimize false positives**: Better to miss some issues than flood users with noise
- **Provide actionable suggestions**: Every finding should include a fix recommendation
- **Include severity**: critical, high, medium, low, or info
- **Test both positive and negative cases**: Ensure safe code passes

## Commit Messages

We use conventional commits:

- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation
- `chore:` Maintenance
- `test:` Adding tests
- `refactor:` Code refactoring

## Pull Request Process

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests (`pnpm test`)
5. Submit a PR with clear description

## Code of Conduct

Be respectful. We're all here to build cool stuff.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
