#!/bin/bash
# SolGuard Pre-Commit Hook
# Copy to .git/hooks/pre-commit and chmod +x

echo "🛡️ Running SolGuard security audit..."

# Check if solguard is installed
if ! command -v solguard &> /dev/null; then
    echo "⚠️  SolGuard not found. Install with: npm install -g @solguard/cli"
    exit 0  # Don't block commit, just warn
fi

# Get list of staged Rust files
STAGED_RS=$(git diff --cached --name-only --diff-filter=ACM | grep '\.rs$')

if [ -z "$STAGED_RS" ]; then
    echo "✅ No Rust files staged, skipping audit"
    exit 0
fi

# Run audit on staged files
echo "Checking files:"
echo "$STAGED_RS"
echo ""

# Run solguard and capture output
OUTPUT=$(solguard audit . --format json 2>&1)
EXIT_CODE=$?

# Parse results
CRITICAL=$(echo "$OUTPUT" | grep -c '"severity": "critical"' || echo "0")
HIGH=$(echo "$OUTPUT" | grep -c '"severity": "high"' || echo "0")

if [ "$CRITICAL" -gt 0 ]; then
    echo ""
    echo "❌ BLOCKED: $CRITICAL critical security issue(s) found!"
    echo ""
    echo "Run 'solguard audit .' for details."
    echo "To bypass (not recommended): git commit --no-verify"
    exit 1
fi

if [ "$HIGH" -gt 0 ]; then
    echo ""
    echo "⚠️  WARNING: $HIGH high severity issue(s) found"
    echo "Run 'solguard audit .' for details."
    echo ""
fi

echo "✅ SolGuard check passed"
exit 0
