#!/usr/bin/env bash
set -euo pipefail

HOOK_FILE=".git/hooks/pre-commit"

cat > "$HOOK_FILE" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if command -v secrethawk >/dev/null 2>&1; then
  secrethawk . --only-staged --fail-on high
else
  python -m secrethawk.cli . --only-staged --fail-on high
fi
EOF

chmod +x "$HOOK_FILE"
echo "Installed pre-commit hook: $HOOK_FILE"
