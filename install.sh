#!/bin/bash
# Guardog Install Script
# Installs dependencies and wires up Claude Code skill

set -e

GUARD_DOG_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILLS_DIR="$HOME/.claude/skills"
HOOKS_DIR="$GUARD_DOG_DIR/bin/hooks"

echo ""
echo "🐕 Guardog Installer"
echo "────────────────────────────────────────"

# 1. Install npm dependencies
echo "📦 Installing dependencies..."
cd "$GUARD_DOG_DIR"
npm install --silent
echo "   Done."

# 2. Create data directory
mkdir -p "$GUARD_DOG_DIR/data"

# 3. Install Claude Code skill
if [ -d "$SKILLS_DIR" ]; then
  cp "$GUARD_DOG_DIR/guardog.md" "$SKILLS_DIR/guardog.md"
  echo "🧠 Claude Code skill installed → $SKILLS_DIR/guardog.md"
else
  echo "⚠️  Claude Code skills directory not found ($SKILLS_DIR)"
  echo "   Manually copy guardog.md to your Claude skills folder."
fi

# 4. Set up global git pre-commit hook (optional)
read -p "
Install git pre-commit hook globally? (scans changed packages before every commit) [y/N] " INSTALL_HOOK
if [[ "$INSTALL_HOOK" =~ ^[Yy]$ ]]; then
  mkdir -p "$HOOKS_DIR"
  cp "$GUARD_DOG_DIR/bin/git-precommit-hook.sh" "$HOOKS_DIR/pre-commit"
  chmod +x "$HOOKS_DIR/pre-commit"
  git config --global core.hooksPath "$HOOKS_DIR"
  echo "   ✅ Git hook installed globally."
fi

# 5. VirusTotal API key setup
echo ""
echo "────────────────────────────────────────"
echo "🔍 VirusTotal API key (highly recommended)"
echo ""
echo "   Free tier: 4 req/min, 500/day — enough for everyday use."
echo "   Sign up at: https://www.virustotal.com/gui/join-us"
echo ""
read -p "   Paste your VirusTotal API key (or press Enter to skip): " VT_KEY
if [ -n "$VT_KEY" ]; then
  echo "VIRUSTOTAL_API_KEY=$VT_KEY" > "$GUARD_DOG_DIR/.env"
  echo "   ✅ Saved to $GUARD_DOG_DIR/.env"
else
  echo "   Skipped. Add it later: echo 'VIRUSTOTAL_API_KEY=your_key' > ~/guardog/.env"
fi

# 6. Done
echo ""
echo "────────────────────────────────────────"
echo "✅ Guardog installed!"
echo ""
echo "Usage:"
echo "  node $GUARD_DOG_DIR/src/index.js analyze lodash npm"
echo "  node $GUARD_DOG_DIR/src/index.js analyze requests pypi"
echo ""
if [ -d "$SKILLS_DIR" ]; then
  echo "  Or in Claude Code: /guardog lodash"
fi
echo ""
