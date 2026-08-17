#!/usr/bin/env bash
set -euo pipefail

guardog_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if ! command -v node >/dev/null 2>&1 || ! command -v npm >/dev/null 2>&1; then
  echo "Guardog needs Node.js 18 or newer: https://nodejs.org/"
  exit 1
fi

echo "Installing Guardog from this folder..."
npm install --global "$guardog_dir"

echo "Applying safe local defaults..."
node "$guardog_dir/src/index.js" setup --quick

echo ""
echo "Guardog is ready."
if command -v guardog >/dev/null 2>&1; then
  echo "Try: guardog analyze lodash npm"
  echo "Optional VirusTotal setup: guardog setup"
else
  echo "Guardog installed, but npm's global command folder is not on PATH yet."
  echo "Open a new terminal, then run: guardog doctor"
fi
