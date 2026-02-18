#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
# OpenShart — Remote Node Setup
# ═══════════════════════════════════════════════════════════════
#
# Run this on each Mac Mini or DO droplet to prepare it for
# distributed testing.
#
# Usage:
#   curl -sSL <raw-github-url>/scripts/setup-node.sh | bash
#   — or —
#   ./scripts/setup-node.sh
#
# Prerequisites: Node.js >= 20, git
# ═══════════════════════════════════════════════════════════════

set -euo pipefail

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║  OpenShart — Node Setup                          ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""

# ─── Check Node.js ──────────────────────────────────────────
if ! command -v node &>/dev/null; then
  echo "ERROR: Node.js not found. Install Node.js >= 20:"
  echo ""
  echo "  # macOS:"
  echo "  brew install node"
  echo ""
  echo "  # Ubuntu/Debian:"
  echo "  curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -"
  echo "  sudo apt-get install -y nodejs"
  exit 1
fi

NODE_VERSION=$(node -v | sed 's/v//' | cut -d. -f1)
if [ "$NODE_VERSION" -lt 20 ]; then
  echo "ERROR: Node.js >= 20 required, found v$(node -v)"
  exit 1
fi
echo "✓ Node.js $(node -v)"

# ─── Clone or update repo ───────────────────────────────────
REPO_DIR="${OPENSHART_DIR:-$HOME/openshart}"

if [ -d "$REPO_DIR/.git" ]; then
  echo "Updating existing repo at $REPO_DIR..."
  cd "$REPO_DIR"
  git pull --ff-only
else
  echo "Cloning repo to $REPO_DIR..."
  git clone https://github.com/bcharleson/openshart.git "$REPO_DIR"
  cd "$REPO_DIR"
fi

# ─── Install dependencies ───────────────────────────────────
echo "Installing dependencies..."
npm install
npm install pg tsx  # pg for Postgres backend, tsx for running TS scripts

# ─── Install pg peer dependency ──────────────────────────────
echo "Installing pg driver..."
npm install pg

# ─── Verify build ───────────────────────────────────────────
echo "Verifying TypeScript build..."
npx tsc --noEmit

echo ""
echo "✓ Node is ready!"
echo ""
echo "═══════════════════════════════════════════════════════"
echo ""
echo "Next steps:"
echo ""
echo "  1. Set the environment variables (get these from setup-digitalocean.sh output):"
echo ""
echo "     export OPENSHART_PG_URL=\"postgres://user:pass@host:port/db?sslmode=require\""
echo "     export OPENSHART_SHARED_KEY=\"<64-hex-char-key>\""
echo "     export AGENT_COUNT=3"
echo ""
echo "  2. Run the distributed test:"
echo ""
echo "     AGENT_ID=$(hostname) npx tsx scripts/distributed-test.ts"
echo ""
echo "═══════════════════════════════════════════════════════"
