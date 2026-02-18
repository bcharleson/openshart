#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
# OpenShart — DigitalOcean Infrastructure Setup
# ═══════════════════════════════════════════════════════════════
#
# Prerequisites:
#   1. Install doctl: brew install doctl
#   2. Authenticate:  doctl auth init
#   3. Install jq:    brew install jq
#
# Usage:
#   ./scripts/setup-digitalocean.sh
#
# What this creates:
#   - A managed Postgres cluster (1 node, $15/mo)
#   - A database named 'openshart'
#   - A dedicated DB user
#   - Outputs the connection string and shared encryption key
# ═══════════════════════════════════════════════════════════════

set -euo pipefail

# ─── Configuration ───────────────────────────────────────────
CLUSTER_NAME="openshart-db"
DB_NAME="openshart"
DB_USER="openshart"
REGION="nyc1"          # Change to your preferred region
PG_VERSION="17"
NODE_SIZE="db-s-1vcpu-1gb"  # Smallest managed PG ($15/mo)

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║  OpenShart — DigitalOcean Setup                  ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""

# ─── Check prerequisites ────────────────────────────────────
if ! command -v doctl &>/dev/null; then
  echo "ERROR: doctl not found. Install it:"
  echo "  brew install doctl"
  echo "  doctl auth init"
  exit 1
fi

if ! command -v jq &>/dev/null; then
  echo "ERROR: jq not found. Install it:"
  echo "  brew install jq"
  exit 1
fi

# Verify auth
if ! doctl account get &>/dev/null; then
  echo "ERROR: doctl not authenticated. Run:"
  echo "  doctl auth init"
  exit 1
fi

echo "✓ doctl authenticated"
echo ""

# ─── Create Postgres cluster ────────────────────────────────
echo "Creating managed Postgres cluster..."
echo "  Name:    $CLUSTER_NAME"
echo "  Region:  $REGION"
echo "  Version: PostgreSQL $PG_VERSION"
echo "  Size:    $NODE_SIZE"
echo ""

# Check if cluster already exists
if doctl databases list --format Name --no-header | grep -q "^${CLUSTER_NAME}$"; then
  echo "Cluster '$CLUSTER_NAME' already exists. Reusing it."
  CLUSTER_ID=$(doctl databases list --format ID,Name --no-header | grep "$CLUSTER_NAME" | awk '{print $1}')
else
  CLUSTER_ID=$(doctl databases create "$CLUSTER_NAME" \
    --engine pg \
    --version "$PG_VERSION" \
    --region "$REGION" \
    --size "$NODE_SIZE" \
    --num-nodes 1 \
    --output json | jq -r '.[0].id')

  echo "Cluster created: $CLUSTER_ID"
  echo ""
  echo "Waiting for cluster to be ready (this takes 3-5 minutes)..."

  while true; do
    STATUS=$(doctl databases get "$CLUSTER_ID" --format Status --no-header 2>/dev/null || echo "creating")
    if [ "$STATUS" = "online" ]; then
      echo "✓ Cluster is online!"
      break
    fi
    echo "  Status: $STATUS — waiting..."
    sleep 15
  done
fi

echo ""

# ─── Create database ────────────────────────────────────────
echo "Creating database '$DB_NAME'..."
doctl databases db create "$CLUSTER_ID" "$DB_NAME" 2>/dev/null || echo "  (database may already exist)"

# ─── Create user ────────────────────────────────────────────
echo "Creating database user '$DB_USER'..."
doctl databases user create "$CLUSTER_ID" "$DB_USER" 2>/dev/null || echo "  (user may already exist)"

# ─── Get connection details ─────────────────────────────────
echo ""
echo "Fetching connection details..."

CONNECTION_JSON=$(doctl databases connection "$CLUSTER_ID" --format Host,Port,User,Password,Database,SSL --output json)
DB_HOST=$(echo "$CONNECTION_JSON" | jq -r '.[0].host')
DB_PORT=$(echo "$CONNECTION_JSON" | jq -r '.[0].port')
DB_PASSWORD=$(doctl databases user get "$CLUSTER_ID" "$DB_USER" --format Password --no-header 2>/dev/null || echo "see-doctl-output")

# Build connection string
PG_URL="postgres://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:${DB_PORT}/${DB_NAME}?sslmode=require"

# Generate a shared encryption key
SHARED_KEY=$(openssl rand -hex 32)

# ─── Configure trusted sources (optional) ───────────────────
echo ""
echo "NOTE: For production, restrict DB access to your IP addresses."
echo "  doctl databases firewalls append $CLUSTER_ID --rule ip_addr:<YOUR_IP>"
echo ""

# ─── Output ─────────────────────────────────────────────────
echo "═══════════════════════════════════════════════════════"
echo ""
echo "✅ DigitalOcean Postgres is ready!"
echo ""
echo "Copy these to every node (Mac Minis + DO droplets):"
echo ""
echo "─── Add to .env or export in shell ───────────────────"
echo ""
echo "  export OPENSHART_PG_URL=\"${PG_URL}\""
echo "  export OPENSHART_SHARED_KEY=\"${SHARED_KEY}\""
echo ""
echo "─── Run integration test (single node) ───────────────"
echo ""
echo "  OPENSHART_PG_URL=\"${PG_URL}\" npx vitest run test/postgres.integration.test.ts"
echo ""
echo "─── Run distributed test (each node) ─────────────────"
echo ""
echo "  export OPENSHART_PG_URL=\"${PG_URL}\""
echo "  export OPENSHART_SHARED_KEY=\"${SHARED_KEY}\""
echo "  export AGENT_COUNT=3  # total number of nodes"
echo ""
echo "  # On Mac Mini 1:"
echo "  AGENT_ID=mac-mini-1 npx tsx scripts/distributed-test.ts"
echo ""
echo "  # On Mac Mini 2:"
echo "  AGENT_ID=mac-mini-2 npx tsx scripts/distributed-test.ts"
echo ""
echo "  # On DO droplet:"
echo "  AGENT_ID=do-droplet-1 npx tsx scripts/distributed-test.ts"
echo ""
echo "═══════════════════════════════════════════════════════"
echo ""
echo "Monthly cost: ~\$15 (managed Postgres, 1 vCPU, 1 GB RAM, 10 GB disk)"
echo "To tear down:  doctl databases delete $CLUSTER_ID"
echo ""

# ─── Save to .env.distributed (gitignored) ──────────────────
cat > .env.distributed <<ENVEOF
# OpenShart Distributed Test Configuration
# Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# Cluster: $CLUSTER_NAME ($CLUSTER_ID)
OPENSHART_PG_URL=${PG_URL}
OPENSHART_SHARED_KEY=${SHARED_KEY}
AGENT_COUNT=3
ENVEOF

echo "Saved to .env.distributed (add this to .gitignore)"
