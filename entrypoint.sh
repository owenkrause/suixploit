#!/usr/bin/env bash
set -euo pipefail

TARGET_CONTRACT="${TARGET_CONTRACT:?TARGET_CONTRACT env var must be set}"
NETWORK="${NETWORK:-devnet}"

# ── Mainnet mode: no devnet, no deploy, just write context and go ──
if [ "$NETWORK" = "mainnet" ]; then
  PACKAGE_ID="${PACKAGE_ID:?PACKAGE_ID env var must be set for mainnet}"
  RPC_URL="https://fullnode.mainnet.sui.io:443"

  cat > /workspace/context.json <<CONTEXT
{
  "rpcUrl": "$RPC_URL",
  "packageId": "$PACKAGE_ID",
  "network": "mainnet"
}
CONTEXT

  echo "=== Container ready (mainnet dry-run) ==="
  touch /workspace/.ready
  exec tail -f /dev/null
fi

# ── Devnet mode: boot local network, deploy contract ──
echo "=== Starting Sui devnet ==="
RUST_LOG="off,sui_node=info" sui start --with-faucet --force-regenesis &
SUI_PID=$!

# Wait for RPC to be ready
echo "Waiting for RPC..."
for i in $(seq 1 60); do
  if curl -s -X POST http://127.0.0.1:9000 \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","method":"sui_getLatestCheckpointSequenceNumber","id":1}' \
    2>/dev/null | grep -q '"result"'; then
    echo "RPC ready after ${i}s"
    break
  fi
  if [ "$i" -eq 60 ]; then
    echo "ERROR: RPC not ready after 60s" >&2
    exit 1
  fi
  sleep 1
done

# Wait for faucet to be ready
echo "Waiting for faucet..."
for i in $(seq 1 60); do
  if curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:9123 2>/dev/null | grep -q '404\|200\|405'; then
    echo "Faucet ready after ${i}s"
    break
  fi
  if [ "$i" -eq 60 ]; then
    echo "ERROR: Faucet not ready after 60s" >&2
    exit 1
  fi
  sleep 1
done

# Configure client: create local env and switch to it
echo "Configuring Sui client..."
sui client new-env --alias local --rpc http://127.0.0.1:9000 -y 2>/dev/null || true
sui client switch --env local

# Generate keypairs using --json for reliable parsing
echo "=== Generating accounts ==="
ADMIN_ADDRESS=$(sui client new-address ed25519 admin --json | jq -r '.address')
ATTACKER_ADDRESS=$(sui client new-address ed25519 attacker --json | jq -r '.address')
USER_ADDRESS=$(sui client new-address ed25519 user --json | jq -r '.address')

echo "Admin:    $ADMIN_ADDRESS"
echo "Attacker: $ATTACKER_ADDRESS"
echo "User:     $USER_ADDRESS"

# Fund accounts via CLI faucet command
echo "=== Funding accounts ==="
for ADDR in "$ADMIN_ADDRESS" "$ATTACKER_ADDRESS" "$USER_ADDRESS"; do
  sui client faucet --address "$ADDR" --url http://127.0.0.1:9123/v2/gas 2>/dev/null || true
  echo "Funded $ADDR"
done

# Wait for faucet transactions to finalize
sleep 3

# Publish contract using test-publish for local/ephemeral environments
echo "=== Publishing contract: $TARGET_CONTRACT ==="
sui client switch --address "$ADMIN_ADDRESS" 2>/dev/null

PUBLISH_OUTPUT=$(sui client test-publish "/workspace/${TARGET_CONTRACT}" \
  --skip-dependency-verification \
  --publish-unpublished-deps \
  --gas-budget 500000000 \
  --build-env testnet \
  --json 2>&1) || true

# test-publish --json prefixes build progress lines before the JSON object;
# strip everything before the first '{' then extract packageId with jq
PACKAGE_ID=$(echo "$PUBLISH_OUTPUT" | sed -n '/^{/,$p' | jq -r '.objectChanges[] | select(.type == "published") | .packageId')

if [ -z "$PACKAGE_ID" ]; then
  echo "ERROR: Failed to extract package ID from publish output" >&2
  echo "$PUBLISH_OUTPUT" >&2
  exit 1
fi

echo "Package ID: $PACKAGE_ID"

# Export private keys using --json for reliable parsing
ADMIN_KEY=$(sui keytool export --key-identity admin --json | jq -r '.exportedPrivateKey')
ATTACKER_KEY=$(sui keytool export --key-identity attacker --json | jq -r '.exportedPrivateKey')
USER_KEY=$(sui keytool export --key-identity user --json | jq -r '.exportedPrivateKey')

# Write context
cat > /workspace/context.json <<CONTEXT
{
  "rpcUrl": "http://127.0.0.1:9000",
  "faucetUrl": "http://127.0.0.1:9123",
  "packageId": "$PACKAGE_ID",
  "adminAddress": "$ADMIN_ADDRESS",
  "attackerAddress": "$ATTACKER_ADDRESS",
  "userAddress": "$USER_ADDRESS",
  "adminKeyPair": "$ADMIN_KEY",
  "attackerKeyPair": "$ATTACKER_KEY",
  "userKeyPair": "$USER_KEY"
}
CONTEXT

echo "=== Container ready ==="
touch /workspace/.ready

# Keep container alive
exec tail -f /dev/null
