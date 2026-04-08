#!/usr/bin/env bash
set -euo pipefail

TARGET_CONTRACT="${TARGET_CONTRACT:?TARGET_CONTRACT env var must be set}"

echo "=== Starting Sui devnet ==="
sui start --with-faucet --force-regenesis &
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

# Generate keypairs
echo "=== Generating accounts ==="
ADMIN_OUTPUT=$(sui client new-address ed25519 admin 2>&1)
ADMIN_ADDRESS=$(echo "$ADMIN_OUTPUT" | grep -oP '0x[a-f0-9]{64}' | head -1)

ATTACKER_OUTPUT=$(sui client new-address ed25519 attacker 2>&1)
ATTACKER_ADDRESS=$(echo "$ATTACKER_OUTPUT" | grep -oP '0x[a-f0-9]{64}' | head -1)

USER_OUTPUT=$(sui client new-address ed25519 user 2>&1)
USER_ADDRESS=$(echo "$USER_OUTPUT" | grep -oP '0x[a-f0-9]{64}' | head -1)

echo "Admin:    $ADMIN_ADDRESS"
echo "Attacker: $ATTACKER_ADDRESS"
echo "User:     $USER_ADDRESS"

# Fund accounts
echo "=== Funding accounts ==="
for ADDR in "$ADMIN_ADDRESS" "$ATTACKER_ADDRESS" "$USER_ADDRESS"; do
  curl -s -X POST http://127.0.0.1:9123/v2/gas \
    -H 'Content-Type: application/json' \
    -d "{\"FixedAmountRequest\":{\"recipient\":\"${ADDR}\"}}" \
    > /dev/null
  echo "Funded $ADDR"
done

# Publish contract
echo "=== Publishing contract: $TARGET_CONTRACT ==="
sui client switch --address "$ADMIN_ADDRESS" 2>/dev/null

PUBLISH_OUTPUT=$(sui client publish "/workspace/${TARGET_CONTRACT}" \
  --skip-dependency-verification \
  --gas-budget 500000000 \
  --json 2>&1)

PACKAGE_ID=$(echo "$PUBLISH_OUTPUT" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for change in data.get('objectChanges', []):
    if change.get('type') == 'published':
        print(change['packageId'])
        break
" 2>/dev/null || echo "")

if [ -z "$PACKAGE_ID" ]; then
  echo "ERROR: Failed to extract package ID from publish output" >&2
  echo "$PUBLISH_OUTPUT" >&2
  exit 1
fi

echo "Package ID: $PACKAGE_ID"

# Export private keys
ADMIN_KEY=$(sui keytool export "$ADMIN_ADDRESS" --json 2>&1 | python3 -c "import sys,json; print(json.load(sys.stdin)['key']['suiPrivateKey'])" 2>/dev/null || echo "")
ATTACKER_KEY=$(sui keytool export "$ATTACKER_ADDRESS" --json 2>&1 | python3 -c "import sys,json; print(json.load(sys.stdin)['key']['suiPrivateKey'])" 2>/dev/null || echo "")
USER_KEY=$(sui keytool export "$USER_ADDRESS" --json 2>&1 | python3 -c "import sys,json; print(json.load(sys.stdin)['key']['suiPrivateKey'])" 2>/dev/null || echo "")

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
