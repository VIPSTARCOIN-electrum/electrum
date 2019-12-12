#!/usr/bin/env bash
export HOME=~
set -eux pipefail
mkdir -p ~/.VIPSTARCOIN
cat > ~/.VIPSTARCOIN/VIPSTARCOIN.conf <<EOF
regtest=1
txindex=1
printtoconsole=1
rpcuser=doggman
rpcpassword=donkey
rpcallowip=127.0.0.1
zmqpubrawblock=tcp://127.0.0.1:28332
zmqpubrawtx=tcp://127.0.0.1:28333
[regtest]
rpcbind=0.0.0.0
rpcport=33916
EOF
rm -rf ~/.VIPSTARCOIN/regtest
screen -S VIPSTARCOINd -X quit || true
screen -S VIPSTARCOINd -m -d VIPSTARCOINd -regtest
sleep 6
addr=$(VIPSTARCOIN-cli getnewaddress)
VIPSTARCOIN-cli generatetoaddress 150 $addr > /dev/null
