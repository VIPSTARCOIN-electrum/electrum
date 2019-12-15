#!/usr/bin/env bash
export HOME=~
set -eux pipefail
mkdir -p ~/.vipstarcoin
cat > ~/.vipstarcoin/VIPSTARCOIN.conf <<EOF
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
rm -rf ~/.vipstarcoin/regtest
screen -S vipstarcoind -X quit || true
screen -S vipstarcoind -m -d vipstarcoind -regtest
sleep 6
addr=$(vipstarcoin-cli getnewaddress)
vipstarcoin-cli generatetoaddress 150 $addr > /dev/null
