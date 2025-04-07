#!/bin/bash

set -e

echo "📦 Setting up ZoKrates circuit..."

# Create zk folder if not exists
mkdir -p zk

# Run inside ZoKrates Docker
docker run --rm -v $(pwd):/home/zokrates/code -w /home/zokrates/code -ti zokrates/zokrates bash -c "
  echo '🛠 Compiling circuit...'
  zokrates compile -i zk/circuit.zok -o zk/out
  echo '📄 Moving abi.json...'
  mv abi.json zk/abi.json
  echo '🔐 Performing trusted setup...'
  zokrates setup -i zk/out -v zk/verification.key -p zk/proving.key
  echo '✅ All done! Files written to zk/: out, abi.json, proving.key, verification.key'
"
