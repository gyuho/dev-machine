#!/usr/bin/env bash
set -xue

if ! [[ "$0" =~ scripts/build.release.sh ]]; then
  echo "must be run from repository root"
  exit 255
fi

# "--bin" can be specified multiple times for each directory in "bin/*" or workspaces
cargo build \
--release \
--bin aws-dev-machine

./target/release/aws-dev-machine --help
./target/release/aws-dev-machine default-spec --help
./target/release/aws-dev-machine apply --help
./target/release/aws-dev-machine delete --help
