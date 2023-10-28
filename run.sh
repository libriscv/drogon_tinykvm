#!/usr/bin/env bash
set -e
mkdir -p .build
pushd .build
cmake .. -G Ninja -DCMAKE_BUILD_TYPE=Release
ninja
popd

ulimit -n 4096
if [ -z "$DEBUG" ]; then
  ./.build/dvm
else
  gdb --args ./.build/dvm
fi
