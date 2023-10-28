#!/usr/bin/env bash
export CXX="ccache clang++-19"
set -e
mkdir -p .build
pushd .build
ln -fs ../program/zpizza .
ln -fs ../tenants.json .
cmake .. -G Ninja -DCMAKE_BUILD_TYPE=Release
ninja
ulimit -n 4096
if [ -z "$DEBUG" ]; then
  ./dvm
else
  gdb --args ./dvm
fi
popd
