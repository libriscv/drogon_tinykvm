#!/usr/bin/env bash
MAIN=hello_world
STORAGE=hello_world_storage
CXX=${CXX:-g++}

$CXX -static -O2 -std=c++20 -Wl,-Ttext-segment=0x40200000 $STORAGE.cpp -o $STORAGE

objcopy -w --extract-symbol --strip-symbol=!remote* --strip-symbol=!_Z*remote* --strip-symbol=* $STORAGE /tmp/storage.syms
$CXX -static -O2 -std=c++20 -Wl,--just-symbols=/tmp/storage.syms $MAIN.cpp -o $MAIN
