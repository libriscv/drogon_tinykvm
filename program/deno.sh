#!/usr/bin/env bash
#APISO=libdrogon.so
#pushd storage_program
#./build.sh
#popd
#STORAGE=storage_program/target/release/demo

#$CXX -shared -fPIC -O2 libdrogon.cpp -o $APISO
#objcopy -w --extract-symbol --strip-symbol=!remote* --strip-symbol=!_Z*remote* --strip-symbol=* $STORAGE libdrogon.so /tmp/storage.syms
#./symbol_offset /tmp/storage.syms 0x2000200000 +exec
#$CXX -shared -fPIC -O2 -Wl,--just-symbols=/tmp/storage.syms libdrogon.cpp -o $APISO

# WARNING: The pre-linked address *must* be **inside the executable** area of guest vmem!
#gcc -shared -fPIC -O2 -Wl,-Ttext-segment=0x4000000000 libdrogon_storage.c -o libdrogon_storage.so
#objcopy -w --extract-symbol --strip-symbol=!remote* --strip-symbol=!_Z*remote* --strip-symbol=* libdrogon_storage.so /tmp/storage.syms
#./symbol_offset /tmp/storage.syms 0x0 remote_ +exec
#
#gcc -shared -fPIC -O2 libdrogon.c -Wl,--just-symbols=/tmp/storage.syms -o libdrogon.so

gcc -shared -fPIC -O2 libdrogon.c -o libdrogon.so
