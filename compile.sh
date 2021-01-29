#!/usr/bin/env sh

cmake --build build/

build/zrin < input.json #| llc --relocation-model=pic | clang -xassembler -O3 -o main -
