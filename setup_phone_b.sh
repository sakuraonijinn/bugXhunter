#!/bin/bash
# Phone B (Dropper, Termux) setup
set -e
# Requires Termux + python
pip install -e . 2>/dev/null || true
# Cross-compile bootstrapper for Phone C arch (arm64)
# NDK path must be set
: "${NDK:?set NDK to your Android NDK root}"
$NDK/toolchains/llvm/prebuilt/*/bin/aarch64-linux-android21-clang \
  -o /tmp/xbug-boot c/bootstrapper/bootstrapper.c
echo "Bootstrapper built at /tmp/xbug-boot"
echo "Transmit with:"
echo "  python3 -m bugxhunter.client.drop_audio --elf /tmp/xbug-boot --psk <hex>"
