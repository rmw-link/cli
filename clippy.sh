#!/usr/bin/env bash

set -e

_DIR=$(dirname $(realpath "$0"))

cd $_DIR


if ! hash cargo-clippy 2>/dev/null; then
  rustup component add clippy
fi

gsync

cargo +nightly clippy --fix -Z unstable-options

