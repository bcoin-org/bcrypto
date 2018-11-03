#!/usr/bin/env bash

# Taken from secp256k1-node
# Copyright (c) 2014-2016 secp256k1-node contributors (MIT License)

has_lib() {
  local regex="\<lib$1.\+\(so\|dylib\)\>"

  # Add /sbin to path as ldconfig is located there on some systems - e.g. Debian
  # (and it still can be used by unprivileged users):
  PATH="$PATH:/sbin"
  export PATH

  # Try just checking common library locations
  for dir in /lib \
             /usr/lib \
             /usr/local/lib \
             /opt/local/lib \
             /usr/lib/x86_64-linux-gnu \
             /usr/lib/i386-linux-gnu; do
    test -d $dir && echo "$(ls $dir)" | grep "$regex" && return 0
  done

  return 1
}

for name in "$@"; do
  if ! has_lib "$name" > /dev/null 2>& 1; then
    echo false
    exit 0
  fi
done

echo true
