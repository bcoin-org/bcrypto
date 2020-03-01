#!/bin/bash

set -ex

type rsync > /dev/null 2>& 1
test $# -eq 1
test ! -z "$1"

prefix="$1"

test -f package.json
test -d "$prefix"
test -d "$prefix/src"
test -d "$prefix/include"

if test ! -d src/torsion; then
  mkdir src/torsion
fi

if test ! -d src/torsion/src; then
  mkdir src/torsion/src
fi

if test ! -d src/torsion/include; then
  mkdir src/torsion/include
fi

cp -f "$prefix/LICENSE" src/torsion/
rsync -av --exclude 'test*.c' --exclude '*.o' "$prefix/src/" src/torsion/src/
rsync -av "$prefix/include/" src/torsion/include/
