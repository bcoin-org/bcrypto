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
  mkdir src/torsion/src
  mkdir src/torsion/include
fi

cp "$prefix/LICENSE" src/torsion/
rsync -av --exclude 'test*.c' "$prefix/src/" src/torsion/src/
rsync -av "$prefix/include/" src/torsion/include/
