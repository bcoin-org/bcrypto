#!/bin/bash

set -ex

test -e package.json
test -e ../torsion
rm -rf src/torsion
mkdir src/torsion
cp -r ../torsion/src src/torsion/
cp -r ../torsion/include src/torsion/
cp -r ../torsion/LICENSE src/torsion/
rm src/torsion/src/test.c
rm src/torsion/src/test-internal.c
