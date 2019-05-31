'use strict';

const bench = require('./bench');
const sha256 = require('../lib/sha256');
const blake2b = require('../lib/blake2b');
const sha3 = require('../lib/sha3');
const random = require('../lib/random');

for (const size of [32, 64, 65, 512]) {
  const rounds = 200000;
  const msg = random.randomBytes(size);

  bench(`sha256 (${size})`, rounds, () => {
    sha256.digest(msg);
  });

  bench(`blake2b (${size})`, rounds, () => {
    blake2b.digest(msg);
  });

  bench(`sha3 (${size})`, rounds, () => {
    sha3.digest(msg);
  });

  if (size !== 512)
    console.log('---');
}
