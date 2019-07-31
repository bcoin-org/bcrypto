'use strict';

const bench = require('./bench');
const sha1 = require('../lib/sha1');
const sha256 = require('../lib/sha256');
const sha512 = require('../lib/sha512');
const ripemd160 = require('../lib/ripemd160');
const blake2b = require('../lib/blake2b');
const blake2s = require('../lib/blake2s');
const sha3 = require('../lib/sha3');
const random = require('../lib/random');

for (const size of [32, 64, 65, 128, 512]) {
  const rounds = 200000;
  const msg = random.randomBytes(size);

  bench(`sha1 (${size})`, rounds, () => {
    sha1.digest(msg);
  });

  bench(`sha256 (${size})`, rounds, () => {
    sha256.digest(msg);
  });

  bench(`sha512 (${size})`, rounds, () => {
    sha512.digest(msg);
  });

  bench(`ripemd160 (${size})`, rounds, () => {
    ripemd160.digest(msg);
  });

  bench(`blake2b (${size})`, rounds, () => {
    blake2b.digest(msg);
  });

  bench(`blake2s (${size})`, rounds, () => {
    blake2s.digest(msg);
  });

  bench(`sha3 (${size})`, rounds, () => {
    sha3.digest(msg);
  });

  if (size !== 512)
    console.log('---');
}
