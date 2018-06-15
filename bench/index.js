'use strict';

const assert = require('assert');
const bench = require('./bench');
const sha256 = require('../lib/sha256');
const blake2b = require('../lib/blake2b');
const sha3 = require('../lib/sha3');
const random = require('../lib/random');
const ChaCha20 = require('../lib/chacha20');

assert.strictEqual(sha256.native, 2);
assert.strictEqual(blake2b.native, 2);
assert.strictEqual(sha3.native, 2);
assert.strictEqual(ChaCha20.native, 2);

const rounds = 1000000;
const msg = random.randomBytes(1024);

bench('sha256', rounds, () => {
  sha256.digest(msg);
});

bench('blake2b', rounds, () => {
  blake2b.digest(msg);
});

bench('sha3', rounds, () => {
  sha3.digest(msg);
});

const chacha = new ChaCha20();
const key = random.randomBytes(32);
const iv = random.randomBytes(12);

bench('chacha20', rounds, () => {
  chacha.init(key, iv, 0);
  chacha.encrypt(msg);
});
