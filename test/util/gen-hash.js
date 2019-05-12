'use strict';

const fs = require('fs');
const crypto = require('crypto');
const createHash = require('./create-hash');

const algs = [
  ['md4', true],
  ['md5', true],
  ['ripemd160', true],
  ['sha1', true],
  ['sha224', true],
  ['sha256', true],
  ['sha384', true],
  ['sha512', true],
  ['hash160', false],
  ['hash256', false],
  ['whirlpool', true],
  ['md5-sha1', true],
  ['blake2s256', true],
  ['blake2b512', true],
  ['sha3-224', true],
  ['sha3-256', true],
  ['sha3-384', true],
  ['sha3-512', true],
  ['shake128', false],
  ['shake256', false]
];

const defaults = [
  ['', ''],
  ['Foobar', 'Baz'],
  ['The quick brown fox jumps over the lazy dog', 'Secret key goes here!'],
  ['The quick brown fox jumps over the lazy dog.', 'Secret key goes here.'],
  ['Message goes here!', 'The quick brown fox jumps over the lazy dog'],
  ['Message goes here.', 'The quick brown fox jumps over the lazy dog.'],
  [Buffer.alloc(777, 0), Buffer.alloc(777, 0)],
  [Buffer.alloc(777, 0xaa), Buffer.alloc(777, 0xff)]
];

function hash(alg, msg) {
  if (typeof msg === 'string')
    msg = Buffer.from(msg, 'utf8');

  const ctx = createHash(alg);
  ctx.update(msg);
  return ctx.digest();
}

function hmac(alg, msg, key) {
  if (typeof msg === 'string')
    msg = Buffer.from(msg, 'utf8');

  if (typeof key === 'string')
    key = Buffer.from(key, 'utf8');

  const ctx = crypto.createHmac(alg, key);
  ctx.update(msg);
  return ctx.digest();
}

for (const [alg, hasMAC] of algs) {
  const vectors = [];

  for (const [msg] of defaults) {
    const digest = hash(alg, msg).toString('hex');

    vectors.push([msg.toString('hex'), null, digest]);
  }

  for (let i = 0; i < 100; i++) {
    const msg = crypto.randomBytes(Math.random() * 300 | 0);
    const digest = hash(alg, msg).toString('hex');

    vectors.push([msg.toString('hex'), null, digest]);
  }

  if (hasMAC) {
    for (const [msg, key] of defaults) {
      const digest = hmac(alg, msg, key).toString('hex');

      vectors.push([msg.toString('hex'), key.toString('hex'), digest]);
    }

    for (let i = 0; i < 100; i++) {
      const msg = crypto.randomBytes(Math.random() * 300 | 0);
      const key = crypto.randomBytes(Math.random() * 300 | 0);
      const mac = hmac(alg, msg, key).toString('hex');

      vectors.push([msg.toString('hex'), key.toString('hex'), mac]);
    }
  }

  fs.writeFileSync(`${__dirname}/../data/hashes/${alg}.json`,
    JSON.stringify(vectors, null, 2) + '\n');
}
