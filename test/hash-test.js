/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const crypto = require('crypto');
const MD5 = require('../lib/md5');
const RIPEMD160 = require('../lib/ripemd160');
const SHA1 = require('../lib/sha1');
const SHA224 = require('../lib/sha224');
const SHA256 = require('../lib/sha256');
const SHA384 = require('../lib/sha384');
const SHA512 = require('../lib/sha512');
const Blake2s256 = require('../lib/blake2s256');
const Blake2b512 = require('../lib/blake2b512');
const random = require('../lib/random');

const algs = [
  ['MD5', true],
  ['RIPEMD160', true],
  ['SHA1', true],
  ['SHA224', true],
  ['SHA256', true],
  ['SHA384', true],
  ['SHA512', true],
  ['BLAKE2S256', false],
  ['BLAKE2B512', false]
];

const hashes = {
  MD5: MD5,
  RIPEMD160: RIPEMD160,
  SHA1: SHA1,
  SHA224: SHA224,
  SHA256: SHA256,
  SHA384: SHA384,
  SHA512: SHA512,
  BLAKE2S256: Blake2s256,
  BLAKE2B512: Blake2b512
};

const vectors = [
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

  const id = alg.toLowerCase();
  const ctx = crypto.createHash(id);
  ctx.update(msg);
  return ctx.digest();
}

function hmac(alg, msg, key) {
  if (typeof msg === 'string')
    msg = Buffer.from(msg, 'utf8');

  if (typeof key === 'string')
    key = Buffer.from(key, 'utf8');

  const id = alg.toLowerCase();
  const ctx = crypto.createHmac(id, key);
  ctx.update(msg);
  return ctx.digest();
}

function testHash(alg, msg) {
  if (typeof msg === 'string')
    msg = Buffer.from(msg, 'utf8');

  const id = alg.toLowerCase();
  const ctx1 = crypto.createHash(id);
  ctx1.update(msg);

  const expect = ctx1.digest();

  const ctx2 = hashes[alg].hash();
  ctx2.init();
  ctx2.update(msg);

  const hash = ctx2.final();

  assert.bufferEqual(hash, expect);

  const ctx3 = hashes[alg].hash();
  ctx3.init();

  const ch = Buffer.allocUnsafe(1);

  for (let i = 0; i < msg.length; i++) {
    ch[0] = msg[i];
    ctx3.update(ch);
  }

  assert.bufferEqual(ctx3.final(), expect);
}

function testHmac(alg, msg, key) {
  if (typeof msg === 'string')
    msg = Buffer.from(msg, 'utf8');

  if (typeof key === 'string')
    key = Buffer.from(key, 'utf8');

  const id = alg.toLowerCase();
  const ctx1 = crypto.createHmac(id, key);
  ctx1.update(msg);

  const expect = ctx1.digest();

  const ctx2 = hashes[alg].hmac();
  ctx2.init(key);
  ctx2.update(msg);

  const hash = ctx2.final();

  assert.bufferEqual(hash, expect);

  const ctx3 = hashes[alg].hmac();
  ctx3.init(key);

  const ch = Buffer.allocUnsafe(1);

  for (let i = 0; i < msg.length; i++) {
    ch[0] = msg[i];
    ctx3.update(ch);
  }

  assert.bufferEqual(ctx3.final(), expect);
}

describe('Hash', function() {
  for (const [alg, hasMAC] of algs) {
    for (const [msg, key] of vectors) {
      const digest = hash(alg, msg).toString('hex');

      it(`should test ${alg} hash of ${digest}`, () => {
        testHash(alg, msg);
      });

      if (hasMAC) {
        const mac = hmac(alg, msg, key).toString('hex');

        it(`should test ${alg} hmac of ${mac}`, () => {
          testHmac(alg, msg, key);
        });
      }
    }
  }

  for (const [alg, hasMAC] of algs) {
    for (let i = 0; i < 50; i++) {
      const msg = random.randomBytes(Math.random() * 500 | 0);
      const key = random.randomBytes(Math.random() * 500 | 0);
      const digest = hash(alg, msg).toString('hex');

      it(`should test ${alg} hash of ${digest}`, () => {
        testHash(alg, msg);
      });

      if (hasMAC) {
        const mac = hmac(alg, msg, key).toString('hex');

        it(`should test ${alg} hmac of ${mac}`, () => {
          testHmac(alg, msg, key);
        });
      }
    }
  }
});
