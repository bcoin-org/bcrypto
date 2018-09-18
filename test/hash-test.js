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
const MD5SHA1 = require('../lib/md5sha1');
const BLAKE2s256 = require('../lib/blake2s256');
const BLAKE2b512 = require('../lib/blake2b512');
const random = require('../lib/random');
const NODE_MAJOR = parseInt(process.version.substring(1).split('.')[0], 10);

const algs = [
  ['md5', true],
  ['ripemd160', true],
  ['sha1', true],
  ['sha224', true],
  ['sha256', true],
  ['sha384', true],
  ['sha512', true],
  ['md5-sha1', true],
  ['blake2s256', true],
  ['blake2b512', true]
];

if (NODE_MAJOR < 10) {
  algs.pop();
  algs.pop();
}

const hashes = {
  md5: MD5,
  ripemd160: RIPEMD160,
  sha1: SHA1,
  sha224: SHA224,
  sha256: SHA256,
  sha384: SHA384,
  sha512: SHA512,
  'md5-sha1': MD5SHA1,
  blake2s256: BLAKE2s256,
  blake2b512: BLAKE2b512
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

  const ctx = crypto.createHash(alg);
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

function testHash(alg, msg) {
  if (typeof msg === 'string')
    msg = Buffer.from(msg, 'utf8');

  const ctx1 = crypto.createHash(alg);
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

  const ctx1 = crypto.createHmac(alg, key);
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
