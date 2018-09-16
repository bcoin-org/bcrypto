/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const crypto = require('crypto');
const bcrypto = require('../');
const {random} = bcrypto;

const algs = [
  'MD5',
  'RIPEMD160',
  'SHA1',
  'SHA224',
  'SHA256',
  'SHA384',
  'SHA512',
  // 'BLAKE2S256',
  'BLAKE2B512'
];

const hashes = {
  MD5: bcrypto.MD5,
  RIPEMD160: bcrypto.RIPEMD160,
  SHA1: bcrypto.SHA1,
  SHA224: bcrypto.SHA224,
  SHA256: bcrypto.SHA256,
  SHA384: bcrypto.SHA384,
  SHA512: bcrypto.SHA512,
  // BLAKE2S256: bcrypto.Blake2s256,
  BLAKE2B512: bcrypto.Blake2b512
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

  const nctx = crypto.createHash(alg.toLowerCase());
  nctx.update(msg);
  return nctx.digest();
}

function hmac(alg, msg, key) {
  if (typeof msg === 'string')
    msg = Buffer.from(msg, 'utf8');

  if (typeof key === 'string')
    key = Buffer.from(key, 'utf8');

  const nctx = crypto.createHmac(alg.toLowerCase(), key);
  nctx.update(msg);
  return nctx.digest();
}

function testHash(alg, msg) {
  if (typeof msg === 'string')
    msg = Buffer.from(msg, 'utf8');

  const nctx = crypto.createHash(alg.toLowerCase());
  nctx.update(msg);
  const expect = nctx.digest();

  const ctx = hashes[alg].hash();
  ctx.init();
  ctx.update(msg);
  const hash = ctx.final();

  assert.bufferEqual(hash, expect);

  const c = hashes[alg].hash();
  c.init();

  const ch = Buffer.allocUnsafe(1);

  for (let i = 0; i < msg.length; i++) {
    ch[0] = msg[i];
    c.update(ch);
  }

  assert.bufferEqual(c.final(), expect);
}

function testHmac(alg, msg, key) {
  if (typeof msg === 'string')
    msg = Buffer.from(msg, 'utf8');

  if (typeof key === 'string')
    key = Buffer.from(key, 'utf8');

  const nctx = crypto.createHmac(alg.toLowerCase(), key);
  nctx.update(msg);
  const expect = nctx.digest();

  const ctx = hashes[alg].hmac();
  ctx.init(key);
  ctx.update(msg);
  const hash = ctx.final();

  assert.bufferEqual(hash, expect);

  const c = hashes[alg].hmac();
  c.init(key);

  const ch = Buffer.allocUnsafe(1);

  for (let i = 0; i < msg.length; i++) {
    ch[0] = msg[i];
    c.update(ch);
  }

  assert.bufferEqual(c.final(), expect);
}

describe('Hash', function() {
  for (const alg of algs) {
    for (const [msg, key] of vectors) {
      const h = hash(alg, msg).toString('hex');

      it(`should test ${alg} hash of ${h}`, () => {
        testHash(alg, msg);
      });

      if (!alg.startsWith('BLAKE2')) {
        const m = hmac(alg, msg, key).toString('hex');

        it(`should test ${alg} hmac of ${m}`, () => {
          testHmac(alg, msg, key);
        });
      }
    }
  }

  for (const alg of algs) {
    for (let i = 0; i < 50; i++) {
      const msg = random.randomBytes(Math.random() * 500 | 0);
      const key = random.randomBytes(Math.random() * 500 | 0);
      const h = hash(alg, msg).toString('hex');

      it(`should test ${alg} hash of ${h}`, () => {
        testHash(alg, msg);
      });

      if (!alg.startsWith('BLAKE2')) {
        const m = hmac(alg, msg, key).toString('hex');

        it(`should test ${alg} hmac of ${m}`, () => {
          testHmac(alg, msg, key);
        });
      }
    }
  }
});
