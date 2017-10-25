/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const crypto = require('crypto');
const bcrypto = require('../');

const algs = [
  'ripemd160',
  'sha1',
  'sha256',
  'sha512'
];

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

  const nctx = crypto.createHash(alg);
  nctx.update(msg);
  return nctx.digest();
}

function hmac(alg, msg, key) {
  if (typeof msg === 'string')
    msg = Buffer.from(msg, 'utf8');

  if (typeof key === 'string')
    key = Buffer.from(key, 'utf8');

  const nctx = crypto.createHmac(alg, key);
  nctx.update(msg);
  return nctx.digest();
}

function testHash(alg, msg) {
  if (typeof msg === 'string')
    msg = Buffer.from(msg, 'utf8');

  const nctx = crypto.createHash(alg);
  nctx.update(msg);
  const expect = nctx.digest();

  const ctx = bcrypto.get(alg).hash();
  ctx.init();
  ctx.update(msg);
  const hash = ctx.final();

  assert.bufferEqual(hash, expect);

  const c = bcrypto.get(alg).hash();
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

  const nctx = crypto.createHmac(alg, key);
  nctx.update(msg);
  const expect = nctx.digest();

  const ctx = bcrypto.get(alg).hmac();
  ctx.init(key);
  ctx.update(msg);
  const hash = ctx.final();

  assert.bufferEqual(hash, expect);

  const c = bcrypto.get(alg).hmac();
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
      const m = hmac(alg, msg, key).toString('hex');

      it(`should test ${alg} hash of ${h}`, () => {
        testHash(alg, msg);
      });

      it(`should test ${alg} hmac of ${m}`, () => {
        testHmac(alg, msg, key);
      });
    }
  }
});
