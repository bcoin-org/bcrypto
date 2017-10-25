/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const crypto = require('crypto');

const bhash = {
  ripemd160: require('../lib/js/ripemd160'),
  sha1: require('../lib/js/sha1'),
  sha256: require('../lib/js/sha256'),
  sha512: require('../lib/js/sha512')
};

const algs = [
  'ripemd160',
  'sha1',
  'sha256'
  // 'sha512'
];

function nhash(alg, msg) {
  const nctx = crypto.createHash(alg);
  nctx.update(msg);
  return nctx.digest();
}

function nhmac(alg, msg, key) {
  const nctx = crypto.createHmac(alg, key);
  nctx.update(msg);
  return nctx.digest();
}

for (const alg of algs) {
  console.log(alg);
  for (let i = 0; i < 100000; i++) {
    const data = crypto.randomBytes((Math.random() * 1000) | 0);
    const key = crypto.randomBytes((Math.random() * 1000) | 0);

    const h1 = bhash[alg].digest(data);
    const h2 = nhash(alg, data);
    assert.bufferEqual(h1, h2);

    const m1 = bhash[alg].mac(data, key);
    const m2 = nhmac(alg, data, key);
    assert.bufferEqual(m1, m2);
  }
}

const native = {
  keccak: require('../lib/native/keccak'),
  sha3: require('../lib/native/sha3'),
  blake2b: require('../lib/native/blake2b')
};

const js = {
  keccak: require('../lib/js/keccak'),
  sha3: require('../lib/js/sha3'),
  blake2b: require('../lib/js/blake2b')
};

for (const alg of Object.keys(native)) {
  console.log(alg);
  for (let i = 0; i < 100000; i++) {
    const data = crypto.randomBytes((Math.random() * 1000) | 0);

    const h1 = js[alg].digest(data);
    const h2 = native[alg].digest(data);
    assert.bufferEqual(h1, h2);

    if (0 && alg === 'blake2b') {
      const key = crypto.randomBytes((Math.random() * 65) | 0);
      const m1 = js[alg].mac(data, key);
      const m2 = native[alg].mac(data, key);
      assert.bufferEqual(m1, m2);
    }
  }
}
