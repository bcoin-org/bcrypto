/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const dsa = require('../lib/internal/dsa');
const params = require('./data/dsa-params.json');

const {
  P1024_160,
  P2048_244,
  P2048_256,
  P3072_256
} = params;

function createParams(json) {
  const p = Buffer.from(json.p, 'hex');
  const q = Buffer.from(json.q, 'hex');
  const g = Buffer.from(json.g, 'hex');
  return new dsa.DSAParams(p, q, g);
}

describe('DSA', function() {
  it('should sign and verify', () => {
    // const key = dsa.generateKey(1024, 160);
    const params = createParams(P2048_256);
    const key = dsa.generateKeyFromParams(params);
    const pub = key.toPublic();

    assert(key.toJSON());
    assert(key.toPEM());
    assert(pub.toPEM());

    const msg = Buffer.alloc(key.q.length, 0x01);
    const sig = dsa.signKey(msg, key);
    assert(sig);

    const result = dsa.verifyKey(msg, sig, pub);
    assert(result);

    sig[(Math.random() * sig.length) | 0] ^= 1;

    const result2 = dsa.verifyKey(msg, sig, pub);
    assert(!result2);
  });
});
