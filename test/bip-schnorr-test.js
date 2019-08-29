'use strict';

const assert = require('bsert');
const secp256k1 = require('../lib/js/secp256k1');
const Schnorr = require('../lib/js/bip-schnorr');
const SHA256 = require('../lib/js/sha256');
const vectors = require('./data/schnorr-new.json');

describe('Secp256k1+Schnorr (new)', function() {
  const schnorr = new Schnorr(secp256k1.curve, SHA256);
  const valid = [];
  const invalid = [];

  for (const [key_, pub_, msg_, sig_, result, comment_] of vectors) {
    const key = Buffer.from(key_, 'hex');
    const pub = Buffer.from(pub_, 'hex');
    const msg = Buffer.from(msg_, 'hex');
    const sig = Buffer.from(sig_, 'hex');
    const text = sig_.slice(0, 32).toLowerCase() + '...';
    const comment = comment_ || `should verify ${text}`;
    const batch = result ? valid : invalid;

    batch.push([msg, sig, pub]);

    it(comment, () => {
      if (key.length > 0)
        assert.bufferEqual(schnorr.sign(msg, key), sig);

      assert.strictEqual(schnorr.verify(msg, sig, pub), result);
    });
  }

  it('should do batch verification', () => {
    assert.strictEqual(schnorr.verifyBatch([]), true);
    assert.strictEqual(schnorr.verifyBatch(valid), true);

    for (const item of valid)
      assert.strictEqual(schnorr.verifyBatch([item]), true);
  });

  it('should do fail batch verification', () => {
    for (const item of invalid) {
      assert.strictEqual(schnorr.verifyBatch([item, ...valid]), false);
      assert.strictEqual(schnorr.verifyBatch([...valid, item]), false);
      assert.strictEqual(schnorr.verifyBatch([item]), false);
    }
  });
});
