'use strict';

const assert = require('bsert');
const schnorr = require('../lib/js/schnorr');
const rng = require('../lib/random');
const vectors = require('./data/schnorr.json');

describe('Secp256k1+Schnorr', function() {
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
      if (key.length > 0) {
        assert(schnorr.privateKeyVerify(key));
        assert.bufferEqual(schnorr.publicKeyCreate(key), pub);
        assert.bufferEqual(schnorr.sign(msg, key), sig);
      }

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

  it('should do HD derivation (additive)', () => {
    const priv = schnorr.privateKeyGenerate();
    const pub = schnorr.publicKeyCreate(priv);
    const tweak = rng.randomBytes(32);
    const cpriv = schnorr.privateKeyTweakAdd(priv, tweak);
    const cpub = schnorr.publicKeyTweakAdd(pub, tweak);

    assert.bufferEqual(schnorr.publicKeyCreate(cpriv), cpub);
  });

  it('should do HD derivation (multiplicative)', () => {
    const priv = schnorr.privateKeyGenerate();
    const pub = schnorr.publicKeyCreate(priv);
    const tweak = rng.randomBytes(32);
    const cpriv = schnorr.privateKeyTweakMul(priv, tweak);
    const cpub = schnorr.publicKeyTweakMul(pub, tweak);

    assert.bufferEqual(schnorr.publicKeyCreate(cpriv), cpub);
  });
});
