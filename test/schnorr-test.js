'use strict';

const assert = require('bsert');
const secp256k1 = require('../lib/secp256k1');
const vectors = require('./data/schnorr.json');

describe('Secp256k1+Schnorr', function() {
  const parsed = [];
  const valid = [];
  const invalid = [];

  // Parse test vectors.
  for (const [key_, pub_, msg_, sig_, result, comment_] of vectors) {
    const key = Buffer.from(key_, 'hex');
    const pub = Buffer.from(pub_, 'hex');
    const msg = Buffer.from(msg_, 'hex');
    const sig = Buffer.from(sig_, 'hex');
    const comment = comment_ || `should verify ${sig_.toLowerCase()}`;
    const batch = result ? valid : invalid;

    parsed.push([key, pub, msg, sig, result, comment]);
    batch.push([msg, sig, pub]);
  }

  for (const [key, pub, msg, sig, result, comment] of parsed) {
    it(comment, () => {
      if (key.length > 0) {
        assert(secp256k1.privateKeyVerify(key));
        assert.bufferEqual(secp256k1.publicKeyCreate(key), pub);
        assert.bufferEqual(secp256k1.schnorrSign(msg, key), sig);
      }

      assert.strictEqual(secp256k1.schnorrVerify(msg, sig, pub), result);
    });
  }

  it('should do batch verification', () => {
    assert.strictEqual(secp256k1.schnorrBatchVerify(valid), true);
  });

  it('should do fail batch verification', () => {
    for (const item of invalid) {
      assert.strictEqual(secp256k1.schnorrBatchVerify([item, ...valid]), false);
      assert.strictEqual(secp256k1.schnorrBatchVerify([...valid, item]), false);
    }
  });
});
