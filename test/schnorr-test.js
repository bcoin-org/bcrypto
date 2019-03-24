'use strict';

const assert = require('bsert');
const secp256k1 = require('../lib/secp256k1');
const csv = require('./util/csv');

describe('Secp256k1+Schnorr', function() {
  const iter = csv.asArray(`${__dirname}/data/schnorr-vectors.csv`);
  const valid = [];
  const invalid = [];

  for (const [key_, pub_, msg_, sig_, result_, comment_] of iter) {
    const key = Buffer.from(key_, 'hex');
    const pub = Buffer.from(pub_, 'hex');
    const msg = Buffer.from(msg_, 'hex');
    const sig = Buffer.from(sig_, 'hex');
    const result = result_ === 'TRUE';
    const comment = comment_ || `should verify ${sig_}`;

    (result ? valid : invalid).push({
      message: msg,
      signature: sig,
      key: pub
    });

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

    for (const item of invalid) {
      assert.strictEqual(secp256k1.schnorrBatchVerify([item, ...valid]), false);
      assert.strictEqual(secp256k1.schnorrBatchVerify([...valid, item]), false);
    }
  });
});
