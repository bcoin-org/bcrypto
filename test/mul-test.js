'use strict';

const assert = require('bsert');
const random = require('../lib/random');
const p192 = require('../lib/p192');
const p224 = require('../lib/p224');
const p256 = require('../lib/p256');
const p384 = require('../lib/p384');
const p521 = require('../lib/p521');
const secp256k1 = require('../lib/secp256k1');
const ed25519 = require('../lib/ed25519');

describe('Mul', function() {
  for (const curve of [p192, p224, p256, p384, p521, secp256k1]) {
    it(`should do multiplicative HD derivation for ${curve.id}`, () => {
      const key = curve.privateKeyGenerate();
      const pub = curve.publicKeyCreate(key);
      const tweak = random.randomBytes(curve.size);

      tweak[0] = 0;

      const key2 = curve.privateKeyTweakMul(key, tweak);
      const pub2 = curve.publicKeyTweakMul(pub, tweak);
      const pub3 = curve.publicKeyCreate(key2);

      assert.bufferEqual(pub2, pub3);
    });
  }

  it('should generate keypair and sign with tweak', () => {
    const key = ed25519.privateKeyGenerate();
    const pub = ed25519.publicKeyCreate(key);
    const tweak = random.randomBytes(32);
    const msg = random.randomBytes(32);
    const child = ed25519.publicKeyTweakMul(pub, tweak);

    assert.notBufferEqual(child, pub);

    const sig = ed25519.signTweakMul(msg, key, tweak);

    assert(ed25519.verify(msg, sig, child));
  });
});
