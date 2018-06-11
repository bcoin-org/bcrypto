/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const ECDSA = require('../lib/ecdsa');
const random = require('../lib/random');

const curves = [
  require('../lib/p192'),
  require('../lib/p224'),
  require('../lib/p256'),
  require('../lib/p384'),
  require('../lib/p521'),
  new ECDSA('secp256k1'),
  require('../lib/secp256k1')
];

describe('ECDSA', function() {
  this.timeout(15000);

  for (const ec of curves) {
    it(`should generate keypair and sign DER (${ec.id})`, () => {
      const msg = random.randomBytes(ec.size);
      const priv = ec.privateKeyGenerate();
      const pub = ec.publicKeyCreate(priv);
      const pubu = ec.publicKeyConvert(pub, false);

      const sig = ec.signDER(msg, priv);
      assert(ec.verifyDER(msg, sig, pub));
      assert(ec.verifyDER(msg, sig, pubu));
    });

    it(`should generate keypair and sign RS (${ec.id})`, () => {
      const msg = random.randomBytes(ec.size);
      const priv = ec.privateKeyGenerate();
      const pub = ec.publicKeyCreate(priv);
      const pubu = ec.publicKeyConvert(pub, false);

      const sig = ec.sign(msg, priv);
      assert(ec.verify(msg, sig, pub));
      assert(ec.verify(msg, sig, pubu));
    });

    it(`should tweak keys (${ec.id})`, () => {
      const priv = ec.privateKeyGenerate();
      const pub = ec.publicKeyCreate(priv);
      const tweak = random.randomBytes(ec.size);

      const tpriv = ec.privateKeyTweakAdd(priv, tweak);
      const tpub = ec.publicKeyTweakAdd(pub, tweak);

      const msg = random.randomBytes(ec.size);

      const sig = ec.sign(msg, tpriv);
      assert(ec.verify(msg, sig, tpub));

      const der = ec.signDER(msg, tpriv);
      assert(ec.verifyDER(msg, der, tpub));
    });

    it(`should do ECDH (${ec.id})`, () => {
      const alicePriv = ec.privateKeyGenerate();
      const alicePub = ec.publicKeyCreate(alicePriv);
      const bobPriv = ec.privateKeyGenerate();
      const bobPub = ec.publicKeyCreate(bobPriv);

      const aliceSecret = ec.ecdh(bobPub, alicePriv);
      const bobSecret = ec.ecdh(alicePub, bobPriv);

      assert.bufferEqual(aliceSecret, bobSecret);
    });
  }
});
