/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');

const NODE_MAJOR = parseInt(process.version.substring(1).split('.')[0], 10);

const ECDSA = (() => {
  if (!process.env.NODE_BACKEND || process.env.NODE_BACKEND === 'native') {
    if (NODE_MAJOR >= 10)
      return require('../lib/native/ecdsa');
  }
  return require('../lib/js/ecdsa');
})();

const random = require('../lib/random');
const SHA256 = require('../lib/sha256');
const p192 = require('../lib/p192');
const p224 = require('../lib/p224');
const p256 = require('../lib/p256');
const p384 = require('../lib/p384');
const p521 = require('../lib/p521');
const secp256k1 = new ECDSA('SECP256K1');
const secp256k1n = require('../lib/secp256k1');
const ed25519 = require('../lib/ed25519');
const ecies = require('../lib/ecies');

const curves = [
  p192,
  p224,
  p256,
  p384,
  p521,
  secp256k1,
  secp256k1n
];

describe('ECIES', function() {
  this.timeout(15000);

  for (const withKey of [true, false]) {
    for (const curve of curves) {
      it(`should encrypt and decrypt (${curve.id})`, () => {
        const alicePriv = curve.privateKeyGenerate();
        const bobPriv = curve.privateKeyGenerate();
        const bobPub = curve.publicKeyCreate(bobPriv);

        const msg = random.randomBytes(100);
        const ct = ecies.encrypt(
          curve,
          SHA256,
          msg,
          bobPub,
          withKey ? alicePriv : null
        );

        assert.notBufferEqual(ct, msg);
        assert(ct.length > msg.length);

        const pt = ecies.decrypt(curve, SHA256, ct, bobPriv);
        assert.bufferEqual(pt, msg);

        assert.throws(() => {
          ecies.decrypt(curve, SHA256, ct, alicePriv);
        });

        for (let i = 0; i < ct.length; i++) {
          ct[i] ^= 1;
          assert.throws(() => {
            ecies.decrypt(curve, SHA256, ct, bobPriv);
          });
          ct[i] ^= 1;
        }
      });
    }

    it('should encrypt and decrypt (ED25519)', () => {
      const alicePriv = ed25519.privateKeyGenerate();
      const bobPriv = ed25519.privateKeyGenerate();
      const bobPub = ed25519.publicKeyCreate(bobPriv);

      const msg = random.randomBytes(100);
      const ct = ecies.encrypt(
        ed25519,
        SHA256,
        msg,
        bobPub,
        withKey ? alicePriv : null
      );

      assert.notBufferEqual(ct, msg);
      assert(ct.length > msg.length);

      const pt = ecies.decrypt(ed25519, SHA256, ct, bobPriv);
      assert.bufferEqual(pt, msg);

      assert.throws(() => {
        ecies.decrypt(ed25519, SHA256, ct, alicePriv);
      });

      for (let i = 0; i < ct.length; i++) {
        ct[i] ^= 1;
        assert.throws(() => {
          ecies.decrypt(ed25519, ct, SHA256, bobPriv);
        });
        ct[i] ^= 1;
      }
    });
  }
});
