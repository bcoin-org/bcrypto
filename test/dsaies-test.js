/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const random = require('../lib/random');
const SHA256 = require('../lib/sha256');
const dsa = require('../lib/dsa');
const dsaies = require('../lib/dsaies');

describe('DSAIES', function() {
  this.timeout(30000);

  for (const withKey of [true, false]) {
    for (const size of [1024, 2048, 3072]) {
      it(`should encrypt and decrypt (${size})`, () => {
        const bobPriv = dsa.privateKeyGenerate(1024);
        const bobPub = dsa.publicKeyCreate(bobPriv);
        const alicePriv = dsa.privateKeyCreate(bobPub);

        const msg = random.randomBytes(100);
        const ct = dsaies.encrypt(
          SHA256, msg, bobPub, withKey ? alicePriv : null);

        assert.notBufferEqual(ct, msg);
        assert(ct.length > msg.length);

        const pt = dsaies.decrypt(SHA256, ct, bobPriv);
        assert.bufferEqual(pt, msg);

        assert.throws(() => {
          dsaies.decrypt(SHA256, ct, alicePriv);
        });

        for (let i = 0; i < ct.length; i++) {
          ct[i] ^= 1;
          assert.throws(() => {
            dsaies.decrypt(SHA256, ct, bobPriv);
          });
          ct[i] ^= 1;
        }
      });
    }
  }
});
