/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const random = require('../lib/random');

const curves = [
  require('../lib/ed25519')
];

describe('EdDSA', function() {
  this.timeout(15000);

  for (const ec of curves) {
    it(`should generate keypair and sign (${ec.id})`, () => {
      const msg = random.randomBytes(ec.size);
      const priv = ec.privateKeyGenerate();
      const pub = ec.publicKeyCreate(priv);

      const sig = ec.sign(msg, priv);
      assert(ec.verify(msg, sig, pub));
    });
  }
});
