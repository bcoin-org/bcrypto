/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const fs = require('fs');
const random = require('../lib/random');
const ed25519 = require('../lib/ed25519');
const derivations = require('./data/ed25519.json');

const filename = `${__dirname}/data/ed25519.input`;
const lines = fs.readFileSync(filename, 'binary').trim().split('\n');

assert.strictEqual(lines.length, 1024);

describe('EdDSA', function() {
  this.timeout(15000);

  it('should generate keypair and sign', () => {
    const msg = random.randomBytes(ed25519.size);
    const priv = ed25519.privateKeyGenerate();
    const pub = ed25519.publicKeyCreate(priv);

    const sig = ed25519.sign(msg, priv);
    assert(ed25519.verify(msg, sig, pub));
  });

  describe('ed25519 derivations', () => {
    for (const [i, test] of derivations.entries()) {
      it(`can compute correct a and A for secret: ${i}`, () => {
        const secret = Buffer.from(test.secret_hex, 'hex');
        const priv = ed25519.privateKeyCreate(secret);
        const pub = ed25519.publicKeyCreate(secret);

        assert.bufferEqual(priv, Buffer.from(test.a_hex, 'hex'));
        assert.bufferEqual(pub, Buffer.from(test.A_hex, 'hex'));
      });
    }
  });

  describe('sign.input ed25519 test vectors', () => {
    for (const [i, line] of lines.entries()) {
      it(`vector ${i}`, () => {
        const split = line.toUpperCase().split(':');
        const secret = Buffer.from(split[0].slice(0, 64), 'hex');
        const pub = ed25519.publicKeyCreate(secret);

        const expectedPk = Buffer.from(split[0].slice(64), 'hex');

        assert.bufferEqual(pub, expectedPk);

        const msg = Buffer.from(split[2], 'hex');
        const sig = ed25519.sign(msg, secret);
        const sigR = sig.slice(0, 32);
        const sigS = sig.slice(32);

        assert.bufferEqual(sigR, Buffer.from(split[3].slice(0, 64), 'hex'));
        assert.bufferEqual(sigS, Buffer.from(split[3].slice(64, 128), 'hex'));
        assert(ed25519.verify(msg, sig, pub));

        let forged = Buffer.from([0x78]); // ord('x')

        if (msg.length > 0) {
          forged = Buffer.concat([
             msg.slice(0, msg.length - 1),
             Buffer.from([(msg[(msg.length - 1)] + 1) % 256])
          ]);
        }

        assert.strictEqual(msg.length || 1, forged.length);
        assert(!ed25519.verify(forged, sig, pub));
      });
    }
  });
});
