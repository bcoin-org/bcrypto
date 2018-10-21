/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const fs = require('fs');
const Path = require('path');
const random = require('../lib/random');
const ed25519 = require('../lib/ed25519');
const derivations = require('./data/ed25519.json');

const filename = Path.resolve(__dirname, 'data', 'ed25519.input');
const lines = fs.readFileSync(filename, 'binary').trim().split('\n');

assert.strictEqual(lines.length, 1024);

describe('EdDSA', function() {
  this.timeout(15000);

  it('should generate keypair and sign', () => {
    const msg = random.randomBytes(ed25519.size);
    const secret = ed25519.privateKeyGenerate();
    const pub = ed25519.publicKeyCreate(secret);

    assert(ed25519.publicKeyVerify(pub));

    const sig = ed25519.sign(msg, secret);
    assert(ed25519.verify(msg, sig, pub));

    sig[(Math.random() * sig.length) | 0] ^= 1;

    assert(!ed25519.verify(msg, sig, pub));

    assert.bufferEqual(
      ed25519.privateKeyImport(ed25519.privateKeyExport(secret)),
      secret);

    assert.bufferEqual(
      ed25519.privateKeyImportPKCS8(ed25519.privateKeyExportPKCS8(secret)),
      secret);

    assert.bufferEqual(
      ed25519.publicKeyImport(ed25519.publicKeyExport(pub)),
      pub);

    assert.bufferEqual(
      ed25519.publicKeyImportSPKI(ed25519.publicKeyExportSPKI(pub)),
      pub);
  });

  it('should do ECDH', () => {
    const alicePriv = ed25519.privateKeyGenerate();
    const alicePub = ed25519.publicKeyCreate(alicePriv);

    const bobPriv = ed25519.privateKeyGenerate();
    const bobPub = ed25519.publicKeyCreate(bobPriv);

    const aliceSecret = ed25519.derive(bobPub, alicePriv);
    const bobSecret = ed25519.derive(alicePub, bobPriv);

    assert.bufferEqual(aliceSecret, bobSecret);
  });

  it('should do ECDH (vector)', () => {
    const alicePriv = Buffer.from(
      '50ec6e55b18b882e06bdc12ff2f80f8f8fa68b04370b45439cf80b4e02610e1e',
      'hex');

    const bobPriv = Buffer.from(
      'c3fb48a8c4e961ab3edb799eea22ff1d07b803140734266748ea4c753dd3655d',
      'hex');

    const alicePub = ed25519.publicKeyCreate(alicePriv);
    const bobPub = ed25519.publicKeyCreate(bobPriv);

    const secret = Buffer.from(
      '4084c076e4ff79e8af71425c0c0b573057e9ebf36185ec8572ec161ddf6f2731',
      'hex');

    const aliceSecret = ed25519.derive(bobPub, alicePriv);
    const bobSecret = ed25519.derive(alicePub, bobPriv);

    assert.bufferEqual(aliceSecret, secret);
    assert.bufferEqual(bobSecret, secret);
  });

  describe('ed25519 derivations', () => {
    for (const [i, test] of derivations.entries()) {
      it(`should compute correct a and A for secret: ${i}`, () => {
        const secret = Buffer.from(test.secret_hex, 'hex');
        const priv = ed25519.privateKeyConvert(secret);
        const pub = ed25519.publicKeyCreate(secret);

        assert(ed25519.publicKeyVerify(pub));

        assert.bufferEqual(priv, Buffer.from(test.a_hex, 'hex'));
        assert.bufferEqual(pub, Buffer.from(test.A_hex, 'hex'));
      });
    }
  });

  describe('sign.input ed25519 test vectors', () => {
    for (const [i, line] of lines.entries()) {
      it(`should pass ed25519 vector #${i}`, () => {
        const split = line.toUpperCase().split(':');
        const secret = Buffer.from(split[0].slice(0, 64), 'hex');
        const pub = ed25519.publicKeyCreate(secret);

        assert(ed25519.publicKeyVerify(pub));

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
