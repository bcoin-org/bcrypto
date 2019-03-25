/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const random = require('../lib/random');
const ed448 = require('../lib/ed448');
const SHAKE256 = require('../lib/shake256');
const rfc8032 = require('./data/rfc8032-vectors.json');

describe('Ed448', function() {
  this.timeout(15000);

  it('should generate keypair and sign', () => {
    const msg = random.randomBytes(ed448.size);
    const secret = ed448.privateKeyGenerate();
    const pub = ed448.publicKeyCreate(secret);

    assert(ed448.publicKeyVerify(pub));

    const sig = ed448.sign(msg, secret);
    assert(ed448.verify(msg, sig, pub));

    sig[(Math.random() * sig.length) | 0] ^= 1;

    assert(!ed448.verify(msg, sig, pub));

    assert.bufferEqual(
      ed448.privateKeyImport(ed448.privateKeyExport(secret)),
      secret);

    assert.bufferEqual(
      ed448.privateKeyImportPKCS8(ed448.privateKeyExportPKCS8(secret)),
      secret);

    assert.bufferEqual(
      ed448.publicKeyImport(ed448.publicKeyExport(pub)),
      pub);

    assert.bufferEqual(
      ed448.publicKeyImportSPKI(ed448.publicKeyExportSPKI(pub)),
      pub);
  });

  it('should do ECDH', () => {
    const alicePriv = ed448.privateKeyGenerate();
    const alicePub = ed448.publicKeyCreate(alicePriv);

    const bobPriv = ed448.privateKeyGenerate();
    const bobPub = ed448.publicKeyCreate(bobPriv);

    const aliceSecret = ed448.derive(bobPub, alicePriv);
    const bobSecret = ed448.derive(alicePub, bobPriv);

    assert.bufferEqual(aliceSecret, bobSecret);

    const secret = aliceSecret;
    const xsecret = ed448.publicKeyConvert(secret);
    const xalicePub = ed448.publicKeyConvert(alicePub);
    const xbobPub = ed448.publicKeyConvert(bobPub);

    assert.notBufferEqual(xsecret, secret);

    const xaliceSecret = ed448.exchange(xbobPub, alicePriv);
    const xbobSecret = ed448.exchange(xalicePub, bobPriv);

    assert.bufferEqual(xaliceSecret, xsecret);
    assert.bufferEqual(xbobSecret, xsecret);
  });

  it('should do ECDH (with scalar)', () => {
    const aliceSeed = ed448.privateKeyGenerate();
    const alicePriv = ed448.privateKeyConvert(aliceSeed);
    const alicePub = ed448.publicKeyFromScalar(alicePriv);

    assert.bufferEqual(alicePub, ed448.publicKeyCreate(aliceSeed));

    const bobSeed = ed448.privateKeyGenerate();
    const bobPriv = ed448.privateKeyConvert(bobSeed);
    const bobPub = ed448.publicKeyFromScalar(bobPriv);

    assert.bufferEqual(bobPub, ed448.publicKeyCreate(bobSeed));

    const aliceSecret = ed448.deriveWithScalar(bobPub, alicePriv);
    const bobSecret = ed448.deriveWithScalar(alicePub, bobPriv);

    assert.bufferEqual(aliceSecret, bobSecret);

    const xalicePub = ed448.publicKeyConvert(alicePub);
    const xbobPub = ed448.publicKeyConvert(bobPub);

    const xaliceSecret = ed448.exchangeWithScalar(xbobPub, alicePriv);
    const xbobSecret = ed448.exchangeWithScalar(xalicePub, bobPriv);

    assert.bufferEqual(xaliceSecret, xbobSecret);
  });

  it('should do ECDH (vector)', () => {
    const pub = Buffer.from(''
      + '93890d139f2e5fedfdaa552aae92'
      + 'e5cc5c716719c28a2e2273962d10'
      + 'a83fc02f0205b1e2478239e4a267'
      + 'f5edd9489a3556f48df899424b4b'
      + '00', 'hex');

    const priv = Buffer.from(''
      + 'a18d4e50f52e78a24e68288b3496'
      + 'd8881066a65b970ded82aac98b59'
      + '8d062648daf289640c830e9098af'
      + '286e8d1a19c7a1623c05d817d78c'
      + '3d', 'hex');

    const xsecret = Buffer.from(''
      + '5b205505fece8945fe02482d2e89'
      + 'e585244b3aec6af8db4e1f570d3c'
      + '2a9f48ada996cb293e457867c9e3'
      + 'fecdec40fe7a8d922bbdac406d0e', 'hex');

    const secret2 = ed448.derive(pub, priv);
    const xsecret2 = ed448.publicKeyConvert(secret2);

    assert.notBufferEqual(secret2, xsecret);
    assert.bufferEqual(xsecret2, xsecret);

    const xpub = ed448.publicKeyConvert(pub);
    const xsecret3 = ed448.exchange(xpub, priv);

    assert.bufferEqual(xsecret3, xsecret);
  });

  it('should generate keypair and sign with additive tweak', () => {
    const key = ed448.privateKeyGenerate();
    const pub = ed448.publicKeyCreate(key);
    const tweak = ed448.scalarGenerate();
    const msg = random.randomBytes(57);
    const child = ed448.publicKeyTweakAdd(pub, tweak);
    const sig = ed448.signTweakAdd(msg, key, tweak);

    assert(ed448.scalarVerify(tweak));
    assert.notBufferEqual(child, pub);

    const childPriv = ed448.scalarTweakAdd(ed448.privateKeyConvert(key), tweak);
    const childPub = ed448.publicKeyFromScalar(childPriv);
    assert.bufferEqual(childPub, child);

    assert(ed448.verify(msg, sig, child));

    const sig2 = ed448.signWithScalar(msg, childPriv, msg);
    assert(ed448.verify(msg, sig2, child));
  });

  it('should generate keypair and sign with multiplicative tweak', () => {
    const key = ed448.privateKeyGenerate();
    const pub = ed448.publicKeyCreate(key);
    const tweak = ed448.scalarGenerate();
    const msg = random.randomBytes(57);
    const child = ed448.publicKeyTweakMul(pub, tweak);

    assert(ed448.scalarVerify(tweak));
    assert.notBufferEqual(child, pub);

    const sig = ed448.signTweakMul(msg, key, tweak);

    const childPriv = ed448.scalarTweakMul(ed448.privateKeyConvert(key), tweak);
    const childPub = ed448.publicKeyFromScalar(childPriv);
    assert.bufferEqual(childPub, child);

    assert(ed448.verify(msg, sig, child));

    const sig2 = ed448.signWithScalar(msg, childPriv, msg);
    assert(ed448.verify(msg, sig2, child));
  });

  it('should convert to montgomery (vector)', () => {
    const pub = Buffer.from(''
      + '3167a5f7ce692bcf3af9094f792c'
      + 'b3618ea034371703a3ffd222254e'
      + '6edba0156aa236c2b3ef406e700c'
      + '55a0beff8e141348cfd354682321'
      + '00', 'hex');

    const xpub = Buffer.from(''
      + '439a943c1550ac472058a2083aed'
      + '6d91f9e74a4d70807b726359d51a'
      + '01d4fb9cb4871f3b2664f0f08e91'
      + '9eb3afc9100de9e56a05828f1f15',
      'hex');

    const xpub2 = ed448.publicKeyConvert(pub);

    assert.bufferEqual(xpub2, xpub);
  });

  it('should sign and verify (vector)', () => {
    const priv = Buffer.from(''
      + 'd65df341ad13e008567688baedda8e9d'
      + 'cdc17dc024974ea5b4227b6530e339bf'
      + 'f21f99e68ca6968f3cca6dfe0fb9f4fa'
      + 'b4fa135d5542ea3f01',
      'hex');

    const pub = Buffer.from(''
      + 'df9705f58edbab802c7f8363cfe5560a'
      + 'b1c6132c20a9f1dd163483a26f8ac53a'
      + '39d6808bf4a1dfbd261b099bb03b3fb5'
      + '0906cb28bd8a081f00',
      'hex');

    const msg = Buffer.from(''
      + 'bd0f6a3747cd561bdddf4640a332461a'
      + '4a30a12a434cd0bf40d766d9c6d458e5'
      + '512204a30c17d1f50b5079631f64eb31'
      + '12182da3005835461113718d1a5ef944',
      'hex');

    const sig = Buffer.from(''
      + '554bc2480860b49eab8532d2a533b7d5'
      + '78ef473eeb58c98bb2d0e1ce488a98b1'
      + '8dfde9b9b90775e67f47d4a1c3482058'
      + 'efc9f40d2ca033a0801b63d45b3b722e'
      + 'f552bad3b4ccb667da350192b61c508c'
      + 'f7b6b5adadc2c8d9a446ef003fb05cba'
      + '5f30e88e36ec2703b349ca229c267083'
      + '3900',
      'hex');

    const pub2 = ed448.publicKeyCreate(priv);

    assert.bufferEqual(pub2, pub);

    const sig2 = ed448.sign(msg, priv);

    assert.bufferEqual(sig2, sig);

    const result = ed448.verify(msg, sig, pub);

    assert.strictEqual(result, true);
  });

  describe('RFC 8032 vectors', () => {
    for (const [i, vector] of rfc8032.entries()) {
      if (!vector.algorithm.startsWith('Ed448'))
        continue;

      const ph = vector.algorithm === 'Ed448ph';
      const ctx = vector.ctx != null
                ? Buffer.from(vector.ctx, 'hex')
                : null;

      let msg = Buffer.from(vector.msg, 'hex');

      if (ph)
        msg = SHAKE256.digest(msg, 64);

      const sig = Buffer.from(vector.sig, 'hex');
      const pub = Buffer.from(vector.pub, 'hex');
      const priv = Buffer.from(vector.priv, 'hex');

      it(`should pass RFC 8032 vector (${vector.algorithm} #${i})`, () => {
        assert(ed448.privateKeyVerify(priv));
        assert(ed448.publicKeyVerify(pub));

        const sig_ = ed448.sign(msg, priv, ph, ctx);

        assert.bufferEqual(sig_, sig);

        assert(ed448.verify(msg, sig, pub, ph, ctx));
        assert(!ed448.verify(msg, sig, pub, !ph, ctx));

        if (msg.length > 0) {
          const msg_ = Buffer.from(msg);
          msg_[Math.random() * msg_.length | 0] ^= 1;
          assert(!ed448.verify(msg_, sig, pub, ph, ctx));
        }

        {
          const sig_ = Buffer.from(sig);
          sig_[Math.random() * sig_.length | 0] ^= 1;
          assert(!ed448.verify(msg, sig_, pub, ph, ctx));
        }

        {
          const pub_ = Buffer.from(pub);
          pub_[Math.random() * pub_.length | 0] ^= 1;
          assert(!ed448.verify(msg, sig, pub_, ph, ctx));
        }

        if (ctx && ctx.length > 0) {
          const ctx_ = Buffer.from(ctx);
          ctx_[Math.random() * ctx_.length | 0] ^= 1;
          assert(!ed448.verify(msg, sig, pub, ph, ctx_));
          assert(!ed448.verify(msg, sig, pub, ph, null));
        } else {
          const ctx_ = Buffer.alloc(1);
          assert(!ed448.verify(msg, sig, pub, true, ctx_));
          assert(!ed448.verify(msg, sig, pub, false, ctx_));
        }
      });
    }
  });

  it('should test serialization formats', () => {
    const priv = ed448.privateKeyGenerate();
    const pub = ed448.publicKeyCreate(priv);
    const rawPriv = ed448.privateKeyExport(priv);
    const rawPub = ed448.publicKeyExport(pub);

    assert.bufferEqual(ed448.privateKeyImport(rawPriv), priv);
    assert.bufferEqual(ed448.publicKeyImport(rawPub), pub);

    const jsonPriv = ed448.privateKeyExportJWK(priv);
    const jsonPub = ed448.publicKeyExportJWK(pub);

    assert.bufferEqual(ed448.privateKeyImportJWK(jsonPriv), priv);
    assert.bufferEqual(ed448.publicKeyImportJWK(jsonPub), pub);

    const asnPriv = ed448.privateKeyExportPKCS8(priv);
    const asnPub = ed448.publicKeyExportSPKI(pub);

    assert.bufferEqual(ed448.privateKeyImportPKCS8(asnPriv), priv);
    assert.bufferEqual(ed448.publicKeyImportSPKI(asnPub), pub);
  });
});
