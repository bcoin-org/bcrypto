/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const secp256k1 = require('../lib/secp256k1');
const vectors1 = require('./data/secp256k1-1.json'); // bcoin
const vectors2 = require('./data/secp256k1-2.json'); // hsd
const vectors3 = require('./data/secp256k1-3.json'); // script
const vectors4 = require('./data/secp256k1-4.json'); // tx

describe('Secp256k1', function() {
  for (const vectors of [vectors1, vectors2, vectors3, vectors4]) {
    for (const vector of vectors.public_key_create) {
      const key = Buffer.from(vector.key, 'hex');
      const compress = vector.compress;
      const result = Buffer.from(vector.result, 'hex');

      it(`should create public key from private key: ${vector.key}`, () => {
        assert.bufferEqual(secp256k1.publicKeyCreate(key, compress), result);
      });
    }

    for (const vector of vectors.public_key_convert) {
      const key = Buffer.from(vector.key, 'hex');
      const compress = vector.compress;
      const result = Buffer.from(vector.result, 'hex');

      it(`should convert public key: ${vector.key}`, () => {
        assert.bufferEqual(secp256k1.publicKeyConvert(key, compress), result);
      });
    }

    for (const vector of vectors.public_key_tweak_add) {
      const key = Buffer.from(vector.key, 'hex');
      const tweak = Buffer.from(vector.tweak, 'hex');
      const compress = vector.compress;
      const result = Buffer.from(vector.result, 'hex');

      it(`should tweak public key: ${vector.key}`, () => {
        assert.bufferEqual(
          secp256k1.publicKeyTweakAdd(key, tweak, compress),
          result);
      });
    }

    for (const vector of vectors.private_key_tweak_add) {
      const key = Buffer.from(vector.key, 'hex');
      const tweak = Buffer.from(vector.tweak, 'hex');
      const result = Buffer.from(vector.result, 'hex');

      it(`should tweak private key: ${vector.key}`, () => {
        assert.bufferEqual(secp256k1.privateKeyTweakAdd(key, tweak), result);
      });
    }

    for (const vector of vectors.ecdh) {
      const pub = Buffer.from(vector.pub, 'hex');
      const priv = Buffer.from(vector.priv, 'hex');
      const compress = vector.compress;
      const result = Buffer.from(vector.result, 'hex');

      it(`should perform ECDH: ${vector.pub}`, () => {
        assert.bufferEqual(secp256k1.ecdh(pub, priv, compress), result);
      });
    }

    for (const vector of vectors.public_key_verify) {
      const key = Buffer.from(vector.key, 'hex');
      const result = vector.result;

      it(`should verify public key: ${vector.key}`, () => {
        assert.strictEqual(secp256k1.publicKeyVerify(key), result);
      });
    }

    for (const vector of vectors.private_key_verify) {
      const key = Buffer.from(vector.key, 'hex');
      const result = vector.result;

      it(`should verify private key: ${vector.key}`, () => {
        assert.strictEqual(secp256k1.privateKeyVerify(key), result);
      });
    }

    for (const vector of vectors.verify) {
      const msg = Buffer.from(vector.msg, 'hex');
      const sig = Buffer.from(vector.sig, 'hex');
      const key = Buffer.from(vector.key, 'hex');
      const result = vector.result;

      it(`should verify R/S signature: ${vector.sig}`, () => {
        assert.strictEqual(secp256k1.verify(msg, sig, key), result);
      });
    }

    for (const vector of vectors.verify_der) {
      const msg = Buffer.from(vector.msg, 'hex');
      const sig = Buffer.from(vector.sig, 'hex');
      const key = Buffer.from(vector.key, 'hex');
      const result = vector.result;

      it(`should verify DER signature: ${vector.sig}`, () => {
        assert.strictEqual(secp256k1.verifyDER(msg, sig, key), result);
      });
    }

    for (const vector of vectors.recover) {
      const msg = Buffer.from(vector.msg, 'hex');
      const sig = Buffer.from(vector.sig, 'hex');
      const param = vector.param;
      const compress = vector.compress;
      const result = Buffer.from(vector.result, 'hex');

      it(`should recover key from R/S signature: ${vector.sig}`, () => {
        assert.bufferEqual(
          secp256k1.recover(msg, sig, param, compress),
          result);
      });
    }

    for (const vector of vectors.recover_der) {
      const msg = Buffer.from(vector.msg, 'hex');
      const sig = Buffer.from(vector.sig, 'hex');
      const param = vector.param;
      const compress = vector.compress;
      const result = Buffer.from(vector.result, 'hex');

      it(`should recover key from DER signature: ${vector.sig}`, () => {
        assert.bufferEqual(
          secp256k1.recoverDER(msg, sig, param, compress),
          result);
      });
    }

    for (const vector of vectors.from_der) {
      const sig = Buffer.from(vector.sig, 'hex');
      const result = Buffer.from(vector.result, 'hex');

      it(`should convert DER to R/S: ${vector.sig}`, () => {
        assert.bufferEqual(secp256k1.fromDER(sig), result);
      });
    }

    for (const vector of vectors.to_der) {
      const sig = Buffer.from(vector.sig, 'hex');
      const result = Buffer.from(vector.result, 'hex');

      it(`should convert R/S to DER: ${vector.sig}`, () => {
        assert.bufferEqual(secp256k1.toDER(sig), result);
      });
    }

    for (const vector of vectors.is_low_s) {
      const sig = Buffer.from(vector.sig, 'hex');
      const result = vector.result;

      it(`should test S value (R/S): ${vector.sig}`, () => {
        assert.strictEqual(secp256k1.isLowS(sig), result);
      });
    }

    for (const vector of vectors.is_low_der) {
      const sig = Buffer.from(vector.sig, 'hex');
      const result = vector.result;

      it(`should test S value (DER): ${vector.sig}`, () => {
        assert.strictEqual(secp256k1.isLowDER(sig), result);
      });
    }
  }

  for (const vectors of [vectors1, vectors2, vectors3, vectors4]) {
    for (const vector of vectors.public_key_create) {
      const key = Buffer.from(vector.key, 'hex');
      const compress = vector.compress;
      const result = Buffer.from(vector.result, 'hex');

      it(`should create public key from private key: ${vector.key}`, () => {
        const priv = new secp256k1.PrivateKey(key);
        assert.bufferEqual(priv.toPublic().toPoint(compress), result);
      });
    }

    for (const vector of vectors.public_key_convert) {
      const key = Buffer.from(vector.key, 'hex');
      const compress = vector.compress;
      const result = Buffer.from(vector.result, 'hex');

      it(`should convert public key: ${vector.key}`, () => {
        const pub = secp256k1.PublicKey.fromPoint(key);
        assert.bufferEqual(pub.toPoint(compress), result);
      });
    }

    for (const vector of vectors.public_key_tweak_add) {
      const key = Buffer.from(vector.key, 'hex');
      const tweak = Buffer.from(vector.tweak, 'hex');
      const compress = vector.compress;
      const result = Buffer.from(vector.result, 'hex');

      it(`should tweak public key: ${vector.key}`, () => {
        const pub = secp256k1.PublicKey.fromPoint(key);

        assert.bufferEqual(
          pub.tweakAdd(tweak).toPoint(compress),
          result);
      });
    }

    for (const vector of vectors.private_key_tweak_add) {
      const key = Buffer.from(vector.key, 'hex');
      const tweak = Buffer.from(vector.tweak, 'hex');
      const result = Buffer.from(vector.result, 'hex');

      it(`should tweak private key: ${vector.key}`, () => {
        const priv = new secp256k1.PrivateKey(key);
        assert.bufferEqual(priv.tweakAdd(tweak).d, result);
      });
    }

    for (const vector of vectors.ecdh) {
      const bpub = Buffer.from(vector.pub, 'hex');
      const bpriv = Buffer.from(vector.priv, 'hex');
      const compress = vector.compress;
      const result = Buffer.from(vector.result, 'hex');

      it(`should perform ECDH: ${vector.pub}`, () => {
        const priv = new secp256k1.PrivateKey(bpriv);
        const pub = secp256k1.PublicKey.fromPoint(bpub);
        assert.bufferEqual(priv.ecdh(pub).toPoint(compress), result);
      });
    }

    for (const vector of vectors.public_key_verify) {
      const key = Buffer.from(vector.key, 'hex');
      const result = vector.result;

      it(`should verify public key: ${vector.key}`, () => {
        let pub;
        try {
          pub = secp256k1.PublicKey.fromPoint(key);
        } catch (e) {
          assert.strictEqual(false, result);
          return;
        }
        assert.strictEqual(pub.validate(), result);
      });
    }

    for (const vector of vectors.private_key_verify) {
      const key = Buffer.from(vector.key, 'hex');
      const result = vector.result;

      it(`should verify private key: ${vector.key}`, () => {
        let priv;
        try {
          priv = new secp256k1.PrivateKey(key);
        } catch (e) {
          assert.strictEqual(false, result);
          return;
        }
        assert.strictEqual(priv.validate(), result);
      });
    }

    for (const vector of vectors.verify) {
      const msg = Buffer.from(vector.msg, 'hex');
      const rs = Buffer.from(vector.sig, 'hex');
      const point = Buffer.from(vector.key, 'hex');
      const result = vector.result;

      it(`should verify R/S signature: ${vector.sig}`, () => {
        let pub;
        try {
          pub = secp256k1.PublicKey.fromPoint(point);
        } catch (e) {
          assert.strictEqual(false, result);
          return;
        }
        let sig;
        try {
          sig = secp256k1.Signature.decode(rs);
        } catch (e) {
          assert.strictEqual(false, result);
          return;
        }
        assert.strictEqual(pub.verify(msg, sig), result);
      });
    }

    for (const vector of vectors.verify_der) {
      const msg = Buffer.from(vector.msg, 'hex');
      const der = Buffer.from(vector.sig, 'hex');
      const point = Buffer.from(vector.key, 'hex');
      const result = vector.result;

      it(`should verify DER signature: ${vector.sig}`, () => {
        let pub;
        try {
          pub = secp256k1.PublicKey.fromPoint(point);
        } catch (e) {
          assert.strictEqual(false, result);
          return;
        }
        let sig;
        try {
          sig = secp256k1.Signature.fromDER(der);
        } catch (e) {
          assert.strictEqual(false, result);
          return;
        }
        assert.strictEqual(pub.verify(msg, sig), result);
      });
    }

    for (const vector of vectors.recover) {
      const msg = Buffer.from(vector.msg, 'hex');
      const rs = Buffer.from(vector.sig, 'hex');
      const param = vector.param;
      const compress = vector.compress;
      const result = Buffer.from(vector.result, 'hex');

      it(`should recover key from R/S signature: ${vector.sig}`, () => {
        const sig = secp256k1.Signature.decode(rs);
        const key = secp256k1.PublicKey.recover(msg, sig, param);
        assert.bufferEqual(key.toPoint(compress), result);
      });
    }

    for (const vector of vectors.recover_der) {
      const msg = Buffer.from(vector.msg, 'hex');
      const rs = Buffer.from(vector.sig, 'hex');
      const param = vector.param;
      const compress = vector.compress;
      const result = Buffer.from(vector.result, 'hex');

      it(`should recover key from DER signature: ${vector.sig}`, () => {
        const sig = secp256k1.Signature.fromDER(rs);
        const key = secp256k1.PublicKey.recover(msg, sig, param);
        assert.bufferEqual(key.toPoint(compress), result);
      });
    }

    for (const vector of vectors.from_der) {
      const der = Buffer.from(vector.sig, 'hex');
      const result = Buffer.from(vector.result, 'hex');

      it(`should convert DER to R/S: ${vector.sig}`, () => {
        assert.bufferEqual(secp256k1.Signature.fromDER(der).encode(), result);
      });
    }

    for (const vector of vectors.to_der) {
      const rs = Buffer.from(vector.sig, 'hex');
      const result = Buffer.from(vector.result, 'hex');

      it(`should convert R/S to DER: ${vector.sig}`, () => {
        assert.bufferEqual(secp256k1.Signature.decode(rs).toDER(), result);
      });
    }

    for (const vector of vectors.is_low_s) {
      const rs = Buffer.from(vector.sig, 'hex');
      const result = vector.result;

      it(`should test S value (R/S): ${vector.sig}`, () => {
        assert.strictEqual(secp256k1.Signature.decode(rs).isLowS(), result);
      });
    }

    for (const vector of vectors.is_low_der) {
      const der = Buffer.from(vector.sig, 'hex');
      const result = vector.result;

      it(`should test S value (DER): ${vector.sig}`, () => {
        assert.strictEqual(secp256k1.Signature.fromDER(der).isLowS(), result);
      });
    }
  }
});
