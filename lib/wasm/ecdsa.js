/*!
 * ecdsa.js - ecdsa wrapper for openssl
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const wasm = require('./binding');
const asn1 = require('../encoding/asn1');
const sec1 = require('../encoding/sec1');
const pkcs8 = require('../encoding/pkcs8');
const x509 = require('../encoding/x509');
const eckey = require('../internal/eckey');

/**
 * ECDSA
 */

class ECDSA {
  constructor(name) {
    this.id = name;
    this.ctx = wasm.curves[name];
    this.type = 'short';
    this.size = wasm.call('bcrypto_ecdsa_field_length', this.ctx);
    this.bits = wasm.call('bcrypto_ecdsa_field_bits', this.ctx);
    this.scalarSize = wasm.call('bcrypto_ecdsa_scalar_length', this.ctx);
    this.keySize = 1 + this.size * 2;
    this.sigSize = this.scalarSize * 2;
    this.derSize = 9 + this.sigSize;
    this.native = 2;
  }

  privateKeyGenerate() {
    const save = wasm.save();
    const out = wasm.alloc(this.scalarSize);

    try {
      wasm.throws('bcrypto_ecdsa_privkey_generate', this.ctx, out);
      return wasm.read(out, this.scalarSize);
    } finally {
      wasm.restore(save);
    }
  }

  privateKeyVerify(key) {
    assert(Buffer.isBuffer(key));

    if (key.length !== this.scalarSize)
      return false;

    return wasm.call('bcrypto_ecdsa_privkey_verify', this.ctx, key) === 1;
  }

  privateKeyExport(key, compress) {
    const pub = this.publicKeyCreate(key, compress);
    return new sec1.ECPrivateKey(1, key, this.id, pub).encode();
  }

  privateKeyImport(raw) {
    const key = sec1.ECPrivateKey.decode(raw);
    const curve = key.namedCurveOID.toString();

    assert(key.version.toNumber() === 1);
    assert(curve === asn1.objects.curves[this.id]
        || curve === asn1.objects.NONE);

    const {value} = key.privateKey;

    if (value.length > this.size)
      throw new Error('Invalid private key.');

    const out = Buffer.alloc(this.size, 0x00);

    value.copy(out, out.length - value.length);

    return out;
  }

  privateKeyExportPKCS8(key, compress) {
    const pub = this.publicKeyCreate(key, compress);
    const curve = asn1.objects.NONE;

    // https://tools.ietf.org/html/rfc5915
    return new pkcs8.PrivateKeyInfo(
      0,
      asn1.objects.keyAlgs.ECDSA,
      new asn1.OID(asn1.objects.curves[this.id]),
      new sec1.ECPrivateKey(1, key, curve, pub).encode()
    ).encode();
  }

  privateKeyImportPKCS8(raw) {
    const pki = pkcs8.PrivateKeyInfo.decode(raw);
    const {algorithm, parameters} = pki.algorithm;

    assert(pki.version.toNumber() === 0);
    assert(algorithm.toString() === asn1.objects.keyAlgs.ECDSA);
    assert(parameters.node.type === asn1.types.OID);
    assert(parameters.node.toString() === asn1.objects.curves[this.id]);

    return this.privateKeyImport(pki.privateKey.value);
  }

  privateKeyExportJWK(key) {
    return eckey.privateKeyExportJWK(this, key);
  }

  privateKeyImportJWK(json) {
    return eckey.privateKeyImportJWK(this, json);
  }

  privateKeyTweakAdd(key, tweak) {
    assert(Buffer.isBuffer(key));
    assert(Buffer.isBuffer(tweak));
    assert(key.length === this.scalarSize);
    assert(tweak.length === this.scalarSize);

    const save = wasm.save();
    const out = wasm.alloc(this.scalarSize);

    try {
      wasm.throws('bcrypto_ecdsa_privkey_tweak_add', this.ctx, out, key, tweak);
      return wasm.read(out, this.scalarSize);
    } finally {
      wasm.restore(save);
    }
  }

  privateKeyTweakMul(key, tweak) {
    assert(Buffer.isBuffer(key));
    assert(Buffer.isBuffer(tweak));
    assert(key.length === this.scalarSize);
    assert(tweak.length === this.scalarSize);

    const save = wasm.save();
    const out = wasm.alloc(this.scalarSize);

    try {
      wasm.throws('bcrypto_ecdsa_privkey_tweak_mul', this.ctx, out, key, tweak);
      return wasm.read(out, this.scalarSize);
    } finally {
      wasm.restore(save);
    }
  }

  privateKeyReduce(key) {
    assert(Buffer.isBuffer(key));

    const save = wasm.save();
    const out = wasm.alloc(this.scalarSize);

    try {
      wasm.throws('bcrypto_ecdsa_privkey_reduce',
                  this.ctx, out, key, key.length);
      return wasm.read(out, this.scalarSize);
    } finally {
      wasm.restore(save);
    }
  }

  privateKeyNegate(key) {
    assert(Buffer.isBuffer(key));
    assert(key.length === this.scalarSize);

    const save = wasm.save();
    const out = wasm.alloc(this.scalarSize);

    try {
      wasm.throws('bcrypto_ecdsa_privkey_negate', this.ctx, out, key);
      return wasm.read(out, this.scalarSize);
    } finally {
      wasm.restore(save);
    }
  }

  privateKeyInverse(key) {
    assert(Buffer.isBuffer(key));
    assert(key.length === this.scalarSize);

    const save = wasm.save();
    const out = wasm.alloc(this.scalarSize);

    try {
      wasm.throws('bcrypto_ecdsa_privkey_inverse', this.ctx, out, key);
      return wasm.read(out, this.scalarSize);
    } finally {
      wasm.restore(save);
    }
  }

  publicKeyCreate(key, compress = true) {
    assert(Buffer.isBuffer(key));
    assert(key.length === this.scalarSize);
    assert(typeof compress === 'boolean');

    const save = wasm.save();
    const out = wasm.alloc(this.keySize);
    const len = wasm.pushSize(0);

    try {
      wasm.throws('bcrypto_ecdsa_pubkey_create',
                  this.ctx, out, len, key, compress);
      return wasm.read(out, wasm.getSize(len));
    } finally {
      wasm.restore(save);
    }
  }

  publicKeyConvert(key, compress = true) {
    assert(Buffer.isBuffer(key));
    assert(typeof compress === 'boolean');

    const save = wasm.save();
    const out = wasm.alloc(this.keySize);
    const len = wasm.pushSize(0);

    try {
      wasm.throws('bcrypto_ecdsa_pubkey_convert', this.ctx,
                  out, len, key, key.length, compress);
      return wasm.read(out, wasm.getSize(len));
    } finally {
      wasm.restore(save);
    }
  }

  publicKeyVerify(key) {
    assert(Buffer.isBuffer(key));

    return wasm.call('bcrypto_ecdsa_pubkey_verify',
                     this.ctx, key, key.length) === 1;
  }

  publicKeyExport(key) {
    return this.publicKeyConvert(key, false).slice(1);
  }

  publicKeyImport(raw, compress) {
    assert(Buffer.isBuffer(raw));
    assert(raw.length === this.size * 2);

    const key = Buffer.allocUnsafe(1 + raw.length);
    key[0] = 0x04;
    raw.copy(key, 1);

    return this.publicKeyConvert(key, compress);
  }

  publicKeyExportSPKI(key, compress) {
    // https://tools.ietf.org/html/rfc5480
    return new x509.SubjectPublicKeyInfo(
      asn1.objects.keyAlgs.ECDSA,
      new asn1.OID(asn1.objects.curves[this.id]),
      this.publicKeyConvert(key, compress)
    ).encode();
  }

  publicKeyImportSPKI(raw, compress) {
    const spki = x509.SubjectPublicKeyInfo.decode(raw);
    const {algorithm, parameters} = spki.algorithm;

    assert(algorithm.toString() === asn1.objects.keyAlgs.ECDSA);
    assert(parameters.node.type === asn1.types.OID);
    assert(parameters.node.toString() === asn1.objects.curves[this.id]);

    return this.publicKeyConvert(spki.publicKey.rightAlign(), compress);
  }

  publicKeyExportJWK(key) {
    return eckey.publicKeyExportJWK(this, key);
  }

  publicKeyImportJWK(json, compress) {
    return eckey.publicKeyImportJWK(this, json, compress);
  }

  publicKeyTweakAdd(key, tweak, compress = true) {
    assert(Buffer.isBuffer(key));
    assert(typeof compress === 'boolean');

    const save = wasm.save();
    const out = wasm.alloc(this.keySize);
    const len = wasm.pushSize(0);

    try {
      wasm.throws('bcrypto_ecdsa_pubkey_tweak_add', this.ctx,
                  out, len, key, key.length, tweak, compress);
      return wasm.read(out, wasm.getSize(len));
    } finally {
      wasm.restore(save);
    }
  }

  publicKeyTweakMul(key, tweak, compress = true) {
    assert(Buffer.isBuffer(key));
    assert(typeof compress === 'boolean');

    const save = wasm.save();
    const out = wasm.alloc(this.keySize);
    const len = wasm.pushSize(0);

    try {
      wasm.throws('bcrypto_ecdsa_pubkey_tweak_mul', this.ctx,
                  out, len, key, key.length, tweak, compress);
      return wasm.read(out, wasm.getSize(len));
    } finally {
      wasm.restore(save);
    }
  }

  publicKeyAdd(key1, key2, compress = true) {
    assert(Buffer.isBuffer(key1));
    assert(Buffer.isBuffer(key2));
    assert(typeof compress === 'boolean');

    const save = wasm.save();
    const out = wasm.alloc(this.keySize);
    const len = wasm.pushSize(0);

    try {
      wasm.throws('bcrypto_ecdsa_pubkey_add', this.ctx, out, len,
                  key1, key1.length, key2, key2.length, compress);
      return wasm.read(out, wasm.getSize(len));
    } finally {
      wasm.restore(save);
    }
  }

  publicKeyNegate(key, compress = true) {
    assert(Buffer.isBuffer(key));
    assert(typeof compress === 'boolean');

    const save = wasm.save();
    const out = wasm.alloc(this.keySize);
    const len = wasm.pushSize(0);

    try {
      wasm.throws('bcrypto_ecdsa_pubkey_negate', this.ctx,
                  out, len, key, key.length, compress);
      return wasm.read(out, wasm.getSize(len));
    } finally {
      wasm.restore(save);
    }
  }

  signatureNormalize(raw) {
    assert(Buffer.isBuffer(raw));
    assert(raw.length === this.sigSize);

    const save = wasm.save();
    const out = wasm.alloc(this.sigSize);

    try {
      wasm.throws('bcrypto_ecdsa_sig_normalize', this.ctx, out, raw);
      return wasm.read(out, this.sigSize);
    } finally {
      wasm.restore(save);
    }
  }

  signatureExport(sig) {
    assert(Buffer.isBuffer(sig));
    assert(sig.length === this.sigSize);

    const save = wasm.save();
    const out = wasm.alloc(this.derSize);
    const len = wasm.pushSize(0);

    try {
      wasm.throws('bcrypto_ecdsa_sig_export', this.ctx, out, len, sig);
      return wasm.read(out, wasm.getSize(len));
    } finally {
      wasm.restore(save);
    }
  }

  signatureImport(sig) {
    assert(Buffer.isBuffer(sig));

    const save = wasm.save();
    const out = wasm.alloc(this.sigSize);

    try {
      wasm.throws('bcrypto_ecdsa_sig_import', this.ctx, out, sig, sig.length);
      return wasm.read(out, this.sigSize);
    } finally {
      wasm.restore(save);
    }
  }

  isLowS(sig) {
    assert(Buffer.isBuffer(sig));
    assert(sig.length === this.sigSize);

    return wasm.call('bcrypto_ecdsa_sig_low_s', this.ctx, sig) === 1;
  }

  isLowDER(sig) {
    assert(Buffer.isBuffer(sig));

    return wasm.call('bcrypto_ecdsa_sig_low_der',
                     this.ctx, sig, sig.length) === 1;
  }

  sign(msg, key) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(key));
    assert(key.length === this.scalarSize);

    const save = wasm.save();
    const out = wasm.alloc(this.sigSize);

    try {
      wasm.throws('bcrypto_ecdsa_sign', this.ctx, out, msg, msg.length, key);
      return wasm.read(out, this.sigSize);
    } finally {
      wasm.restore(save);
    }
  }

  signRecoverable(msg, key) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(key));
    assert(key.length === this.scalarSize);

    const save = wasm.save();
    const out = wasm.alloc(this.sigSize);
    const param = wasm.pushU32(0);

    try {
      wasm.throws('bcrypto_ecdsa_sign_recoverable',
                  this.ctx, out, param, msg, msg.length, key);
      return {
        signature: wasm.read(out, this.sigSize),
        recovery: wasm.getU32(param)
      };
    } finally {
      wasm.restore(save);
    }
  }

  signDER(msg, key) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(key));
    assert(key.length === this.scalarSize);

    const save = wasm.save();
    const out = wasm.alloc(this.derSize);
    const len = wasm.pushSize(0);

    try {
      wasm.throws('bcrypto_ecdsa_sign_der',
                  this.ctx, out, len, msg, msg.length, key);
      return wasm.read(out, wasm.getSize(len));
    } finally {
      wasm.restore(save);
    }
  }

  signRecoverableDER(msg, key) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(key));
    assert(key.length === this.scalarSize);

    const save = wasm.save();
    const out = wasm.alloc(this.derSize);
    const len = wasm.pushSize(0);
    const param = wasm.pushU32(0);

    try {
      wasm.throws('bcrypto_ecdsa_sign_recoverable_der',
                  this.ctx, out, len, param, msg, msg.length, key);
      return {
        signature: wasm.read(out, wasm.getSize(len)),
        recovery: wasm.getU32(param)
      };
    } finally {
      wasm.restore(save);
    }
  }

  verify(msg, sig, key) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(sig));
    assert(Buffer.isBuffer(key));

    if (sig.length !== this.sigSize)
      return false;

    return wasm.call('bcrypto_ecdsa_verify', this.ctx,
                     msg, msg.length, sig, key, key.length) === 1;
  }

  verifyDER(msg, sig, key) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(sig));
    assert(Buffer.isBuffer(key));

    return wasm.call('bcrypto_ecdsa_verify_der', this.ctx,
                     msg, msg.length, sig, sig.length, key, key.length) === 1;
  }

  recover(msg, sig, param = 0, compress = true) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(sig));
    assert(sig.length === this.sigSize);
    assert((param >>> 0) === param);
    assert(typeof compress === 'boolean');

    const save = wasm.save();
    const out = wasm.alloc(this.keySize);
    const len = wasm.pushSize(0);

    try {
      wasm.throws('bcrypto_ecdsa_recover',
                  this.ctx, out, len, msg, msg.length, sig, param, compress);
      return wasm.read(out, wasm.getSize(len));
    } finally {
      wasm.restore(save);
    }
  }

  recoverDER(msg, sig, param, compress = true) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(sig));
    assert((param >>> 0) === param);
    assert(typeof compress === 'boolean');

    const save = wasm.save();
    const out = wasm.alloc(this.keySize);
    const len = wasm.pushSize(0);

    try {
      wasm.throws('bcrypto_ecdsa_recover_der',
                  this.ctx, out, len, msg, msg.length,
                  sig, sig.length, param, compress);
      return wasm.read(out, wasm.getSize(len));
    } finally {
      wasm.restore(save);
    }
  }

  derive(pub, priv, compress = true) {
    assert(Buffer.isBuffer(pub));
    assert(Buffer.isBuffer(priv));
    assert(priv.length === this.scalarSize);
    assert(typeof compress === 'boolean');

    const save = wasm.save();
    const out = wasm.alloc(this.keySize);
    const len = wasm.pushSize(0);

    try {
      wasm.throws('bcrypto_ecdsa_derive',
                  this.ctx, out, len, pub,
                  pub.length, priv, compress);
      return wasm.read(out, wasm.getSize(len));
    } finally {
      wasm.restore(save);
    }
  }

  /*
   * Compat
   */

  generatePrivateKey() {
    return this.privateKeyGenerate();
  }

  fromDER(sig) {
    return this.signatureImport(sig);
  }

  toDER(sig) {
    return this.signatureExport(sig);
  }

  ecdh(pub, priv, compress) {
    return this.derive(pub, priv, compress);
  }
}

/*
 * Expose
 */

module.exports = ECDSA;
