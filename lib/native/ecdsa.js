/*!
 * ecdsa.js - ecdsa wrapper for openssl
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const backend = require('./binding');
const asn1 = require('../encoding/asn1');
const sec1 = require('../encoding/sec1');
const pkcs8 = require('../encoding/pkcs8');
const x509 = require('../encoding/x509');
const binding = backend.ecdsa;

if (!binding)
  throw new Error('ECDSA native support not available.');

const eckey = require('../internal/eckey');

/**
 * ECDSA
 */

class ECDSA {
  constructor(name) {
    this.id = name;
    this.ctx = backend.curves[name];
    this.type = 'short';
    this.size = binding._size(this.ctx);
    this.bits = binding._bits(this.ctx);
    this.native = 2;
  }

  privateKeyGenerate() {
    backend.reseed();
    return binding.privateKeyGenerate(this.ctx);
  }

  privateKeyVerify(key) {
    return binding.privateKeyVerify(this.ctx, key);
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
    return binding.privateKeyTweakAdd(this.ctx, key, tweak);
  }

  privateKeyTweakMul(key, tweak) {
    return binding.privateKeyTweakMul(this.ctx, key, tweak);
  }

  privateKeyReduce(key) {
    return binding.privateKeyReduce(this.ctx, key);
  }

  privateKeyNegate(key) {
    return binding.privateKeyNegate(this.ctx, key);
  }

  privateKeyInvert(key) {
    return binding.privateKeyInvert(this.ctx, key);
  }

  publicKeyCreate(key, compress) {
    return binding.publicKeyCreate(this.ctx, key, compress);
  }

  publicKeyConvert(key, compress) {
    return binding.publicKeyConvert(this.ctx, key, compress);
  }

  publicKeyVerify(key) {
    return binding.publicKeyVerify(this.ctx, key);
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

  publicKeyTweakAdd(key, tweak, compress) {
    return binding.publicKeyTweakAdd(this.ctx, key, tweak, compress);
  }

  publicKeyTweakMul(key, tweak, compress) {
    return binding.publicKeyTweakMul(this.ctx, key, tweak, compress);
  }

  publicKeyAdd(key1, key2, compress) {
    return binding.publicKeyAdd(this.ctx, key1, key2, compress);
  }

  publicKeyCombine(keys, compress) {
    return binding.publicKeyCombine(this.ctx, keys, compress);
  }

  publicKeyNegate(key, compress) {
    return binding.publicKeyNegate(this.ctx, key, compress);
  }

  signatureNormalize(raw) {
    return binding.signatureNormalize(this.ctx, raw);
  }

  signatureNormalizeDER(raw) {
    return binding.signatureNormalizeDER(this.ctx, raw);
  }

  signatureExport(sig) {
    return binding.signatureExport(this.ctx, sig);
  }

  signatureImport(sig) {
    return binding.signatureImport(this.ctx, sig);
  }

  isLowS(sig) {
    return binding.isLowS(this.ctx, sig);
  }

  isLowDER(sig) {
    return binding.isLowDER(this.ctx, sig);
  }

  sign(msg, key) {
    backend.reseed();
    return binding.sign(this.ctx, msg, key);
  }

  signRecoverable(msg, key) {
    backend.reseed();
    return binding.signRecoverable(this.ctx, msg, key);
  }

  signDER(msg, key) {
    backend.reseed();
    return binding.signDER(this.ctx, msg, key);
  }

  signRecoverableDER(msg, key) {
    backend.reseed();
    return binding.signRecoverableDER(this.ctx, msg, key);
  }

  verify(msg, sig, key) {
    return binding.verify(this.ctx, msg, sig, key);
  }

  verifyDER(msg, sig, key) {
    return binding.verifyDER(this.ctx, msg, sig, key);
  }

  recover(msg, sig, param, compress) {
    return binding.recover(this.ctx, msg, sig, param, compress);
  }

  recoverDER(msg, sig, param, compress) {
    return binding.recoverDER(this.ctx, msg, sig, param, compress);
  }

  derive(pub, priv, compress) {
    return binding.derive(this.ctx, pub, priv, compress);
  }

  /*
   * Schnorr
   */

  schnorrSign(msg, key) {
    return binding.schnorrSign(this.ctx, msg, key);
  }

  schnorrVerify(msg, sig, key) {
    return binding.schnorrVerify(this.ctx, msg, sig, key);
  }

  schnorrVerifyBatch(batch) {
    backend.reseed();
    return binding.schnorrVerifyBatch(this.ctx, batch);
  }
}

/*
 * Expose
 */

module.exports = ECDSA;
