/*!
 * ecdsa.js - ecdsa wrapper for openssl
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const Native = require('./binding').ECDSA;
const asn1 = require('../encoding/asn1');
const sec1 = require('../encoding/sec1');
const pkcs8 = require('../encoding/pkcs8');
const x509 = require('../encoding/x509');
const eckey = require('../internal/eckey');
const random = require('./random');

/**
 * ECDSA
 */

class ECDSA extends Native {
  constructor(name) {
    super(name);

    this.id = name;
    this.type = 'ecdsa';
    this.size = this._size();
    this.bits = this._bits();
    this.native = 2;
  }

  privateKeyExport(key, compress) {
    // [RFC5915] Page 2, Section 3.
    const pub = this.publicKeyCreate(key, compress);
    return new sec1.ECPrivateKey(1, key, this.id, pub).encode();
  }

  privateKeyImport(raw) {
    // [RFC5915] Page 2, Section 3.
    const key = sec1.ECPrivateKey.decode(raw);
    const curve = key.namedCurveOID.toString();

    assert(key.version.toNumber() === 1);
    assert(curve === asn1.objects.curves[this.id]
        || curve === asn1.objects.NONE);

    const {value} = key.privateKey;

    if (value.length > this.size)
      throw new Error('Invalid private key.');

    return this.privateKeyReduce(value); // XXX
  }

  privateKeyExportPKCS8(key, compress) {
    // [RFC5915] Page 2, Section 3.
    const pub = this.publicKeyCreate(key, compress);
    const curve = asn1.objects.NONE;

    return new pkcs8.PrivateKeyInfo(
      0,
      asn1.objects.keyAlgs.ECDSA,
      new asn1.OID(asn1.objects.curves[this.id]),
      new sec1.ECPrivateKey(1, key, curve, pub).encode()
    ).encode();
  }

  privateKeyImportPKCS8(raw) {
    // [RFC5915] Page 2, Section 3.
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
    // [RFC5480] Page 7, Section 2.2.
    return new x509.SubjectPublicKeyInfo(
      asn1.objects.keyAlgs.ECDSA,
      new asn1.OID(asn1.objects.curves[this.id]),
      this.publicKeyConvert(key, compress)
    ).encode();
  }

  publicKeyImportSPKI(raw, compress) {
    // [RFC5480] Page 7, Section 2.2.
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

  publicKeyToUniform(key, hint = random.randomInt()) {
    return super.publicKeyToUniform(key, hint);
  }
}

/*
 * Expose
 */

module.exports = ECDSA;
