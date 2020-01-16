/*!
 * eddsa.js - EdDSA for bcrypto
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const binding = require('./binding');
const eckey = require('../internal/eckey');
const asn1 = require('../encoding/asn1');
const pkcs8 = require('../encoding/pkcs8');
const x509 = require('../encoding/x509');
const rng = require('../random');

/*
 * EDDSA
 */

class EDDSA extends binding.EDDSA {
  constructor(name) {
    super(name);

    this.id = name;
    this.type = 'eddsa';
    this.size = this._size();
    this.bits = this._bits();
    this.native = 2;
  }

  privateKeyGenerate() {
    return super.privateKeyGenerate(binding.entropy());
  }

  scalarGenerate() {
    return super.scalarGenerate(binding.entropy());
  }

  privateKeyExport(secret) {
    // [RFC8410] Page 7, Section 7.
    if (!this.privateKeyVerify(secret))
      throw new Error('Invalid private key.');

    return new asn1.OctString(secret).encode();
  }

  privateKeyImport(raw) {
    // [RFC8410] Page 7, Section 7.
    const str = asn1.OctString.decode(raw);

    if (!this.privateKeyVerify(str.value))
      throw new Error('Invalid private key.');

    return str.value;
  }

  privateKeyExportPKCS8(secret) {
    // [RFC8410] Page 7, Section 7.
    return new pkcs8.PrivateKeyInfo(
      0,
      asn1.objects.curves[this.id],
      new asn1.Null(),
      this.privateKeyExport(secret)
    ).encode();
  }

  privateKeyImportPKCS8(raw) {
    // [RFC8410] Page 7, Section 7.
    const pki = pkcs8.PrivateKeyInfo.decode(raw);
    const version = pki.version.toNumber();
    const {algorithm, parameters} = pki.algorithm;

    assert(version === 0 || version === 1);
    assert(algorithm.toString() === asn1.objects.curves[this.id]);
    assert(parameters.node.type === asn1.types.NULL);

    return this.privateKeyImport(pki.privateKey.value);
  }

  privateKeyExportJWK(secret) {
    return eckey.privateKeyExportJWK(this, secret);
  }

  privateKeyImportJWK(json) {
    return eckey.privateKeyImportJWK(this, json);
  }

  publicKeyToUniform(key, hint = rng.randomInt()) {
    return super.publicKeyToUniform(key, hint);
  }

  publicKeyExport(key) {
    // [RFC8410] Page 4, Section 4.
    if (!this.publicKeyVerify(key))
      throw new Error('Invalid public key.');

    return Buffer.from(key);
  }

  publicKeyImport(raw) {
    // [RFC8410] Page 4, Section 4.
    if (!this.publicKeyVerify(raw))
      throw new Error('Invalid public key.');

    return Buffer.from(raw);
  }

  publicKeyExportSPKI(key) {
    // [RFC8410] Page 4, Section 4.
    return new x509.SubjectPublicKeyInfo(
      asn1.objects.curves[this.id],
      new asn1.Null(),
      this.publicKeyExport(key)
    ).encode();
  }

  publicKeyImportSPKI(raw) {
    // [RFC8410] Page 4, Section 4.
    const spki = x509.SubjectPublicKeyInfo.decode(raw);
    const {algorithm, parameters} = spki.algorithm;

    assert(algorithm.toString() === asn1.objects.curves[this.id]);
    assert(parameters.node.type === asn1.types.NULL);

    return this.publicKeyImport(spki.publicKey.rightAlign());
  }

  publicKeyExportJWK(key) {
    return eckey.publicKeyExportJWK(this, key);
  }

  publicKeyImportJWK(json) {
    return eckey.publicKeyImportJWK(this, json, false);
  }

  publicKeyToHash(key) {
    return super.publicKeyToHash(key, binding.entropy());
  }
}

/*
 * Expose
 */

module.exports = EDDSA;
