/*!
 * ecdh.js - ECDH for bcrypto
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Resources:
 *   https://tools.ietf.org/html/rfc7748
 */

'use strict';

const assert = require('bsert');
const elliptic = require('./elliptic');
const eckey = require('../internal/eckey');
const asn1 = require('../encoding/asn1');
const pkcs8 = require('../encoding/pkcs8');
const x509 = require('../encoding/x509');
const rng = require('../random');

/**
 * ECDH
 */

class ECDH {
  constructor(id, eid, pre) {
    assert(typeof id === 'string');
    assert(!eid || typeof eid === 'string');

    this.id = id;
    this.type = 'mont';
    this.eid = eid || null;
    this._pre = pre || null;
    this._curve = null;
    this._edwards = null;
    this.native = 0;
  }

  get curve() {
    if (!this._curve) {
      this._curve = elliptic.curve(this.id);
      this._curve.precompute(rng);
      this._pre = null;
    }
    return this._curve;
  }

  get edwards() {
    if (!this.eid)
      throw new Error('No equivalent edwards curve.');

    if (!this._edwards) {
      this._edwards = elliptic.curve(this.eid, this._pre);
      this._edwards.precompute(rng);
      this._pre = null;
    }

    return this._edwards;
  }

  get size() {
    return this.curve.fieldSize;
  }

  get bits() {
    return this.curve.fieldBits;
  }

  privateKeyGenerate() {
    const key = rng.randomBytes(this.curve.scalarSize);
    return this.curve.clamp(key);
  }

  privateKeyGenerateCovert() {
    for (;;) {
      const key = this.privateKeyGenerate();
      const pub = this.publicKeyCreate(key);

      let bytes;
      try {
        bytes = this.publicKeyToUniform(pub);
      } catch (e) {
        if (e.message === 'X is not a square mod P.')
          continue;
        throw e;
      }

      return [key, bytes];
    }
  }

  privateKeyVerify(key) {
    assert(Buffer.isBuffer(key));
    return key.length === this.curve.scalarSize;
  }

  privateKeyExport(key) {
    if (!this.privateKeyVerify(key))
      throw new Error('Invalid private key.');

    return new asn1.OctString(key).encode();
  }

  privateKeyImport(raw) {
    const key = asn1.OctString.decode(raw);

    if (!this.privateKeyVerify(key.value))
      throw new Error('Invalid private key.');

    return key.value;
  }

  privateKeyExportPKCS8(key) {
    return new pkcs8.PrivateKeyInfo(
      0,
      asn1.objects.curves[this.id],
      new asn1.Null(),
      this.privateKeyExport(key)
    ).encode();
  }

  privateKeyImportPKCS8(raw) {
    const pki = pkcs8.PrivateKeyInfo.decode(raw);
    const version = pki.version.toNumber();
    const {algorithm, parameters} = pki.algorithm;

    assert(version === 0 || version === 1);
    assert(algorithm.toString() === asn1.objects.curves[this.id]);
    assert(parameters.node.type === asn1.types.NULL);

    return this.privateKeyImport(pki.privateKey.value);
  }

  privateKeyExportJWK(key) {
    return eckey.privateKeyExportJWK(this, key);
  }

  privateKeyImportJWK(json) {
    return eckey.privateKeyImportJWK(this, json);
  }

  publicKeyCreate(key) {
    const s = this.curve.decodeScalar(key);
    const k = this.curve.reduce(s);

    if (this.eid) {
      const A = this.edwards.g.mul(k);
      const p = this.curve.pointFromEdwards(A);

      return p.encode();
    }

    const p = this.curve.g.mul(k);

    return p.encode();
  }

  publicKeyConvert(pub, sign = false) {
    const p = this.curve.decodePoint(pub);

    if (!p.validate())
      throw new Error('Invalid point.');

    const A = this.edwards.pointFromMont(p, sign);

    return A.encode();
  }

  publicKeyFromUniform(bytes) {
    const u = this.curve.decodeUniform(bytes);
    const [p] = this.curve.pointFromUniform(u);

    return p.encode();
  }

  publicKeyToUniform(pub, sign) {
    if (sign == null)
      sign = (rng.randomInt() & 1) !== 0;

    const p = this.curve.decodePoint(pub);
    const u = this.curve.pointToUniform(p, sign);

    return this.curve.encodeUniform(u, rng);
  }

  publicKeyFromHash(bytes) {
    const p = this.curve.pointFromHash(this.edwards, bytes);

    return p.encode();
  }

  publicKeyVerify(key) {
    assert(Buffer.isBuffer(key));

    let p;
    try {
      p = this.curve.decodePoint(key);
    } catch (e) {
      return false;
    }

    return p.validate();
  }

  publicKeyIsSmall(key) {
    assert(Buffer.isBuffer(key));

    let p;
    try {
      p = this.curve.decodePoint(key);
    } catch (e) {
      return false;
    }

    if (!p.validate())
      return false;

    return p.isSmall();
  }

  publicKeyHasTorsion(key) {
    assert(Buffer.isBuffer(key));

    let p;
    try {
      p = this.curve.decodePoint(key);
    } catch (e) {
      return false;
    }

    if (!p.validate())
      return false;

    return p.hasTorsion();
  }

  publicKeyExport(key) {
    if (!this.publicKeyVerify(key))
      throw new Error('Invalid public key.');

    return Buffer.from(key);
  }

  publicKeyImport(raw) {
    if (!this.publicKeyVerify(raw))
      throw new Error('Invalid public key.');

    return Buffer.from(raw);
  }

  publicKeyExportSPKI(key) {
    return new x509.SubjectPublicKeyInfo(
      asn1.objects.curves[this.id],
      new asn1.Null(),
      this.publicKeyExport(key)
    ).encode();
  }

  publicKeyImportSPKI(raw) {
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

  derive(pub, priv) {
    const s = this.curve.decodeScalar(priv);
    const A = this.curve.decodePoint(pub);
    const k = this.curve.reduce(s);
    const p = A.mulConst(k, rng);

    return p.encode();
  }
}

/*
 * Expose
 */

module.exports = ECDH;
