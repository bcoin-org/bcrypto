/*!
 * ecdsa.js - wrapper for elliptic
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const elliptic = require('../../vendor/elliptic');
const BN = require('../../vendor/bn.js');
const eckey = require('../internal/eckey');
const Signature = require('../internal/signature');
const asn1 = require('../encoding/asn1');
const sec1 = require('../encoding/sec1');
const pkcs8 = require('../encoding/pkcs8');
const x509 = require('../encoding/x509');

/**
 * API
 */

class API {
  constructor(name) {
    assert(typeof name === 'string');

    this.id = name;
    this.edwards = false;
    this.native = 0;
  }

  get ec() {
    if (!this._ec)
      this._ec = new ECDSA(this.id);
    return this._ec;
  }

  get size() {
    return this.ec.size;
  }

  get bits() {
    return this.ec.bits;
  }

  get zero() {
    return this.ec.zero;
  }

  get order() {
    return this.ec.order;
  }

  get half() {
    return this.ec.half;
  }

  privateKeyGenerate() {
    return this.ec.privateKeyGenerate();
  }

  privateKeyVerify(key) {
    return this.ec.privateKeyVerify(key);
  }

  privateKeyExport(key, compress) {
    return this.ec.privateKeyExport(key, compress);
  }

  privateKeyImport(raw) {
    return this.ec.privateKeyImport(raw);
  }

  privateKeyExportPKCS8(key, compress) {
    return this.ec.privateKeyExportPKCS8(key, compress);
  }

  privateKeyImportPKCS8(raw) {
    return this.ec.privateKeyImportPKCS8(raw);
  }

  privateKeyExportJWK(key) {
    return this.ec.privateKeyExportJWK(key);
  }

  privateKeyImportJWK(json) {
    return this.ec.privateKeyImportJWK(json);
  }

  privateKeyTweakAdd(key, tweak) {
    return this.ec.privateKeyTweakAdd(key, tweak);
  }

  privateKeyTweakMul(key, tweak) {
    return this.ec.privateKeyTweakMul(key, tweak);
  }

  publicKeyCreate(key, compress) {
    return this.ec.publicKeyCreate(key, compress);
  }

  publicKeyConvert(key, compress) {
    return this.ec.publicKeyConvert(key, compress);
  }

  publicKeyVerify(key) {
    return this.ec.publicKeyVerify(key);
  }

  publicKeyExport(key) {
    return this.ec.publicKeyExport(key);
  }

  publicKeyImport(raw, compress) {
    return this.ec.publicKeyImport(raw, compress);
  }

  publicKeyExportSPKI(key, compress) {
    return this.ec.publicKeyExportSPKI(key, compress);
  }

  publicKeyImportSPKI(raw, compress) {
    return this.ec.publicKeyImportSPKI(raw, compress);
  }

  publicKeyExportJWK(key) {
    return this.ec.publicKeyExportJWK(key);
  }

  publicKeyImportJWK(json, compress) {
    return this.ec.publicKeyImportJWK(json, compress);
  }

  publicKeyTweakAdd(key, tweak, compress) {
    return this.ec.publicKeyTweakAdd(key, tweak, compress);
  }

  publicKeyTweakMul(key, tweak, compress) {
    return this.ec.publicKeyTweakMul(key, tweak, compress);
  }

  signatureExport(sig) {
    return this.ec.signatureExport(sig);
  }

  signatureImport(sig) {
    return this.ec.signatureImport(sig);
  }

  sign(msg, key) {
    return this.ec.sign(msg, key);
  }

  signRecoverable(msg, key) {
    return this.ec.signRecoverable(msg, key);
  }

  signDER(msg, key) {
    return this.ec.signDER(msg, key);
  }

  signRecoverableDER(msg, key) {
    return this.ec.signRecoverableDER(msg, key);
  }

  verify(msg, sig, key) {
    return this.ec.verify(msg, sig, key);
  }

  verifyDER(msg, sig, key) {
    return this.ec.verifyDER(msg, sig, key);
  }

  recover(msg, sig, param, compress) {
    return this.ec.recover(msg, sig, param, compress);
  }

  recoverDER(msg, sig, param, compress) {
    return this.ec.recoverDER(msg, sig, param, compress);
  }

  derive(pub, priv, compress) {
    return this.ec.derive(pub, priv, compress);
  }

  isLowS(sig) {
    return this.ec.isLowS(sig);
  }

  isLowDER(sig) {
    return this.ec.isLowDER(sig);
  }

  /*
   * Compat
   */

  generatePrivateKey() {
    return this.ec.generatePrivateKey();
  }

  fromDER(sig) {
    return this.ec.fromDER(sig);
  }

  toDER(sig) {
    return this.ec.toDER(sig);
  }

  ecdh(pub, priv, compress) {
    return this.ec.ecdh(pub, priv, compress);
  }
}

/**
 * ECDSA
 */

class ECDSA {
  constructor(name) {
    assert(typeof name === 'string');

    this.id = name;
    this.edwards = false;
    this.ec = elliptic.ec(this.id.toLowerCase());
    this.curve = this.ec.curve;
    this.n = this.ec.n;
    this.nh = this.ec.nh;
    this.p = this.curve.p;
    this.g = this.ec.g;
    this.hash = this.ec.hash.bcrypto;
    this.size = this.curve.n.byteLength();
    this.bits = this.curve.n.bitLength();
    this.zero = this.encodeInt(new BN(0));
    this.order = this.encodeInt(this.n);
    this.half = this.encodeInt(this.nh);
    this.native = 0;
  }

  hashInt(...items) {
    // eslint-disable-next-line
    const h = new this.hash();

    h.init();

    for (const item of items)
      h.update(item);

    const hash = h.final();
    const num = this.decodeInt(hash);

    return num.umod(this.n);
  }

  encodeInt(num) {
    assert(num instanceof BN);
    return num.toArrayLike(Buffer, 'be', this.size);
  }

  decodeInt(raw) {
    assert(Buffer.isBuffer(raw));
    assert(raw.length === this.size);
    return new BN(raw, 'be');
  }

  encodePoint(point, compress = true) {
    return Buffer.from(point.encode('array', compress));
  }

  decodePoint(raw) {
    if (!this.isValidPoint(raw))
      throw new Error('Invalid point.');

    return this.curve.decodePoint(raw);
  }

  isValidPoint(point) {
    assert(Buffer.isBuffer(point));

    if (point.length < 1 + this.size)
      return false;

    switch (point[0]) {
      case 0x02:
      case 0x03:
        return point.length === 1 + this.size;
      case 0x04:
        return point.length === 1 + this.size * 2;
      case 0x06:
      case 0x07:
        return point.length === 1 + this.size * 2
            && (point[0] & 1) === (point[point.length - 1] & 1);
      default:
        return false;
    }
  }

  privateKeyGenerate() {
    const key = this.ec.genKeyPair();
    return this.encodeInt(key.getPrivate());
  }

  privateKeyVerify(key) {
    assert(Buffer.isBuffer(key));

    if (key.length !== this.size)
      return false;

    if (key.equals(this.zero))
      return false;

    return key.compare(this.order) < 0;
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
    assert(key.privateKey.value.length === this.size);

    return key.privateKey.value;
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
    assert(key.length === this.size);
    assert(tweak.length === this.size);

    const t = new BN(tweak);

    if (t.cmp(this.n) >= 0)
      throw new Error('Invalid scalar.');

    const k = new BN(key);

    k.iadd(t);

    if (k.cmp(this.n) >= 0)
      k.isub(this.n);

    // Only a 1 in 2^127 chance of happening.
    if (k.isZero())
      throw new Error('Invalid private key.');

    return this.encodeInt(k);
  }

  privateKeyTweakMul(key, tweak) {
    assert(Buffer.isBuffer(key));
    assert(Buffer.isBuffer(tweak));
    assert(key.length === this.size);
    assert(tweak.length === this.size);

    const t = new BN(tweak);

    if (t.cmp(this.n) >= 0 || t.isZero())
      throw new Error('Invalid scalar.');

    let k = new BN(key);

    k.imul(t);

    if (k.cmp(this.n) >= 0)
      k = k.umod(this.n);

    return this.encodeInt(k);
  }

  publicKeyCreate(key, compress) {
    if (compress == null)
      compress = true;

    assert(Buffer.isBuffer(key));
    assert(typeof compress === 'boolean');
    assert(key.length === this.size);

    if (!this.privateKeyVerify(key))
      throw new Error('Invalid private key.');

    const pub = this.ec.keyFromPrivate(key);
    const point = pub.getPublic();

    return this.encodePoint(point, compress);
  }

  publicKeyConvert(key, compress) {
    if (compress == null)
      compress = true;

    assert(Buffer.isBuffer(key));
    assert(typeof compress === 'boolean');
    assert(this.isValidPoint(key));

    const point = this.decodePoint(key);

    return this.encodePoint(point, compress);
  }

  publicKeyVerify(key) {
    assert(Buffer.isBuffer(key));

    if (!this.isValidPoint(key))
      return false;

    let k;
    try {
      k = this.ec.keyFromPublic(key);
    } catch (e) {
      return false;
    }

    return k.validate().result;
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
    if (compress == null)
      compress = true;

    assert(Buffer.isBuffer(key));
    assert(Buffer.isBuffer(tweak));
    assert(typeof compress === 'boolean');
    assert(this.isValidPoint(key));
    assert(tweak.length === this.size);

    const t = new BN(tweak);

    if (t.cmp(this.n) >= 0)
      throw new Error('Invalid scalar.');

    const k = this.decodePoint(key);
    const point = this.g.mul(t).add(k);

    // Only a 1 in 2^127 chance of happening.
    if (point.isInfinity())
      throw new Error('Invalid public key.');

    return this.encodePoint(point, compress);
  }

  publicKeyTweakMul(key, tweak, compress) {
    return this.derive(key, tweak, compress);
  }

  signatureExport(sig) {
    return Signature.toDER(sig, this.size);
  }

  signatureImport(sig) {
    return Signature.toRS(sig, this.size);
  }

  _sign(msg, key) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(key));
    assert(msg.length >= 20 && msg.length <= 128);
    assert(key.length === this.size);

    if (!this.privateKeyVerify(key))
      throw new Error('Invalid private key.');

    // Sign message and ensure low S value.
    const es = this.ec.sign(msg, key, { canonical: true });

    const r = this.encodeInt(es.r);
    const s = this.encodeInt(es.s);

    const sig = new Signature();
    sig.r = r;
    sig.s = s;
    sig.param = es.recoveryParam | 0;

    return sig;
  }

  sign(msg, key) {
    const sig = this._sign(msg, key);
    return sig.encode(this.size);
  }

  signRecoverable(msg, key) {
    const sig = this._sign(msg, key);
    return {
      signature: sig.encode(this.size),
      recovery: sig.param
    };
  }

  signDER(msg, key) {
    const sig = this._sign(msg, key);
    return sig.toDER(this.size);
  }

  signRecoverableDER(msg, key) {
    const sig = this._sign(msg, key);
    return {
      signature: sig.toDER(this.size),
      recovery: sig.param
    };
  }

  verify(msg, sig, key) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(sig));
    assert(Buffer.isBuffer(key));

    if (msg.length < 20 || msg.length > 128)
      return false;

    if (sig.length !== this.size * 2)
      return false;

    if (!this.isValidPoint(key))
      return false;

    const s = Signature.decode(sig, this.size);

    try {
      return this.ec.verify(msg, s, key);
    } catch (e) {
      return false;
    }
  }

  verifyDER(msg, sig, key) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(sig));
    assert(Buffer.isBuffer(key));

    if (msg.length < 20 || msg.length > 128)
      return false;

    if (!this.isValidPoint(key))
      return false;

    let s;
    try {
      s = Signature.fromDER(sig, this.size);
    } catch (e) {
      return false;
    }

    try {
      return this.ec.verify(msg, s, key);
    } catch (e) {
      return false;
    }
  }

  recover(msg, sig, param, compress) {
    if (param == null)
      param = 0;

    if (compress == null)
      compress = true;

    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(sig));
    assert((param >>> 0) === param);
    assert(typeof compress === 'boolean');

    if (msg.length < 20 || msg.length > 128)
      return null;

    if (sig.length !== this.size * 2)
      return null;

    const s = Signature.decode(sig, this.size);

    if (!this.privateKeyVerify(s.r))
      return null;

    if (!this.privateKeyVerify(s.s))
      return null;

    let point;
    try {
      point = this.ec.recoverPubKey(msg, s, param);
    } catch (e) {
      return null;
    }

    return this.encodePoint(point, compress);
  }

  recoverDER(msg, sig, param, compress) {
    if (param == null)
      param = 0;

    if (compress == null)
      compress = true;

    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(sig));
    assert((param >>> 0) === param);
    assert(typeof compress === 'boolean');

    if (msg.length < 20 || msg.length > 128)
      return null;

    let s;
    try {
      s = Signature.fromDER(sig, this.size);
    } catch (e) {
      return null;
    }

    if (!this.privateKeyVerify(s.r))
      return null;

    if (!this.privateKeyVerify(s.s))
      return null;

    let point;
    try {
      point = this.ec.recoverPubKey(msg, s, param);
    } catch (e) {
      return null;
    }

    return this.encodePoint(point, compress);
  }

  derive(pub, priv, compress) {
    if (compress == null)
      compress = true;

    assert(Buffer.isBuffer(pub));
    assert(Buffer.isBuffer(priv));
    assert(typeof compress === 'boolean');
    assert(this.isValidPoint(pub));
    assert(priv.length === this.size);

    if (!this.privateKeyVerify(priv))
      throw new Error('Invalid private key.');

    const pk = this.ec.keyFromPublic(pub);
    const sk = this.ec.keyFromPrivate(priv);
    const point = pk.getPublic().mul(sk.priv);

    if (point.isInfinity())
      throw new Error('Invalid public key.');

    return this.encodePoint(point, compress);
  }

  isLowS(sig) {
    return Signature.isLowS(sig, this.size, this.half);
  }

  isLowDER(sig) {
    return Signature.isLowDER(sig, this.size, this.half);
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

module.exports = API;
