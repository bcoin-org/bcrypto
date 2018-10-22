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
 * ECDSA
 */

class ECDSA {
  constructor(name) {
    assert(typeof name === 'string');

    this.id = name;
    this.edwards = false;
    this._ec = null;
    this._size = -1;
    this._bits = -1;
    this._zero = null;
    this._order = null;
    this._half = null;
    this.native = 0;
  }

  get ec() {
    if (!this._ec)
      this._ec = elliptic.ec(this.id.toLowerCase());
    return this._ec;
  }

  get curve() {
    return this.ec.curve;
  }

  get size() {
    if (this._size === -1)
      this._size = this.curve.n.byteLength();
    return this._size;
  }

  get bits() {
    if (this._bits === -1)
      this._bits = this.curve.n.bitLength();
    return this._bits;
  }

  get zero() {
    if (!this._zero)
      this._zero = Buffer.alloc(this.size, 0x00);
    return this._zero;
  }

  get order() {
    if (!this._order)
      this._order = toBuffer(this.curve.n, this.size);
    return this._order;
  }

  get half() {
    if (!this._half)
      this._half = toBuffer(this.ec.nh, this.size);
    return this._half;
  }

  privateKeyGenerate() {
    const key = this.ec.genKeyPair();
    return toBuffer(key.getPrivate(), this.size);
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

    if (t.cmp(this.curve.n) >= 0)
      throw new Error('Invalid scalar.');

    const k = new BN(key);

    k.iadd(t);

    if (k.cmp(this.curve.n) >= 0)
      k.isub(this.curve.n);

    // Only a 1 in 2^127 chance of happening.
    if (k.isZero())
      throw new Error('Invalid private key.');

    return toBuffer(k, this.size);
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

    return encodePoint(point, compress);
  }

  publicKeyConvert(key, compress) {
    if (compress == null)
      compress = true;

    assert(Buffer.isBuffer(key));
    assert(typeof compress === 'boolean');
    assert(isValidPoint(key, this.size));

    const point = this.curve.decodePoint(key);

    return encodePoint(point, compress);
  }

  publicKeyVerify(key) {
    assert(Buffer.isBuffer(key));

    if (!isValidPoint(key, this.size))
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
    assert(isValidPoint(key, this.size));
    assert(tweak.length === this.size);

    const t = new BN(tweak);

    if (t.cmp(this.curve.n) >= 0)
      throw new Error('Invalid scalar.');

    const k = this.curve.decodePoint(key);
    const point = this.curve.g.mul(t).add(k);

    // Only a 1 in 2^127 chance of happening.
    if (point.isInfinity())
      throw new Error('Invalid public key.');

    return encodePoint(point, compress);
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

    const r = toBuffer(es.r, this.size);
    const s = toBuffer(es.s, this.size);

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

  signDER(msg, key) {
    const sig = this._sign(msg, key);
    return sig.toDER(this.size);
  }

  verify(msg, sig, key) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(sig));
    assert(Buffer.isBuffer(key));

    if (msg.length < 20 || msg.length > 128)
      return false;

    if (sig.length !== this.size * 2)
      return false;

    if (!isValidPoint(key, this.size))
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

    if (!isValidPoint(key, this.size))
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

    return encodePoint(point, compress);
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

    return encodePoint(point, compress);
  }

  derive(pub, priv, compress) {
    if (compress == null)
      compress = true;

    assert(Buffer.isBuffer(pub));
    assert(Buffer.isBuffer(priv));
    assert(typeof compress === 'boolean');
    assert(isValidPoint(pub, this.size));
    assert(priv.length === this.size);

    if (!this.privateKeyVerify(priv))
      throw new Error('Invalid private key.');

    const pk = this.ec.keyFromPublic(pub);
    const sk = this.ec.keyFromPrivate(priv);
    const point = pk.getPublic().mul(sk.priv);

    if (point.isInfinity())
      throw new Error('Invalid private key.');

    return encodePoint(point, compress);
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
 * Helpers
 */

function toBuffer(n, size) {
  return n.toArrayLike(Buffer, 'be', size);
}

function encodePoint(point, compress) {
  const arr = point.encode('array', compress);
  return Buffer.from(arr);
}

function isValidPoint(point, size) {
  assert(Buffer.isBuffer(point));
  assert((size >>> 0) === size);

  if (point.length < 1 + size)
    return false;

  switch (point[0]) {
    case 0x02:
    case 0x03:
      return point.length === 1 + size;
    case 0x04:
      return point.length === 1 + size * 2;
    case 0x06:
    case 0x07:
      return point.length === 1 + size * 2
          && (point[0] & 1) === (point[point.length - 1] & 1);
    default:
      return false;
  }
}

/*
 * Expose
 */

module.exports = ECDSA;
