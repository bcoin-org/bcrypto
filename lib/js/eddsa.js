/*!
 * eddsa.js - wrapper for elliptic
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const elliptic = require('../../vendor/elliptic');
const random = require('../random');
const asn1 = require('../encoding/asn1');
const pkcs8 = require('../encoding/pkcs8');
const x509 = require('../encoding/x509');

/**
 * EDDSA
 */

class EDDSA {
  constructor(name, xname) {
    assert(typeof name === 'string');
    assert(typeof xname === 'string');

    this.id = name;
    this.xid = xname;
    this.edwards = true;
    this._ec = null;
    this._ka = null;
    this._bits = -1;
    this._zero = null;
    this._order = null;
    this.native = 0;
  }

  get ec() {
    if (!this._ec)
      this._ec = elliptic.eddsa(this.id.toLowerCase());
    return this._ec;
  }

  get ka() {
    if (!this._ka)
      this._ka = elliptic.ec(this.xid.toLowerCase());
    return this._ka;
  }

  get curve() {
    return this.ec.curve;
  }

  get size() {
    return this.ec.encodingLength;
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

  privateKeyGenerate() {
    return random.randomBytes(this.size);
  }

  privateKeyConvert(secret) {
    assert(Buffer.isBuffer(secret));
    assert(secret.length === this.size);

    const k = this.ec.keyFromSecret(secret);

    return Buffer.from(k.privBytes());
  }

  privateKeyVerify(secret) {
    assert(Buffer.isBuffer(secret));
    return secret.length === this.size;
  }

  privateKeyExport(secret) {
    assert(Buffer.isBuffer(secret));
    assert(secret.length === this.size);
    return new asn1.OctString(secret).encode();
  }

  privateKeyImport(raw) {
    const key = asn1.OctString.decode(raw);

    assert(key.value.length === this.size);

    return key.value;
  }

  privateKeyExportPKCS8(secret) {
    // https://tools.ietf.org/html/draft-ietf-curdle-pkix-eddsa-00
    // https://tools.ietf.org/html/rfc8410
    // https://tools.ietf.org/html/rfc5958
    // https://tools.ietf.org/html/rfc7468
    return new pkcs8.PrivateKeyInfo(
      0,
      asn1.objects.curves[this.id],
      new asn1.Null(),
      this.privateKeyExport(secret)
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

  publicKeyCreate(secret) {
    assert(Buffer.isBuffer(secret));
    assert(secret.length === this.size);

    const k = this.ec.keyFromSecret(secret);

    return Buffer.from(k.pubBytes());
  }

  publicKeyConvert(key) {
    assert(Buffer.isBuffer(key));
    assert(key.length === this.size);

    const point = this.ec.decodePoint(toArray(key));

    // x = ((y + z) * inverse(z - y)) % p
    const curve = this.ec.curve;
    const y = point.y;
    const z = point.z;

    // curve25519_add(yplusz, p.y, p.z);
    const yplusz = y.redAdd(z);

    // curve25519_sub(zminusy, p.z, p.y);
    const zminusy = z.redSub(y);

    // curve25519_recip(zminusy, zminusy);
    const zinv = zminusy.redInvm();

    // curve25519_mul(yplusz, yplusz, zminusy);
    const zmul = yplusz.redMul(zinv);

    // curve25519_contract(pk, yplusz);
    const x = zmul.fromRed();

    return toBuffer(x, curve.p.byteLength(), 'le');
  }

  publicKeyVerify(key) {
    assert(Buffer.isBuffer(key));

    if (key.length !== this.size)
      return false;

    const k = toArray(key);

    try {
      const pub = this.ec.keyFromPublic(k);
      return pub.pub().validate();
    } catch (e) {
      return false;
    }
  }

  publicKeyExport(key) {
    assert(Buffer.isBuffer(key));
    assert(key.length === this.size);
    return key;
  }

  publicKeyImport(raw) {
    assert(Buffer.isBuffer(raw));
    assert(raw.length === this.size);

    if (!this.publicKeyVerify(raw))
      throw new Error('Invalid public key.');

    return raw;
  }

  publicKeyExportSPKI(key) {
    // https://tools.ietf.org/html/rfc8410
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

    return this.publicKeyImport(spki.subjectPublicKey.rightAlign());
  }

  sign(msg, secret) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(secret));
    assert(secret.length === this.size);

    const sig = this.ec.sign(msg, secret);

    return Buffer.from(sig.toBytes());
  }

  verify(msg, sig, key) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(sig));
    assert(Buffer.isBuffer(key));

    if (sig.length !== this.size * 2)
      return false;

    if (key.length !== this.size)
      return false;

    const s = toArray(sig);
    const k = toArray(key);

    try {
      return this.ec.verify(msg, s, k);
    } catch (e) {
      return false;
    }
  }

  derive(edpub, secret) {
    const xpub = this.publicKeyConvert(edpub);
    return this.exchange(xpub, secret);
  }

  exchange(xpub, secret) {
    assert(Buffer.isBuffer(xpub) && xpub.length === this.size);

    const pub = Buffer.from(xpub);
    const priv = this.privateKeyConvert(secret);
    const pk = this.ka.keyFromPublic(reverse(pub));
    const sk = this.ka.keyFromPrivate(reverse(priv));
    const point = pk.getPublic().mul(sk.priv);

    if (point.isInfinity())
      throw new Error('Invalid public key.');

    return reverse(encodePoint(point));
  }

  /*
   * Compat
   */

  ecdh(edpub, secret) {
    return this.derive(edpub, secret);
  }
}

/*
 * Helpers
 */

function toArray(buf) {
  if (Array.from)
    return Array.from(buf);
  return Array.prototype.slice.call(buf);
}

function toBuffer(n, size, endian = 'be') {
  return n.toArrayLike(Buffer, endian, size);
}

function encodePoint(point) {
  const arr = point.encode('array', false);
  return Buffer.from(arr);
}

function reverse(key) {
  let i = key.length - 1;
  let j = 0;

  while (i > j) {
    const t = key[i];
    key[i] = key[j];
    key[j] = t;
    i -= 1;
    j += 1;
  }

  return key;
}

/*
 * Expose
 */

module.exports = EDDSA;
