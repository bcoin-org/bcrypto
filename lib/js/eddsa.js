/*!
 * eddsa.js - ed25519 for bcrypto
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on indutny/elliptic:
 *   Copyright (c) 2014, Fedor Indutny (MIT License).
 *   https://github.com/indutny/elliptic
 *
 * Resources:
 *   https://tools.ietf.org/html/rfc7748
 *   https://tools.ietf.org/html/rfc7748#section-5
 *   https://tools.ietf.org/html/rfc8032
 *   https://tools.ietf.org/html/rfc8032#appendix-A
 *   https://tools.ietf.org/html/rfc8032#appendix-B
 *   https://eprint.iacr.org/2015/625.pdf
 *   http://ed448goldilocks.sourceforge.net/
 *   git://git.code.sf.net/p/ed448goldilocks/code
 *   https://git.zx2c4.com/goldilocks/tree/src
 */

'use strict';

const assert = require('bsert');
const curves = require('./curves');
const eckey = require('../internal/eckey');
const asn1 = require('../encoding/asn1');
const pkcs8 = require('../encoding/pkcs8');
const x509 = require('../encoding/x509');
const BN = require('../bn.js');
const random = require('../random');

/*
 * Constants
 */

const SLAB = Buffer.alloc(1);

/*
 * EDDSA
 */

class EDDSA {
  constructor(id, xid, hash) {
    assert(typeof id === 'string');
    assert(typeof xid === 'string');
    assert(hash);

    this.id = id;
    this.xid = xid;
    this.hash = hash;
    this._curve = null;
    this._x = null;
    this.edwards = true;
    this.mont = false;
    this.native = 0;
  }

  get curve() {
    if (!this._curve)
      this._curve = new curves[this.id]();
    return this._curve;
  }

  get x() {
    if (!this._x)
      this._x = new curves[this.xid]();
    return this._x;
  }

  get size() {
    return this.curve.size;
  }

  get bits() {
    return this.curve.bits;
  }

  hashKey(secret) {
    assert(Buffer.isBuffer(secret));
    assert(secret.length === this.size);

    return this.hash.digest(secret, this.size * 2);
  }

  hashInt(ph, ctx, ...items) {
    assert(ph == null || typeof ph === 'boolean');
    assert(ctx == null || Buffer.isBuffer(ctx));
    assert(!ctx || ctx.length <= 255);

    // eslint-disable-next-line
    const h = new this.hash();

    h.init();

    if (this.curve.context || ph != null) {
      // Prefix.
      h.update(this.curve.prefix);

      // Pre-hash Flag.
      SLAB[0] = ph & 0xff;
      h.update(SLAB);

      // Context.
      if (ctx) {
        SLAB[0] = ctx.length;
        h.update(SLAB);
        h.update(ctx);
      } else {
        SLAB[0] = 0x00;
        h.update(SLAB);
      }
    } else {
      assert(ctx == null, 'Must pass pre-hash flag with context.');
    }

    // Integers.
    for (const item of items)
      h.update(item);

    const hash = h.final(this.size * 2);
    const num = new BN(hash, 'le');

    return num.umod(this.curve.n);
  }

  privateKeyGenerate() {
    return random.randomBytes(this.size);
  }

  scalarGenerate() {
    const scalar = random.randomBytes(this.size);
    return this.curve.clamp(scalar);
  }

  privateKeyConvert(secret) {
    return this.curve.clamp(this.hashKey(secret));
  }

  privateKeyVerify(secret) {
    assert(Buffer.isBuffer(secret));
    return secret.length === this.size;
  }

  scalarVerify(scalar) {
    assert(Buffer.isBuffer(scalar));

    if (scalar.length !== this.curve.scalarLength)
      return false;

    const clamped = this.curve.clamp(Buffer.from(scalar));

    return scalar.equals(clamped);
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

  privateKeyExportJWK(key) {
    return eckey.privateKeyExportJWK(this, key);
  }

  privateKeyImportJWK(json) {
    return eckey.privateKeyImportJWK(this, json);
  }

  scalarTweakAdd(scalar, tweak) {
    const t = this.curve.decodeScalar(tweak).umod(this.curve.n);
    const k = this.curve.decodeScalar(scalar).iadd(t).umod(this.curve.n);

    if (k.isZero())
      throw new Error('Invalid scalar.');

    return this.curve.encodeScalar(k);
  }

  scalarTweakMul(scalar, tweak) {
    const t = this.curve.decodeScalar(tweak).umod(this.curve.n);
    const k = this.curve.decodeScalar(scalar).imul(t).umod(this.curve.n);

    if (k.isZero())
      throw new Error('Invalid scalar.');

    return this.curve.encodeScalar(k);
  }

  publicKeyCreate(secret) {
    const key = this.privateKeyConvert(secret);
    return this.publicKeyFromScalar(key);
  }

  publicKeyFromScalar(scalar) {
    const a = this.curve.decodeScalar(scalar).umod(this.curve.n);
    const A = this.curve.g.mul(a);

    return A.encode();
  }

  publicKeyConvert(key) {
    const point = this.curve.decodePoint(key);
    return this.x.fromEdwards(point).encode();
  }

  publicKeyDeconvert(key, sign = false) {
    const point = this.x.decodePoint(key);
    return this.curve.fromMont(point, sign).encode();
  }

  publicKeyVerify(key) {
    assert(Buffer.isBuffer(key));

    let point;

    try {
      point = this.curve.decodePoint(key);
    } catch (e) {
      return false;
    }

    return point.validate();
  }

  publicKeyExport(key) {
    assert(Buffer.isBuffer(key));
    assert(key.length === this.size);
    return key;
  }

  publicKeyImport(raw) {
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

    return this.publicKeyImport(spki.publicKey.rightAlign());
  }

  publicKeyExportJWK(key) {
    return eckey.publicKeyExportJWK(this, key);
  }

  publicKeyImportJWK(json) {
    return eckey.publicKeyImportJWK(this, json, false);
  }

  publicKeyTweakAdd(key, tweak) {
    const t = this.curve.decodeScalar(tweak).umod(this.curve.n);
    const k = this.curve.decodePoint(key);
    const point = this.curve.g.mul(t).add(k);

    if (point.isInfinity())
      throw new Error('Invalid public key.');

    return point.encode();
  }

  publicKeyTweakMul(key, tweak) {
    const t = this.curve.decodeScalar(tweak).umod(this.curve.n);
    const k = this.curve.decodePoint(key);
    const point = k.mul(t);

    if (point.isInfinity())
      throw new Error('Invalid private key.');

    return point.encode();
  }

  sign(msg, secret, ph, ctx) {
    const hash = this.hashKey(secret);
    const key = this.curve.clamp(hash);
    const prefix = hash.slice(this.size);

    return this.signWithScalar(msg, key, prefix, ph, ctx);
  }

  signWithScalar(msg, scalar, prefix, ph, ctx) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(prefix));
    assert(prefix.length === this.size);

    const a = this.curve.decodeScalar(scalar);
    const A = this.curve.g.mul(a).encode();
    const r = this.hashInt(ph, ctx, prefix, msg);
    const R = this.curve.g.mul(r).encode();
    const h = this.hashInt(ph, ctx, R, A, msg);
    const S = r.add(h.mul(a)).umod(this.curve.n);

    return Buffer.concat([R, this.curve.encodeInt(S)]);
  }

  signTweakAdd(msg, secret, tweak, ph, ctx) {
    const hash = this.hashKey(secret);
    const key_ = this.curve.clamp(hash);
    const prefix_ = hash.slice(this.size);
    const key = this.scalarTweakAdd(key_, tweak);
    const expanded = this.hash.multi(prefix_, tweak, null, this.size * 2);
    const prefix = expanded.slice(0, this.size);

    return this.signWithScalar(msg, key, prefix, ph, ctx);
  }

  signTweakMul(msg, secret, tweak, ph, ctx) {
    const hash = this.hashKey(secret);
    const key_ = this.curve.clamp(hash);
    const prefix_ = hash.slice(this.size);
    const key = this.scalarTweakMul(key_, tweak);
    const expanded = this.hash.multi(prefix_, tweak, null, this.size * 2);
    const prefix = expanded.slice(0, this.size);

    return this.signWithScalar(msg, key, prefix, ph, ctx);
  }

  verify(msg, sig, key, ph, ctx) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(sig));
    assert(Buffer.isBuffer(key));
    assert(ph == null || typeof ph === 'boolean');
    assert(ctx == null || Buffer.isBuffer(ctx));
    assert(!ctx || ctx.length <= 255);

    if (!this.curve.context && ctx != null)
      assert(ph != null, 'Must pass pre-hash flag with context.');

    if (sig.length !== this.size * 2)
      return false;

    if (key.length !== this.size)
      return false;

    try {
      return this._verify(msg, sig, key, ph, ctx);
    } catch (e) {
      return false;
    }
  }

  _verify(msg, sig, key, ph, ctx) {
    const Rraw = sig.slice(0, this.size);
    const Sraw = sig.slice(this.size);
    const R = this.curve.decodePoint(Rraw);
    const S = this.curve.decodeInt(Sraw);
    const A = this.curve.decodePoint(key);

    if (S.cmp(this.curve.n) >= 0)
      return false;

    const h = this.hashInt(ph, ctx, Rraw, key, msg);
    const rhs = R.add(A.mul(h));
    const lhs = this.curve.g.mul(S);

    return lhs.eq(rhs);
  }

  derive(pub, secret) {
    const priv = this.privateKeyConvert(secret);
    return this.deriveWithScalar(pub, priv);
  }

  deriveWithScalar(pub, scalar) {
    const a = this.curve.decodeScalar(scalar).umod(this.curve.n);
    const A = this.curve.decodePoint(pub);
    const point = A.mul(a);

    if (point.isInfinity())
      throw new Error('Invalid public key.');

    return point.encode();
  }

  exchange(pub, secret) {
    const priv = this.privateKeyConvert(secret);
    return this.exchangeWithScalar(pub, priv);
  }

  exchangeWithScalar(pub, scalar) {
    const s = this.curve.clamp(Buffer.from(scalar));
    const u = this.x.decodePoint(pub);
    const k = this.x.decodeScalar(s);
    const A = u.mul(k);

    if (A.isInfinity())
      throw new Error('Invalid public key.');

    return A.encode();
  }
}

/*
 * Expose
 */

module.exports = EDDSA;
