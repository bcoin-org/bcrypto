/*!
 * ecdsa.js - wrapper for elliptic
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on indutny/elliptic:
 *   Copyright (c) 2014, Fedor Indutny (MIT License).
 *   https://github.com/indutny/elliptic
 */

'use strict';

const assert = require('bsert');
const BN = require('../bn.js');
const eckey = require('../internal/eckey');
const Signature = require('../internal/signature');
const asn1 = require('../encoding/asn1');
const sec1 = require('../encoding/sec1');
const pkcs8 = require('../encoding/pkcs8');
const x509 = require('../encoding/x509');
const rng = require('../random');
const Schnorr = require('./schnorr');
const DRBG = require('../drbg');
const curves = require('./curves');

/**
 * ECDSA
 */

class ECDSA {
  constructor(name, hash, pre) {
    assert(typeof name === 'string');
    assert(hash);

    this.id = name;
    this.type = 'short';
    this.hash = hash;
    this.native = 0;

    this._pre = pre || null;
    this._curve = null;
    this._schnorr = null;
  }

  get curve() {
    if (!this._curve) {
      this._curve = new curves[this.id](this._pre);
      this._curve.precompute(rng);
      this._pre = null;
    }
    return this._curve;
  }

  get schnorr() {
    if (!this._schnorr)
      this._schnorr = new Schnorr(this.curve, this.hash);
    return this._schnorr;
  }

  get size() {
    return this.curve.fieldSize;
  }

  get bits() {
    return this.curve.fieldBits;
  }

  privateKeyGenerate() {
    const a = BN.random(rng, 1, this.curve.n);
    return this.curve.encodeScalar(a);
  }

  privateKeyVerify(key) {
    assert(Buffer.isBuffer(key));

    let a = null;

    try {
      a = this.curve.decodeScalar(key);
    } catch (e) {
      return false;
    }

    if (a.isZero() || a.cmp(this.curve.n) >= 0)
      return false;

    return true;
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

    if (value.length > this.curve.scalarSize)
      throw new Error('Invalid private key.');

    const a = BN.decode(value, this.curve.endian);

    if (a.isZero() || a.cmp(this.curve.n) >= 0)
      throw new Error('Invalid private key.');

    return this.curve.encodeScalar(a);
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
    const t = this.curve.decodeScalar(tweak);

    if (t.cmp(this.curve.n) >= 0)
      throw new Error('Invalid scalar.');

    const a = this.curve.decodeScalar(key);

    if (a.isZero() || a.cmp(this.curve.n) >= 0)
      throw new Error('Invalid private key.');

    const T = a.iadd(t).iumod(this.curve.n);

    if (T.isZero())
      throw new Error('Invalid private key.');

    return this.curve.encodeScalar(T);
  }

  privateKeyTweakMul(key, tweak) {
    const t = this.curve.decodeScalar(tweak);

    if (t.isZero() || t.cmp(this.curve.n) >= 0)
      throw new Error('Invalid scalar.');

    const a = this.curve.decodeScalar(key);

    if (a.isZero() || a.cmp(this.curve.n) >= 0)
      throw new Error('Invalid private key.');

    const T = a.imul(t).iumod(this.curve.n);

    if (T.isZero())
      throw new Error('Invalid private key.');

    return this.curve.encodeScalar(T);
  }

  privateKeyReduce(key) {
    assert(Buffer.isBuffer(key));

    if (key.length > this.curve.scalarSize)
      key = key.slice(0, this.curve.scalarSize);

    const a = BN.decode(key, this.curve.endian).iumod(this.curve.n);

    return this.curve.encodeScalar(a);
  }

  privateKeyNegate(key) {
    const a = this.curve.decodeScalar(key);

    if (a.cmp(this.curve.n) >= 0)
      throw new Error('Invalid private key.');

    const T = a.ineg().iumod(this.curve.n);

    return this.curve.encodeScalar(T);
  }

  privateKeyInverse(key) {
    const a = this.curve.decodeScalar(key);

    if (a.isZero() || a.cmp(this.curve.n) >= 0)
      throw new Error('Invalid private key.');

    const T = a.invm(this.curve.n);

    if (T.isZero())
      throw new Error('Invalid private key.');

    return this.curve.encodeScalar(T);
  }

  publicKeyCreate(key, compress) {
    const a = this.curve.decodeScalar(key);

    if (a.isZero() || a.cmp(this.curve.n) >= 0)
      throw new Error('Invalid private key.');

    const A = this.curve.g.mulBlind(a);

    return A.encode(compress);
  }

  publicKeyConvert(key, compress) {
    const A = this.curve.decodePoint(key);
    return A.encode(compress);
  }

  publicKeyVerify(key) {
    assert(Buffer.isBuffer(key));

    try {
      this.curve.decodePoint(key);
    } catch (e) {
      return false;
    }

    return true;
  }

  publicKeyExport(key) {
    return this.publicKeyConvert(key, false).slice(1);
  }

  publicKeyImport(raw, compress) {
    assert(Buffer.isBuffer(raw));
    assert(raw.length === this.curve.fieldSize * 2);

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
    const t = this.curve.decodeScalar(tweak);

    if (t.cmp(this.curve.n) >= 0)
      throw new Error('Invalid scalar.');

    const A = this.curve.decodePoint(key);
    const T = this.curve.g.mul(t).add(A);

    return T.encode(compress);
  }

  publicKeyTweakMul(key, tweak, compress) {
    const t = this.curve.decodeScalar(tweak);

    if (t.isZero() || t.cmp(this.curve.n) >= 0)
      throw new Error('Invalid scalar.');

    const A = this.curve.decodePoint(key);
    const T = A.mul(t);

    return T.encode(compress);
  }

  publicKeyAdd(key1, key2, compress) {
    const A1 = this.curve.decodePoint(key1);
    const A2 = this.curve.decodePoint(key2);
    const T = A1.add(A2);

    return T.encode(compress);
  }

  publicKeyNegate(key, compress) {
    const A = this.curve.decodePoint(key);
    const T = A.neg();

    return T.encode(compress);
  }

  signatureNormalize(raw) {
    const sig = Signature.decode(raw, this.curve.scalarSize);
    const r = this.curve.decodeScalar(sig.r);
    const s = this.curve.decodeScalar(sig.s);

    if (r.isZero() || r.cmp(this.curve.n) >= 0)
      throw new Error('Invalid R value.');

    if (s.isZero() || s.cmp(this.curve.n) >= 0)
      throw new Error('Invalid S value.');

    if (s.cmp(this.curve.nh) > 0)
      sig.s = this.curve.encodeScalar(s.ineg().iumod(this.curve.n));

    return sig.encode(this.curve.scalarSize);
  }

  signatureExport(sig) {
    return Signature.toDER(sig, this.curve.scalarSize);
  }

  signatureImport(sig) {
    return Signature.toRS(sig, this.curve.scalarSize);
  }

  _isLowS(sig) {
    const r = this.curve.decodeScalar(sig.r);
    const s = this.curve.decodeScalar(sig.s);

    if (r.isZero() || r.cmp(this.curve.n) >= 0)
      return false;

    if (s.isZero() || s.cmp(this.curve.n) >= 0)
      return false;

    return s.cmp(this.curve.nh) <= 0;
  }

  isLowS(sig) {
    assert(Buffer.isBuffer(sig));

    if (sig.length !== this.curve.scalarSize * 2)
      return false;

    const s = Signature.decode(sig, this.curve.scalarSize);

    return this._isLowS(s);
  }

  isLowDER(sig) {
    assert(Buffer.isBuffer(sig));

    let s;
    try {
      s = Signature.fromDER(sig, this.curve.scalarSize);
    } catch (e) {
      return false;
    }

    return this._isLowS(s);
  }

  _sign(msg, key) {
    assert(Buffer.isBuffer(msg));

    const N = this.curve.n;
    const Nh = this.curve.nh;
    const G = this.curve.g;
    const a = this.curve.decodeScalar(key);

    if (a.isZero() || a.cmp(N) >= 0)
      throw new Error('Invalid private key.');

    // https://tools.ietf.org/html/rfc6979#section-3.2
    const m = this._reduce(msg);
    const nonce = this.curve.encodeScalar(m);
    const drbg = new DRBG(this.hash, key, nonce);

    for (;;) {
      const bytes = drbg.generate(this.curve.scalarSize);
      const k = this._truncate(bytes);

      if (k.isZero() || k.cmp(N) >= 0)
        continue;

      const kp = G.mulBlind(k);

      if (kp.isInfinity())
        continue;

      const x = kp.getX();
      const r = x.umod(N);

      if (r.isZero())
        continue;

      // Reasoning: fermat's little theorem
      // has better constant-time properties
      // than an EGCD.
      const ki = k.finvm(N);

      // Scalar blinding factor.
      const [blind, unblind] = this.curve.getBlinding();

      // Blind.
      const ba = a.mul(blind).iumod(N);
      const bm = m.mul(blind).iumod(N);

      // s := ((r * a + m) * k^-1) mod n
      const s = r.mul(ba).iumod(N)
                 .iadd(bm).iumod(N)
                 .imul(ki).iumod(N);

      // Unblind.
      s.imul(unblind).iumod(N);

      if (s.isZero())
        continue;

      let param = (kp.getY().isOdd() ? 1 : 0)
                | (x.cmp(r) !== 0 ? 2 : 0);

      // Use complement of `s`, if it is > `n / 2`.
      if (s.cmp(Nh) > 0) {
        s.ineg().iumod(N);
        param ^= 1;
      }

      const sig = new Signature();

      sig.r = this.curve.encodeScalar(r);
      sig.s = this.curve.encodeScalar(s);
      sig.param = param;

      return sig;
    }
  }

  sign(msg, key) {
    const sig = this._sign(msg, key);
    return sig.encode(this.curve.scalarSize);
  }

  signRecoverable(msg, key) {
    const sig = this._sign(msg, key);
    return {
      signature: sig.encode(this.curve.scalarSize),
      recovery: sig.param
    };
  }

  signDER(msg, key) {
    const sig = this._sign(msg, key);
    return sig.toDER(this.curve.scalarSize);
  }

  signRecoverableDER(msg, key) {
    const sig = this._sign(msg, key);
    return {
      signature: sig.toDER(this.curve.scalarSize),
      recovery: sig.param
    };
  }

  _verify(msg, sig, key) {
    const N = this.curve.n;
    const G = this.curve.g;
    const m = this._reduce(msg);
    const A = this.curve.decodePoint(key);
    const r = this.curve.decodeScalar(sig.r);
    const s = this.curve.decodeScalar(sig.s);

    if (r.isZero() || r.cmp(N) >= 0)
      return false;

    if (s.isZero() || s.cmp(N) >= 0)
      return false;

    const si = s.invm(N);
    const u1 = m.imul(si).iumod(N);
    const u2 = r.mul(si).iumod(N);

    if (this.curve.maxwellTrick) {
      // Greg Maxwell's trick, inspired by:
      // https://git.io/vad3K
      const p = G.jmulAdd(u1, A, u2);

      if (p.isInfinity())
        return false;

      // Compare `p.x` of Jacobian point with `r`,
      // this will do `p.x == r * p.z^2` instead
      // of multiplying `p.x` by the inverse of
      // `p.z^2`.
      return p.eqXToP(r);
    }

    const p = G.mulAdd(u1, A, u2);

    if (p.isInfinity())
      return false;

    return p.getX().umod(N).cmp(r) === 0;
  }

  verify(msg, sig, key) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(sig));
    assert(Buffer.isBuffer(key));

    if (sig.length !== this.curve.scalarSize * 2)
      return false;

    const s = Signature.decode(sig, this.curve.scalarSize);

    try {
      return this._verify(msg, s, key);
    } catch (e) {
      return false;
    }
  }

  verifyDER(msg, sig, key) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(sig));
    assert(Buffer.isBuffer(key));

    let s;
    try {
      s = Signature.fromDER(sig, this.curve.scalarSize);
    } catch (e) {
      return false;
    }

    try {
      return this._verify(msg, s, key);
    } catch (e) {
      return false;
    }
  }

  _recover(msg, sig, param) {
    const P = this.curve.p;
    const N = this.curve.n;
    const G = this.curve.g;
    const m = this._reduce(msg);
    const r = this.curve.decodeScalar(sig.r);
    const s = this.curve.decodeScalar(sig.s);

    if (r.isZero() || r.cmp(N) >= 0)
      throw new Error('Invalid R value.');

    if (s.isZero() || s.cmp(N) >= 0)
      throw new Error('Invalid S value.');

    const sign = param & 1;
    const high = param >>> 1;

    let x = r;

    if (high) {
      if (x.cmp(P.umod(N)) >= 0)
        throw new Error('Invalid R value.');

      x = x.add(N);
    }

    const kp = this.curve.pointFromX(x, sign);
    const ri = r.invm(N);
    const s1 = m.imul(ri).ineg().iumod(N);
    const s2 = s.imul(ri).iumod(N);
    const A = G.mulAdd(s1, kp, s2);

    if (A.isInfinity())
      throw new Error('Invalid point.');

    return A;
  }

  recover(msg, sig, param, compress) {
    if (param == null)
      param = 0;

    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(sig));
    assert((param >>> 0) === param);
    assert((param & 3) === param, 'The recovery param is more than two bits.');

    if (sig.length !== this.curve.scalarSize * 2)
      return null;

    const s = Signature.decode(sig, this.curve.scalarSize);

    let point;
    try {
      point = this._recover(msg, s, param);
    } catch (e) {
      return null;
    }

    return point.encode(compress);
  }

  recoverDER(msg, sig, param, compress) {
    if (param == null)
      param = 0;

    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(sig));
    assert((param >>> 0) === param);
    assert((param & 3) === param, 'The recovery param is more than two bits.');

    let s;
    try {
      s = Signature.fromDER(sig, this.curve.scalarSize);
    } catch (e) {
      return null;
    }

    let point;
    try {
      point = this._recover(msg, s, param);
    } catch (e) {
      return null;
    }

    return point.encode(compress);
  }

  derive(pub, priv, compress) {
    const a = this.curve.decodeScalar(priv);

    if (a.isZero() || a.cmp(this.curve.n) >= 0)
      throw new Error('Invalid private key.');

    const A = this.curve.decodePoint(pub);
    const point = A.mulBlind(a, rng);

    return point.encode(compress);
  }

  /*
   * Compat
   */

  fromDER(sig) {
    return this.signatureImport(sig);
  }

  toDER(sig) {
    return this.signatureExport(sig);
  }

  /*
   * Helpers
   */

  _truncate(msg) {
    assert(Buffer.isBuffer(msg));

    const bits = this.curve.n.bitLength();
    const bytes = (bits + 7) >>> 3;

    if (msg.length > bytes)
      msg = msg.slice(0, bytes);

    const m = BN.decode(msg, this.curve.endian);
    const d = msg.length * 8 - bits;

    if (d > 0)
      m.iushrn(d);

    return m;
  }

  _reduce(msg) {
    return this._truncate(msg).iumod(this.curve.n);
  }
}

/*
 * Expose
 */

module.exports = ECDSA;
