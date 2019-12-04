/*!
 * schnorr.js - bip-schnorr for bcrypto
 * Copyright (c) 2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on sipa/bip-schnorr:
 *   Copyright (c) 2018-2019, Pieter Wuille (2-clause BSD License).
 *   https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr/reference.py
 *
 * Parts of this software are based on ElementsProject/secp256k1-zkp:
 *   Copyright (c) 2013, Pieter Wuille.
 *   https://github.com/ElementsProject/secp256k1-zkp
 *
 * Parts of this software are based on bitcoin-core/secp256k1:
 *   Copyright (c) 2013, Pieter Wuille.
 *   https://github.com/bitcoin-core/secp256k1
 *
 * Resources:
 *   https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki
 *   https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr/reference.py
 *   https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr/test-vectors.csv
 *   https://github.com/bitcoin-core/secp256k1/pull/558
 *   https://github.com/jonasnick/secp256k1/blob/schnorrsig/src/secp256k1.c
 *   https://github.com/jonasnick/secp256k1/blob/schnorrsig/src/modules/schnorrsig/main_impl.h
 */

'use strict';

const assert = require('bsert');
const BN = require('../bn.js');
const ChaCha20 = require('../chacha20');
const rng = require('../random');
const SHA256 = require('../sha256');
const elliptic = require('./elliptic');
const pre = require('./precomputed/secp256k1.json');
const secp256k1 = elliptic.curve('SECP256K1', pre);

/**
 * Schnorr
 */

class Schnorr {
  constructor(curve, hash) {
    this.curve = curve;
    this.hash = hash;
    this.id = this.curve.id;
    this.type = 'schnorr';
    this.size = this.curve.fieldSize;
    this.bits = this.curve.fieldBits;
    this.native = 0;
    this.deriveTag = createTag(hash, 'BIPSchnorrDerive');
    this.hashTag = createTag(hash, 'BIPSchnorr');
    this.rng = new RNG(this);
    this.curve.precompute(rng);
  }

  hashInt(...items) {
    // eslint-disable-next-line
    const h = new this.hash();

    h.init();

    for (const item of items)
      h.update(item);

    const hash = h.final();
    const num = BN.decode(hash, this.curve.endian);

    return num.imod(this.curve.n);
  }

  privateKeyGenerate() {
    const a = this.curve.randomScalar(rng);
    return this.curve.encodeScalar(a);
  }

  privateKeyConvert(key) {
    const a = this.curve.decodeScalar(key);

    if (a.isZero() || a.cmp(this.curve.n) >= 0)
      throw new Error('Invalid private key.');

    const A = this.curve.g.mul(a);

    if (!A.hasQuadY())
      a.ineg().imod(this.curve.n);

    return this.curve.encodeScalar(a);
  }

  privateKeyVerify(key) {
    assert(Buffer.isBuffer(key));

    let a;
    try {
      a = this.curve.decodeScalar(key);
    } catch (e) {
      return false;
    }

    return !a.isZero() && a.cmp(this.curve.n) < 0;
  }

  privateKeyTweakAdd(key, tweak) {
    const t = this.curve.decodeScalar(tweak);

    if (t.cmp(this.curve.n) >= 0)
      throw new Error('Invalid scalar.');

    const a = this.curve.decodeScalar(key);

    if (a.isZero() || a.cmp(this.curve.n) >= 0)
      throw new Error('Invalid private key.');

    const A = this.curve.g.mul(a);

    if (!A.hasQuadY())
      a.ineg().imod(this.curve.n);

    const T = a.iadd(t).imod(this.curve.n);

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

    const T = a.imul(t).imod(this.curve.n);

    if (T.isZero())
      throw new Error('Invalid private key.');

    return this.curve.encodeScalar(T);
  }

  privateKeyReduce(key) {
    assert(Buffer.isBuffer(key));

    if (key.length > this.curve.scalarSize)
      key = key.slice(0, this.curve.scalarSize);

    const a = BN.decode(key, this.curve.endian).imod(this.curve.n);

    return this.curve.encodeScalar(a);
  }

  privateKeyInvert(key) {
    const a = this.curve.decodeScalar(key);

    if (a.isZero() || a.cmp(this.curve.n) >= 0)
      throw new Error('Invalid private key.');

    const T = a.invert(this.curve.n);

    return this.curve.encodeScalar(T);
  }

  publicKeyCreate(key) {
    const a = this.curve.decodeScalar(key);

    if (a.isZero() || a.cmp(this.curve.n) >= 0)
      throw new Error('Invalid private key.');

    const A = this.curve.g.mulBlind(a);

    return A.encodeX();
  }

  publicKeyConvert(key, compress) {
    const A = this.curve.decodeX(key);
    return A.encode(compress);
  }

  publicKeyFromUniform(bytes) {
    const u = this.curve.decodeUniform(bytes);
    const p = this.curve.pointFromUniform(u);

    return p.encodeX();
  }

  publicKeyToUniform(key, hint = rng.randomInt()) {
    const p = this.curve.decodeX(key);
    const u = this.curve.pointToUniform(p, hint);

    return this.curve.encodeUniform(u, rng);
  }

  publicKeyFromHash(bytes) {
    const p = this.curve.pointFromHash(bytes);

    return p.encodeX();
  }

  publicKeyToHash(key) {
    const p = this.curve.decodeX(key);
    return this.curve.pointToHash(p, rng);
  }

  publicKeyVerify(key) {
    assert(Buffer.isBuffer(key));

    try {
      this.curve.decodeX(key);
    } catch (e) {
      return false;
    }

    return true;
  }

  publicKeyExport(key, compress) {
    const A = this.curve.decodeX(key);
    return A.encode(compress);
  }

  publicKeyImport(key) {
    const A = this.curve.decodePoint(key);
    return A.encodeX();
  }

  publicKeyTweakAdd(key, tweak) {
    const t = this.curve.decodeScalar(tweak);

    if (t.cmp(this.curve.n) >= 0)
      throw new Error('Invalid scalar.');

    const A = this.curve.decodeX(key);
    const T = this.curve.g.mul(t).add(A);

    return T.encodeX();
  }

  publicKeyTweakMul(key, tweak) {
    const t = this.curve.decodeScalar(tweak);

    if (t.isZero() || t.cmp(this.curve.n) >= 0)
      throw new Error('Invalid scalar.');

    const A = this.curve.decodeX(key);
    const T = A.mul(t);

    return T.encodeX();
  }

  publicKeyAdd(key1, key2) {
    const A1 = this.curve.decodeX(key1);
    const A2 = this.curve.decodeX(key2);
    const T = A1.add(A2);

    return T.encodeX();
  }

  publicKeyCombine(keys) {
    assert(Array.isArray(keys));

    let acc = this.curve.jpoint();

    for (const key of keys) {
      const point = this.curve.decodeX(key);

      acc = acc.add(point);
    }

    return acc.encodeX();
  }

  sign(msg, key) {
    assert(Buffer.isBuffer(msg));
    assert(msg.length === 32);

    const N = this.curve.n;
    const G = this.curve.g;

    // The secret key d': an integer in the range 1..n-1.
    const a = this.curve.decodeScalar(key);

    if (a.isZero() || a.cmp(N) >= 0)
      throw new Error('Invalid private key.');

    // Let P = d' * G.
    const A = G.mulBlind(a);

    // Let d = d' if jacobi(y(P)) = 1, otherwise let d = n - d'.
    if (!A.hasQuadY())
      a.ineg().imod(N);

    // Let k' = int(hashBIPSchnorrDerive(bytes(d) || m)) mod n.
    const raw = this.curve.encodeScalar(a);
    const k = this.hashInt(this.deriveTag, raw, msg);

    // Fail if k' = 0.
    if (k.isZero())
      throw new Error('Signing failed (k\' = 0).');

    // Let R = k' * G.
    const R = G.mulBlind(k);

    // Let k = k' if jacobi(y(R)) = 1, otherwise let k = n - k' .
    if (!R.hasQuadY())
      k.ineg().imod(N);

    // Encode x(R).
    const Rraw = R.encodeX();

    // Encode x(P).
    const Araw = A.encodeX();

    // Let e = int(hashBIPSchnorr(bytes(R) || bytes(P) || m)) mod n.
    const e = this.hashInt(this.hashTag, Rraw, Araw, msg);

    // Scalar blinding factor.
    const [blind, unblind] = this.curve.getBlinding();

    // Blind.
    a.imul(blind).imod(N);
    k.imul(blind).imod(N);

    // Let S = (k + e * d) mod n.
    const S = k.iadd(e.imul(a)).imod(N);

    // Unblind.
    S.imul(unblind).imod(N);

    // The signature is bytes(R) || bytes((k + e * d) mod n).
    return Buffer.concat([Rraw, this.curve.encodeScalar(S)]);
  }

  verify(msg, sig, key) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(sig));
    assert(Buffer.isBuffer(key));

    if (msg.length !== 32)
      return false;

    if (sig.length !== this.curve.fieldSize + this.curve.scalarSize)
      return false;

    if (key.length !== this.curve.fieldSize)
      return false;

    try {
      return this._verify(msg, sig, key);
    } catch (e) {
      return false;
    }
  }

  _verify(msg, sig, key) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(sig));
    assert(Buffer.isBuffer(key));

    const P = this.curve.p;
    const N = this.curve.n;
    const G = this.curve.g;

    // Let P = point(pk); fail if point(pk) fails.
    // Let r = int(sig[0:32]); fail if r >= p.
    // Let s = int(sig[32:64]); fail if s >= n.
    const Rraw = sig.slice(0, this.curve.fieldSize);
    const Sraw = sig.slice(this.curve.fieldSize);
    const Rx = this.curve.decodeField(Rraw);
    const S = this.curve.decodeScalar(Sraw);
    const A = this.curve.decodeX(key);

    if (Rx.cmp(P) >= 0 || S.cmp(N) >= 0)
      return false;

    // Let e = int(hashBIPSchnorr(bytes(r) || bytes(P) || m)) mod n.
    const e = this.hashInt(this.hashTag, Rraw, key, msg);

    // In concept, a schnorr sig can be validated with:
    //
    //   s * G == R + e * P
    //
    // But bip-schnorr optimizes for Shamir's trick with:
    //
    //   r == x(s * G - e * P)
    //
    // This is even more necessary perf-wise since we only
    // encode the X coordinate as the R value (it avoids us
    // having to recalculate the Y coordinate).
    //
    // Note that we stay in the jacobian space here. This
    // avoids any unnecessary divisions by the Z coordinate.

    // Let R = s * G - e * P.
    // Fail if infinite(R) or jacobi(y(R)) != 1 or x(R) != r.
    const R = G.jmulAdd(S, A, e.ineg().imod(N));

    // Check for point at infinity.
    if (R.isInfinity())
      return false;

    // Check for quadratic residue in the jacobian space.
    // Optimized as `jacobi(y(R) * z(R)) == 1`.
    if (!R.hasQuadY())
      return false;

    // Check `x(R) == r` in the jacobian space.
    // Optimized as `x(R) == r * z(R)^2 mod p`.
    if (!R.eqX(Rx))
      return false;

    return true;
  }

  verifyBatch(batch) {
    assert(Array.isArray(batch));

    for (const item of batch) {
      assert(Array.isArray(item) && item.length === 3);

      const [msg, sig, key] = item;

      assert(Buffer.isBuffer(msg));
      assert(Buffer.isBuffer(sig));
      assert(Buffer.isBuffer(key));

      if (msg.length !== 32)
        return false;

      if (sig.length !== this.curve.fieldSize + this.curve.scalarSize)
        return false;

      if (key.length !== this.curve.fieldSize)
        return false;
    }

    try {
      return this._verifyBatch(batch);
    } catch (e) {
      return false;
    }
  }

  _verifyBatch(batch) {
    const N = this.curve.n;
    const G = this.curve.g;
    const items = new Array(batch.length);
    const points = new Array(1 + batch.length * 2);
    const coeffs = new Array(1 + batch.length * 2);
    const sum = new BN(0);

    // Pre-parse all keys for the RNG.
    for (let i = 0; i < batch.length; i++) {
      const [msg, sig, key] = batch[i];
      const A = this.curve.decodeX(key);

      items[i] = [msg, sig, key, A];
    }

    // Seed the RNG with our batch.
    this.rng.init(items);

    // Setup multiplication for lhs * G.
    points[0] = G;
    coeffs[0] = sum;

    // Verify all signatures.
    for (let i = 0; i < items.length; i++) {
      const [msg, sig, key, A] = items[i];

      // Let r = int(sigi[0:32]); fail if r >= p.
      // Let Ri = lift_x(r); fail if lift_x(r) fails.
      // Let si = int(sigi[32:64]); fail if si >= n.
      // Let Pi = point(pki); fail if point(pki) fails.
      const Rraw = sig.slice(0, this.curve.fieldSize);
      const Sraw = sig.slice(this.curve.fieldSize);
      const R = this.curve.decodeX(Rraw);
      const S = this.curve.decodeScalar(Sraw);

      if (S.cmp(N) >= 0)
        return false;

      // Let ei = int(hashBIPSchnorr(bytes(r) || bytes(Pi) || mi)) mod n.
      const e = this.hashInt(this.hashTag, Rraw, key, msg);

      // Generate u-1 random integers a2...u in the range 1...n-1.
      const a = this.rng.generate(i);
      const ea = e.imul(a).imod(N);

      // Let lhs = s1 + a2 * s2 + ... + au * su.
      sum.iadd(S.imul(a)).imod(N);

      // Let rhs = R1 + a2 * R2 + ... + au * Ru
      //         + e1 * P1 + (a2 * e2) * P2 + ... + (au * eu) * Pu.
      points[1 + i * 2 + 0] = R;
      coeffs[1 + i * 2 + 0] = a;
      points[1 + i * 2 + 1] = A;
      coeffs[1 + i * 2 + 1] = ea;
    }

    // In concept, we can validate the batch with:
    //
    //   lhs * G == rhs
    //
    // But we can use Shamir's trick to check:
    //
    //   -lhs * G + rhs == O
    //
    // This trick is borrowed from libsecp256k1-zkp.
    sum.ineg().imod(N);

    return this.curve.jmulAll(points, coeffs).isInfinity();
  }

  derive(pub, priv) {
    const a = this.curve.decodeScalar(priv);

    if (a.isZero() || a.cmp(this.curve.n) >= 0)
      throw new Error('Invalid private key.');

    const A = this.curve.decodeX(pub);
    const point = A.mulConst(a, rng);

    return point.encodeX();
  }
}

/**
 * RNG (designed to mimic the libsecp256k1 CSPRNG)
 * @see https://github.com/jonasnick/secp256k1/blob/1901f3b/src/modules/schnorrsig/main_impl.h#L178
 * @see https://github.com/jonasnick/secp256k1/blob/1901f3b/src/scalar_4x64_impl.h#L965
 * @see https://github.com/jonasnick/secp256k1/blob/1901f3b/src/scalar_8x32_impl.h#L736
 */

class RNG {
  constructor(schnorr) {
    this.curve = schnorr.curve;
    this.hash = schnorr.hash;
    this.chacha = new ChaCha20();
    this.key = Buffer.alloc(32, 0x00);
    this.iv = Buffer.alloc(8, 0x00);
    this.cache = [new BN(1), new BN(1)];
  }

  init(batch) {
    assert(Array.isArray(batch));

    // eslint-disable-next-line
    const h = new this.hash();
    const sign = Buffer.alloc(1);

    h.init();

    for (const [msg, sig, key, A] of batch) {
      sign[0] = 0x02 | A.sign();

      h.update(sig);
      h.update(msg);
      h.update(sign);
      h.update(key);
    }

    let key = h.final();

    if (key.length > 32)
      key = key.slice(0, 32);

    assert(key.length === 32);

    this.key = key;
    this.cache[0] = new BN(1);
    this.cache[1] = new BN(1);

    return this;
  }

  encrypt(counter) {
    const size = (this.curve.scalarSize * 2 + 3) & -4;
    const data = Buffer.alloc(size, 0x00);
    const left = data.slice(0, this.curve.scalarSize);
    const right = data.slice(this.curve.scalarSize);

    this.chacha.init(this.key, this.iv, counter);
    this.chacha.encrypt(data);

    // Swap endianness of each 32 bit int. This should
    // match the behavior of libsecp256k1 exactly.
    for (let i = 0; i < size; i += 4) {
      [data[i + 0], data[i + 3]] = [data[i + 3], data[i + 0]];
      [data[i + 1], data[i + 2]] = [data[i + 2], data[i + 1]];
    }

    return [
      this.curve.decodeScalar(left),
      this.curve.decodeScalar(right)
    ];
  }

  refresh(counter) {
    let overflow = 0;

    for (;;) {
      // First word is always zero.
      this.iv[4] = overflow;
      this.iv[5] = overflow >>> 8;
      this.iv[6] = overflow >>> 16;
      this.iv[7] = overflow >>> 24;

      overflow += 1;

      const [s1, s2] = this.encrypt(counter);

      if (s1.isZero() || s1.cmp(this.curve.n) >= 0)
        continue;

      if (s2.isZero() || s2.cmp(this.curve.n) >= 0)
        continue;

      this.cache[0] = s1;
      this.cache[1] = s2;

      break;
    }
  }

  generate(index) {
    assert((index >>> 0) === index);

    if (index & 1)
      this.refresh(index >>> 1);

    return this.cache[index & 1];
  }
}

/*
 * Helpers
 */

function createTag(alg, tag) {
  const raw = Buffer.from(tag, 'binary');
  const hash = alg.digest(raw);

  return Buffer.concat([hash, hash]);
}

/*
 * Expose
 */

module.exports = new Schnorr(secp256k1, SHA256);
