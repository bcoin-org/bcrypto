/*!
 * schnorr-legacy.js - legacy bip-schnorr for bcrypto
 * Copyright (c) 2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on sipa/bip-schnorr:
 *   Copyright (c) 2018-2019, Pieter Wuille (2-clause BSD License).
 *   https://github.com/sipa/bips/blob/d194620/bip-schnorr/reference.py
 *
 * Parts of this software are based on ElementsProject/secp256k1-zkp:
 *   Copyright (c) 2013, Pieter Wuille.
 *   https://github.com/ElementsProject/secp256k1-zkp
 *
 * Resources:
 *   https://github.com/sipa/bips/blob/d194620/bip-schnorr.mediawiki
 *   https://github.com/sipa/bips/blob/d194620/bip-schnorr/reference.py
 *   https://github.com/sipa/bips/blob/d194620/bip-schnorr/test-vectors.csv
 *   https://github.com/ElementsProject/secp256k1-zkp/tree/5d5374f/src/modules/schnorrsig
 *   https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/2019-05-15-schnorr.md
 */

'use strict';

const assert = require('bsert');
const BN = require('../bn.js');
const ChaCha20 = require('../chacha20');

/**
 * Schnorr
 */

class Schnorr {
  constructor(curve, hash) {
    this.curve = curve;
    this.hash = hash;
    this.msgSize = 32;
    this.sigSize = this.curve.fieldSize + this.curve.scalarSize;
    this.supported = this.support();
    this.rng = new RNG(this);
  }

  support() {
    // In order for BIP-Schnorr's quadratic residue trick
    // to work, `-1 mod p` must _not_ be a quadratic residue.
    //
    // The latest BIP-Schnorr also assumes a point's sign is
    // the result of the square root formula: c^((p + 1) / 4),
    // meaning the prime must be congruent to 3 mod 4.
    //
    // For more information, see the bip-schnorr footnotes:
    //   https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki#footnotes
    return this.curve.one.redNeg().redJacobi() === -1
        && this.curve.p.andln(3) === 3;
  }

  check() {
    if (!this.supported)
      throw new Error(`Schnorr is not supported for ${this.curve.id}.`);
  }

  encode(key) {
    assert(Buffer.isBuffer(key));

    // Extra speedy key reserialization.
    // This function assumes the key
    // has already been validated.
    const {fieldSize} = this.curve;

    if (key.length === 1 + fieldSize)
      return key;

    if (key.length !== 1 + fieldSize * 2)
      throw new Error('Invalid point.');

    const out = Buffer.allocUnsafe(1 + fieldSize);

    out[0] = 0x02 | (key[key.length - 1] & 1);
    key.copy(out, 1, 1, 1 + fieldSize);

    return out;
  }

  hashInt(x, y, z) {
    const hash = this.hash.multi(x, y, z);
    const num = BN.decode(hash, this.curve.endian);
    return num.imod(this.curve.n);
  }

  sign(msg, key) {
    assert(Buffer.isBuffer(msg));
    assert(msg.length === this.msgSize);

    this.check();

    const N = this.curve.n;
    const G = this.curve.g;

    // The secret key d: an integer in the range 1..n-1.
    const a = this.curve.decodeScalar(key);

    if (a.isZero() || a.cmp(N) >= 0)
      throw new Error('Invalid private key.');

    // Let k' = int(hash(bytes(d) || m)) mod n
    const k = this.hashInt(key, msg);

    // Fail if k' = 0.
    if (k.isZero())
      throw new Error('Signing failed (k\' = 0).');

    // Let R = k' * G.
    const R = G.mulBlind(k);

    // Encode x(R).
    const Rraw = R.encodeX();

    // Encode d * G.
    const Araw = G.mulBlind(a).encode();

    // Let e = int(hash(bytes(x(R)) || bytes(d * G) || m)) mod n.
    const e = this.hashInt(Rraw, Araw, msg);

    // Scalar blinding factor.
    const [blind, unblind] = this.curve.getBlinding();

    // Blind.
    a.imul(blind).imod(N);
    k.imul(blind).imod(N);

    // Let k = k' if jacobi(y(R)) = 1, otherwise let k = n - k'.
    if (!R.hasQuadY())
      k.ineg().imod(N);

    // Let S = k + e * d mod n.
    const S = k.iadd(e.imul(a)).imod(N);

    // Unblind.
    S.imul(unblind).imod(N);

    // The signature is bytes(x(R)) || bytes(k + e * d mod n).
    return Buffer.concat([Rraw, this.curve.encodeScalar(S)]);
  }

  verify(msg, sig, key) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(sig));
    assert(Buffer.isBuffer(key));

    this.check();

    if (msg.length !== this.msgSize)
      return false;

    if (sig.length !== this.sigSize)
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

    // Let r = int(sig[0:32]); fail if r >= p.
    // Let s = int(sig[32:64]); fail if s >= n.
    // Let P = point(pk); fail if point(pk) fails.
    const Rraw = sig.slice(0, this.curve.fieldSize);
    const Sraw = sig.slice(this.curve.fieldSize);
    const Rx = this.curve.decodeField(Rraw);
    const S = this.curve.decodeScalar(Sraw);
    const A = this.curve.decodePoint(key);

    if (Rx.cmp(P) >= 0 || S.cmp(N) >= 0)
      return false;

    // Let e = int(hash(bytes(r) || bytes(P) || m)) mod n.
    const e = this.hashInt(Rraw, this.encode(key), msg);

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

    this.check();

    for (const item of batch) {
      assert(Array.isArray(item) && item.length === 3);

      const [msg, sig, key] = item;

      assert(Buffer.isBuffer(msg));
      assert(Buffer.isBuffer(sig));
      assert(Buffer.isBuffer(key));

      if (msg.length !== this.msgSize)
        return false;

      if (sig.length !== this.sigSize)
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
    const points = new Array(1 + batch.length * 2);
    const coeffs = new Array(1 + batch.length * 2);
    const sum = new BN(0);

    // Seed the RNG with our batch.
    this.rng.init(batch);

    // Setup multiplication for lhs * G.
    points[0] = G;
    coeffs[0] = sum;

    // Verify all signatures.
    for (let i = 0; i < batch.length; i++) {
      const [msg, sig, key] = batch[i];

      // Let r = int(sigi[0:32]); fail if r >= p.
      // Let Ri = lift_x(r); fail if lift_x(r) fails.
      // Let si = int(sigi[32:64]); fail if si >= n.
      // Let Pi = point(pki); fail if point(pki) fails.
      const Rraw = sig.slice(0, this.curve.fieldSize);
      const Sraw = sig.slice(this.curve.fieldSize);
      const R = this.curve.decodeX(Rraw);
      const S = this.curve.decodeScalar(Sraw);
      const A = this.curve.decodePoint(key);

      if (S.cmp(N) >= 0)
        return false;

      // Let ei = int(hash(bytes(r) || bytes(Pi) || mi)) mod n.
      const e = this.hashInt(Rraw, this.encode(key), msg);

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
}

/**
 * RNG (designed to mimic the libsecp256k1-zkp CSPRNG)
 * @see https://github.com/ElementsProject/secp256k1-zkp/blob/d5e22a5/src/modules/schnorrsig/main_impl.h#L166
 * @see https://github.com/ElementsProject/secp256k1-zkp/blob/d5e22a5/src/scalar_4x64_impl.h#L974
 * @see https://github.com/ElementsProject/secp256k1-zkp/blob/d5e22a5/src/scalar_8x32_impl.h#L749
 */

class RNG {
  constructor(schnorr) {
    this.curve = schnorr.curve;
    this.hash = schnorr.hash;
    this.encode = schnorr.encode.bind(schnorr);
    this.chacha = new ChaCha20();
    this.key = Buffer.alloc(32, 0x00);
    this.iv = Buffer.alloc(8, 0x00);
    this.cache = [new BN(1), new BN(1)];
  }

  init(batch) {
    assert(Array.isArray(batch));

    // eslint-disable-next-line
    const h = new this.hash();

    h.init();

    for (const [msg, sig, key] of batch) {
      h.update(sig);
      h.update(msg);
      h.update(this.encode(key));
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
    assert((counter >>> 0) === counter);

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
 * Expose
 */

module.exports = Schnorr;
