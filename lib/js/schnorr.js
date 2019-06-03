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
 * Resources:
 *   https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki
 *   https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr/reference.py
 *   https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr/test-vectors.csv
 *   https://github.com/ElementsProject/secp256k1-zkp/tree/secp256k1-zkp/src/modules/schnorrsig
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
    // In order for BIP-Schnorr's quadratic residue trick to work,
    // `-1 mod p` must _not_ be a quadratic residue itself. In
    // other words, the curve must satisfy `jacobi(-1, p) != 1`
    // (or `jacobi(-1, p) == -1` for that matter).
    //
    // For more information, see the bip-schnorr citations:
    //   https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki#cite_note-4
    return this.curve.one.redNeg().redJacobi() === -1;
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
    return num.iumod(this.curve.n);
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

    // Let R = k'*G.
    const R = G.mulBlind(k);

    // Encode x(R).
    const Rraw = this.curve.encodeField(R.getX());

    // Encode d*G.
    const Araw = G.mulBlind(a).encode();

    // Let e = int(hash(bytes(x(R)) || bytes(d*G) || m)) mod n.
    const e = this.hashInt(Rraw, Araw, msg);

    // Scalar blinding factor.
    const [blind, unblind] = this.curve.getBlinding();

    // Blind.
    a.imul(blind).iumod(N);
    k.imul(blind).iumod(N);

    // Let k = k' if jacobi(y(R)) = 1, otherwise let k = n - k'.
    if (R.y.redJacobi() !== 1)
      k.ineg().iumod(N);

    // Let S = k + e*d mod n.
    const S = k.iadd(e.imul(a)).iumod(N);

    // Unblind.
    S.imul(unblind).iumod(N);

    // The signature is bytes(x(R)) || bytes(k + e*d mod n).
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
    //   s*G == R + e*P
    //
    // But bip-schnorr optimizes for shamir's trick with:
    //
    //   r == x(s*G - e*P)
    //
    // This is even more necessary perf-wise since we only
    // encode the X coordinate as the R value (it avoids us
    // having to recalculate the Y coordinate).
    //
    // Note that we stay in the jacobian space here. This
    // avoids any unnecessary divisions by the Z coordinate.

    // Let R = s*G - e*P.
    // Fail if infinite(R) or jacobi(y(R)) != 1 or x(R) != r.
    const R = G.jmulAdd(S, A, e.ineg().iumod(N));

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

  batchVerify(batch) {
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
      return this._batchVerify(batch);
    } catch (e) {
      return false;
    }
  }

  _batchVerify(batch) {
    const P = this.curve.p;
    const N = this.curve.n;
    const G = this.curve.g;
    const points = [];
    const coeffs = [];

    let sum = null;

    // Seed the RNG with our batch. This
    // code assumes the signers do not
    // have complete knowledge of the
    // other signatures in the set.
    this.rng.seed(batch);

    // Verify all signatures.
    for (const [msg, sig, key] of batch) {
      // Let r = int(sigi[0:32]); fail if r >= p.
      // Let si = int(sigi[32:64]); fail if si >= n.
      // Let Pi = point(pki); fail if point(pki) fails.
      const Rraw = sig.slice(0, this.curve.fieldSize);
      const Sraw = sig.slice(this.curve.fieldSize);
      const Rx = this.curve.decodeField(Rraw);
      const S = this.curve.decodeScalar(Sraw);
      const A = this.curve.decodePoint(key);

      if (Rx.cmp(P) >= 0 || S.cmp(N) >= 0)
        return false;

      // Let ei = int(hash(bytes(r) || bytes(Pi) || mi)) mod n.
      const e = this.hashInt(Rraw, this.encode(key), msg);

      // Let c = (r^3 + 7) mod p.
      // Let y = c^((p+1)/4) mod p.
      // Fail if c != y^2 mod p.
      // Let Ri = (r, y).
      const R = this.curve.pointFromR(Rx);

      // Let lhs = s1 + a2*s2 + ... + au*su.
      // Let rhs = R1 + a2*R2 + ... + au*Ru
      //         + e1*P1 + (a2*e2)P2 + ... + (au*eu)Pu.
      if (sum === null) {
        sum = S;
        points.push(R, A);
        coeffs.push(new BN(1), e);
        continue;
      }

      // Generate u-1 random integers a2...u in the range 1...n-1.
      const a = this.rng.generate();
      const ea = e.imul(a).iumod(N);

      sum.iadd(S.imul(a)).iumod(N);
      points.push(R, A);
      coeffs.push(a, ea);
    }

    // No signatures.
    if (sum === null)
      return true;

    // If our curve is endomorphic, we can pass an odd
    // number of points and coefficients to mullAll().
    // This means we can optimize the final check as:
    //
    //   rhs - lhs*G == infinity
    //
    // This trick is borrowed from libsecp256k1-zkp.
    if (this.curve.endo) {
      points.push(G);
      coeffs.push(sum.ineg().iumod(N));
      return this.curve.jmulAll(points, coeffs).isInfinity();
    }

    // Fail if lhs*G != rhs.
    const lhs = G.jmul(sum);
    const rhs = this.curve.jmulAll(points, coeffs);

    return lhs.eq(rhs);
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
    this.index = 0;
  }

  seed(batch) {
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
    this.index = 0;

    return this;
  }

  encrypt(counter) {
    assert((counter >>> 0) === counter);

    const data = Buffer.alloc(this.curve.scalarSize * 2, 0x00);
    const left = data.slice(0, this.curve.scalarSize);
    const right = data.slice(this.curve.scalarSize);

    this.chacha.init(this.key, this.iv, counter);
    this.chacha.encrypt(data);

    return [
      this.curve.decodeScalar(left),
      this.curve.decodeScalar(right)
    ];
  }

  refresh(counter) {
    let overflow = 0;

    for (;;) {
      this.iv.writeUInt32LE(overflow++, 4);

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

  scalar(index) {
    assert((index >>> 0) === index);

    if (index & 1)
      this.refresh(index >>> 1);

    return this.cache[index & 1];
  }

  generate() {
    this.index += 1;
    return this.scalar(this.index);
  }
}

/*
 * Expose
 */

module.exports = Schnorr;
