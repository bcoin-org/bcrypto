/*!
 * primes.js - Prime number generation for javascript
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on golang/go:
 *   Copyright (c) 2009 The Go Authors. All rights reserved.
 *   https://github.com/golang/go
 *
 * Parts of this software are based on indutny/miller-rabin:
 *   Copyright (c) 2014, Fedor Indutny (MIT License).
 *   https://github.com/indutny/miller-rabin
 *
 * Resources:
 *   https://github.com/golang/go/blob/master/src/crypto/rsa/rsa.go
 *   https://github.com/golang/go/blob/master/src/math/big/prime.go
 *   https://github.com/golang/go/blob/master/src/math/big/int.go
 *   https://github.com/golang/go/blob/master/src/math/big/nat.go
 *   https://github.com/golang/go/blob/master/src/crypto/rand/util.go
 *   https://github.com/indutny/miller-rabin/blob/master/lib/mr.js
 */

'use strict';

const assert = require('bsert');
const BN = require('../bn.js');
const rng = require('../random');

/*
 * Constants
 */

const smallPrimes = new Uint8Array([
   3,  5,  7,
  11, 13, 17,
  19, 23, 29,
  31, 37, 41,
  43, 47, 53
]);

const smallPrimesProduct = new BN('16294579238595022365', 10);

const primeBitMaskLo = 0
  | (1 << 2)
  | (1 << 3)
  | (1 << 5)
  | (1 << 7)
  | (1 << 11)
  | (1 << 13)
  | (1 << 17)
  | (1 << 19)
  | (1 << 23)
  | (1 << 29)
  | (1 << 31);

const primeBitMaskHi = 0
  | (1 << (37 - 32))
  | (1 << (41 - 32))
  | (1 << (43 - 32))
  | (1 << (47 - 32))
  | (1 << (53 - 32))
  | (1 << (59 - 32))
  | (1 << (61 - 32));

const primesA = new BN(3 * 5 * 7 * 11 * 13 * 17 * 19 * 23 * 37);
const primesB = new BN(29 * 31 * 41 * 43 * 47 * 53);

// https://github.com/golang/go/blob/aadaec5/src/crypto/rand/util.go#L31
function randomPrime(bits, reps = 20) {
  assert((bits >>> 0) === bits);
  assert((reps >>> 0) === reps);
  assert(bits >= 2);

  let b = bits % 8;

  if (b === 0)
    b = 8;

  const len = (bits + 7) >>> 3;
  const bytes = Buffer.allocUnsafe(len);

  for (;;) {
    rng.randomFill(bytes, 0, len);

    bytes[0] &= (1 << b) - 1;

    if (b >= 2) {
      bytes[0] |= 3 << (b - 2);
    } else {
      bytes[0] |= 1;
      if (bytes.length > 1)
        bytes[1] |= 0x80;
    }

    bytes[bytes.length - 1] |= 1;

    const p = new BN(bytes);
    const mod = p.mod(smallPrimesProduct);

next:
    for (let delta = 0; delta < (1 << 20); delta += 2) {
      const m = mod.addn(delta);

      for (let i = 0; i < smallPrimes.length; i++) {
        const prime = smallPrimes[i];
        if (m.modrn(prime) === 0 && (bits > 6 || m.cmpn(prime) !== 0))
          continue next;
      }

      if (delta > 0)
        p.iaddn(delta);

      break;
    }

    if (p.bitLength() !== bits)
      continue;

    if (!probablyPrime(p, reps))
      continue;

    return p;
  }
}

// https://github.com/golang/go/blob/aadaec5/src/math/big/prime.go#L26
function probablyPrime(x, reps) {
  assert(x instanceof BN);
  assert((reps >>> 0) === reps);

  if (x.isNeg() || x.isZero())
    return false;

  if (x.cmpn(64) < 0) {
    const w = x.andln(0xff);

    if (w > 31)
      return (primeBitMaskHi & (1 << (w - 32))) !== 0;

    return (primeBitMaskLo & (1 << w)) !== 0;
  }

  if (!x.isOdd())
    return false;

  const ra = x.umod(primesA).toNumber();
  const rb = x.umod(primesB).toNumber();

  if (ra % 3 === 0
      || ra % 5 === 0
      || ra % 7 === 0
      || ra % 11 === 0
      || ra % 13 === 0
      || ra % 17 === 0
      || ra % 19 === 0
      || ra % 23 === 0
      || ra % 37 === 0
      || rb % 29 === 0
      || rb % 31 === 0
      || rb % 41 === 0
      || rb % 43 === 0
      || rb % 47 === 0
      || rb % 53 === 0) {
    return false;
  }

  if (!millerRabinPrime(x, reps + 1, true))
    return false;

  if (!lucasPrime(x))
    return false;

  return true;
}

// https://github.com/indutny/miller-rabin/blob/master/lib/mr.js
function millerRabinPrime(n, reps, force2) {
  assert(n instanceof BN);
  assert((reps >>> 0) === reps);
  assert(typeof force2 === 'boolean');

  if (n.cmpn(7) < 0) {
    if (n.cmpn(2) === 0 || n.cmpn(3) === 0 || n.cmpn(5) === 0)
      return true;
    return false;
  }

  const nm1 = n.subn(1);
  const k = nm1.zeroBits();
  const q = nm1.ushrn(k);

  const nm3 = nm1.subn(2);

  const red = BN.red(n);
  const rnm1 = nm1.toRed(red);
  const rone = new BN(1).toRed(red);

  // Miller-Rabin primality test.
next:
  for (let i = 0; i < reps; i++) {
    let x;

    if (i === reps - 1 && force2) {
      x = new BN(2);
    } else {
      x = nm3.randomInt(rng);
      x.iaddn(2);
    }

    const y = x.toRed(red).redPow(q);

    if (y.cmp(rone) === 0 || y.cmp(rnm1) === 0)
      continue;

    for (let j = 1; j < k; j++) {
      y.redISqr();

      if (y.cmp(rnm1) === 0)
        continue next;

      if (y.cmp(rone) === 0)
        return false;
    }

    return false;
  }

  return true;
}

// https://github.com/golang/go/blob/aadaec5/src/math/big/prime.go#L150
function lucasPrime(n) {
  assert(n instanceof BN);

  // Ignore 0 and 1.
  if (n.isZero() || n.cmpn(1) === 0)
    return false;

  // Two is the only even prime.
  if (n.isEven())
    return n.cmpn(2) === 0;

  // Baillie-OEIS "method C" for choosing D, P, Q.
  // See: https://oeis.org/A217719/a217719.txt.
  let p = 3;

  for (;;) {
    if (p > 10000) {
      // Thought to be impossible.
      throw new Error(`Cannot find (D/n) = -1 for ${n.toString(10)}.`);
    }

    const d = new BN(p * p - 4);
    const j = d.jacobi(n);

    if (j === -1)
      break;

    if (j === 0)
      return n.cmpn(p + 2) === 0;

    if (p === 40) {
      const t1 = n.sqrt();
      t1.isqr();
      if (t1.cmp(n) === 0)
        return false;
    }

    p += 1;
  }

  // Check for Grantham definition of
  // "extra strong Lucas pseudoprime".
  const s = n.addn(1);
  const r = s.zeroBits();
  const nm2 = n.subn(2);

  s.iushrn(r);

  const bp = new BN(p);

  let vk = new BN(2);
  let vk1 = new BN(p);

  for (let i = s.bitLength(); i >= 0; i--) {
    let t1;

    if (s.testn(i)) {
      t1 = vk.mul(vk1);
      t1.iadd(n);
      t1.isub(bp);
      vk = t1.umod(n);
      t1 = vk1.sqr();
      t1.iadd(nm2);
      vk1 = t1.umod(n);
    } else {
      t1 = vk.mul(vk1);
      t1.iadd(n);
      t1.isub(bp);
      vk1 = t1.umod(n);
      t1 = vk.sqr();
      t1.iadd(nm2);
      vk = t1.umod(n);
    }
  }

  if (vk.cmpn(2) === 0 || vk.cmp(nm2) === 0) {
    let t1 = vk.mul(bp);
    let t2 = vk1.ushln(1);

    if (t1.cmp(t2) < 0)
      [t1, t2] = [t2, t1];

    t1.isub(t2);

    const t3 = t1.umod(n);

    if (t3.isZero())
      return true;
  }

  for (let t = 0; t < r - 1; t++) {
    if (vk.isZero())
      return true;

    if (vk.cmpn(2) === 0)
      return false;

    const t1 = vk.sqr();
    t1.isubn(2);
    vk = t1.umod(n);
  }

  return false;
}

/*
 * Expose
 */

exports.randomPrime = randomPrime;
exports.probablyPrime = probablyPrime;
exports.millerRabinPrime = millerRabinPrime;
exports.lucasPrime = lucasPrime;
