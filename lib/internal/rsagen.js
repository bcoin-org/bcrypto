/*!
 * rsagen.js - RSA for javascript
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 *
 * Parts of this software are based on golang/go:
 *   Copyright (c) 2009 The Go Authors. All rights reserved.
 *   https://github.com/golang/go
 *
 * Resources:
 *   https://github.com/golang/go/blob/master/src/crypto/rsa/rsa.go#L220
 *   https://github.com/golang/go/blob/master/src/crypto/rand/util.go
 *   https://github.com/golang/go/blob/master/src/math/big/prime.go
 *   https://github.com/golang/go/blob/master/src/math/big/nat.go#L991
 */

'use strict';

const assert = require('assert');
const BN = require('bn.js');
const random = require('../random');
const rsakey = require('./rsakey');
const gen = exports;

const {
  RSAKey,
  RSAPrivateKey,
  RSAPublicKey
} = rsakey;

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

const smallPrimesProduct = new BN('16294579238595022365', 'hex');

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

/**
 * Generate a private key.
 * @param {Number} [bits=2048]
 * @returns {RSAPrivateKey}
 */

gen.generateKey = function generateKey(bits = 2048) {
  assert((bits >>> 0) === bits);

  assert(bits === 512
    || bits === 1024
    || bits === 2048
    || bits === 4096
    || bits === 8192);

  const [, key] = genKey(2, bits);

  return key;
};

/**
 * Verify a public key.
 * @param {RSAKey} key
 * @returns {Boolean}
 */

gen.publicVerify = function publicVerify(key) {
  assert(key instanceof RSAKey);

  const e = new BN(key.e, 'be');

  if (e.cmpn(2) < 0)
    return false;

  if (e.bitLength() > 31)
    return false;

  const bits = key.n.length << 3;

  switch (bits) {
    case 512:
    case 1024:
    case 2048:
    case 4096:
    case 8192:
      break;
    default:
      return false;
  }

  return true;
};

/**
 * Verify a private key.
 * @param {RSAPrivateKey} key
 * @returns {Boolean}
 */

gen.privateVerify = function privateVerify(key) {
  assert(key instanceof RSAPrivateKey);

  if (!gen.publicVerify(key))
    return false;

  const mod = new BN(1);
  const primes = [key.p, key.q];

  for (const prime of primes) {
    if (prime.cmpn(1) <= 0)
      return false;

    mod.imul(prime);
  }

  const n = new BN(key.n, 'be');

  if (mod.cmp(n) !== 0)
    return false;

  const de = new BN(key.e, 'be');
  const d = new BN(key.d, 'be');

  de.imul(d);

  for (const prime of primes) {
    const pminus1 = prime.subn(1);
    const cg = de.mod(pminus1);

    if (cg.cmpn(1) !== 0)
      return false;
  }

  return true;
};

/**
 * Generate a private key.
 * @param {Number} [bits=2048]
 * @returns {Buffer} Private key.
 */

gen.privateKeyGenerate = function privateKeyGenerate(bits = 2048) {
  const key = gen.generateKey(bits);
  return key.encode();
};

/**
 * Generate a private key.
 * @param {Number} [bits=2048]
 * @returns {Buffer} Private key.
 */

gen.generatePrivateKey = gen.privateKeyGenerate;

/**
 * Create a public key from a private key.
 * @param {Buffer} key
 * @returns {Buffer}
 */

gen.publicKeyCreate = function publicKeyCreate(key) {
  const k = RSAPrivateKey.decode(key);
  const p = k.toPublic();
  return p.encode();
};

/**
 * Validate a public key.
 * @param {Buffer} key
 * @returns {Boolean} True if buffer is a valid public key.
 */

gen.publicKeyVerify = function publicKeyVerify(key) {
  assert(Buffer.isBuffer(key));

  let k;

  try {
    k = RSAPublicKey.decode(key);
  } catch (e) {
    return false;
  }

  return gen.publicVerify(k);
};

/**
 * Validate a private key.
 * @param {Buffer} key
 * @returns {Boolean} True if buffer is a valid private key.
 */

gen.privateKeyVerify = function privateKeyVerify(key) {
  assert(Buffer.isBuffer(key));

  let k;

  try {
    k = RSAPrivateKey.decode(key);
  } catch (e) {
    return false;
  }

  return gen.privateVerify(k);
};

/*
 * Helpers
 */

function genKey(total, bits) {
  assert((total >>> 0) === total);
  assert((bits >>> 0) === bits);
  assert(total >= 2);

  const E = 65537;

  if (bits < 64) {
    const primeLimit = Math.pow(2, Math.floor(bits / total));

    let pi = primeLimit / (Math.log(primeLimit) - 1);

    pi /= 4;
    pi /= 2;

    if (pi <= total)
      throw new Error('too few primes');
  }

next:
  for (;;) {
    const primes = [];

    let todo = bits;

    if (total >= 7)
      todo += Math.floor((total - 2) / 5);

    for (let i = 0; i < total; i++) {
      const prime = randPrime(Math.floor(todo / (total - i)));
      todo -= prime.bitLength();
      primes.push(prime);
    }

    for (let i = 0; i < total; i++) {
      const prime = primes[i];
      for (let j = 0; j < i; j++) {
        if (prime.cmp(primes[j]) === 0)
          continue next;
      }
    }

    const n = new BN(1);
    const totient = new BN(1);

    for (const prime of primes) {
      n.imul(prime);
      const pminus1 = prime.subn(1);
      totient.imul(pminus1);
    }

    if (n.bitLength() !== bits)
      continue next;

    const e = new BN(E);
    const D = e.invm(totient);

    const dp = D.mod(primes[0].subn(1));
    const dq = D.mod(primes[1].subn(1));
    const qinv = primes[1].invm(primes[0]);

    const key = new RSAPrivateKey();

    key.n = toBuffer(n);
    key.e = toBuffer(e);
    key.d = toBuffer(D);
    key.p = toBuffer(primes[0]);
    key.q = toBuffer(primes[1]);
    key.dp = toBuffer(dp);
    key.dq = toBuffer(dq);
    key.qi = toBuffer(qinv);

    return [primes, key];
  }
};

function randPrime(bits) {
  assert((bits >>> 0) === bits);
  assert(bits >= 2);

  let b = bits % 8;

  if (b === 0)
    b = 8;

  for (;;) {
    const s = Math.floor((bits + 7) / 8);
    const bytes = random.randomBytes(s);

    bytes[0] &= (1 << b) - 1;

    if (b >= 2) {
      bytes[0] |= 3 << (b - 2);
    } else {
      bytes[1] |= 1;
      if (bytes.length > 1)
        bytes[1] |= 0x80;
    }

    bytes[bytes.length - 1] |= 1;

    const p = new BN(bytes, 'be');
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

    if (probablyPrime(p, 20) && p.bitLength() === bits)
      return p;
  }
}

function probablyPrime(x, n) {
  if (x.isNeg() || x.isZero())
    return false;

  const w = x.words[0];

  if (x.length === 1 && w < 64) {
    if (w > 31)
      return (primeBitMaskHi & (1 << (w - 32))) !== 0;
    return (primeBitMaskLo & (1 << w)) !== 0;
  }

  if ((w & 1) === 0)
    return false;

  const ra = x.mod(primesA).toNumber();
  const rb = x.mod(primesB).toNumber();

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

  return millerRabinPrime(x, n + 1, true) && lucasPrime(x);
}

function millerRabinPrime(n, reps, force2) {
  const nm1 = n.subn(1);
  const k = trailingZeroes(nm1);
  const q = nm1.ushrn(k);

  const nm3 = nm1.subn(2);
  const nm3Len = nm3.bitLength();

  let x = new BN();
  let y = new BN();

next:
  for (let i = 0; i < reps; i++) {
    if (i === reps - 1 && force2) {
      x = new BN(2);
    } else {
      x = randomN(nm3, nm3Len);
      x = x.iaddn(2);
    }

    y = expNN(x, q, n);

    if (y.cmpn(1) === 0 || y.cmp(nm1) === 0)
      continue;

    for (let j = 1; j < k; j++) {
      y = y.isqr();
      // qt = y.div(n);
      y = y.mod(n);

      if (y.cmp(nm1) === 0)
        continue next;

      if (y.cmpn(1) === 0)
        return false;
    }

    return false;
  }

  return true;
}

function lucasPrime(n) {
  return true;
}

function trailingZeroes(n) {
  let t = 0;
  let i;

  for (i = 0; i < n.length; i++) {
    if (n.words[i] !== 0)
      break;
    t += 26;
  }

  if (i === n.length)
    return t;

  let w = n.words[i];

  while ((w & 1) === 0) {
    t += 1;
    w >>>= 1;
  }

  return t;
}

function randomN(limit, bits) {
  const n = limit.clone();

  for (;;) {
    for (let i = 0; i < n.length; i++)
      n.words[i] = (Math.random() * 0x4000000) | 0;

    if (n.cmp(limit) < 0)
      break;
  }

  return n;
}

function expNN(x, y, m) {
  if (m.cmpn(1) === 0)
    return new BN(0);

  if (y.isZero())
    return new BN(1);

  if (y.cmpn(1) === 0 && !m.isZero())
    return x.div(m);

  if (x.cmpn(0) === 0)
    return x.clone();

  if (y.length > 1 && !m.isZero())
    return x.toRed(BN.red(m)).redPow(y).fromRed();

  x = x.pow(y);

  if (m.isZero())
    return x;

  return x.mod(m);
}

function toBuffer(n) {
  return n.toArrayLike(Buffer, 'be');
}
