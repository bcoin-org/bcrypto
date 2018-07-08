/*!
 * rsagen.js - RSA key generation for javascript
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
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

const defaultExponent = 65537;

/**
 * Generate a private key.
 * @param {Number} [bits=2048]
 * @returns {RSAPrivateKey}
 */

gen.generateKey = function generateKey(bits = 2048) {
  assert((bits & 0xffff) === bits);
  assert(bits >= 4 && bits <= 16384, '`bits` must range from 4-16384.');

  const [key] = generateMultiPrime(2, bits, defaultExponent);

  return key;
};

/**
 * Generate a private key.
 * @param {Number} [bits=2048]
 * @returns {RSAPrivateKey}
 */

gen.generateKeyAsync = async function generateKeyAsync(bits = 2048) {
  assert((bits & 0xffff) === bits);
  assert(bits >= 4 && bits <= 16384, '`bits` must range from 4-16384.');

  try {
    return await generateSubtle(bits);
  } catch (e) {
    return gen.generateKey(bits);
  }
};

/**
 * Verify a public key.
 * @param {RSAKey} key
 * @returns {Boolean}
 */

gen.publicVerify = function publicVerify(key) {
  assert(key instanceof RSAKey);
  return key.verify();
};

/**
 * Verify a private key.
 * @param {RSAPrivateKey} key
 * @returns {Boolean}
 */

gen.privateVerify = function privateVerify(key) {
  assert(key instanceof RSAPrivateKey);

  // https://github.com/golang/go/blob/aadaec5/src/crypto/rsa/rsa.go#L169
  if (!gen.publicVerify(key))
    return false;

  const mod = new BN(1);
  const primes = [
    new BN(key.p, 'be'),
    new BN(key.q, 'be')
  ];

  for (const prime of primes) {
    if (prime.cmpn(1) <= 0)
      return false;

    mod.imul(prime);
  }

  const n = new BN(key.n, 'be');

  if (mod.cmp(n) !== 0)
    return false;

  const d = new BN(key.d, 'be');
  const de = new BN(key.e, 'be');

  de.imul(d);

  for (const prime of primes) {
    const cg = de.mod(prime.subn(1));

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

gen.privateKeyGenerate = function privateKeyGenerate(bits) {
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
 * Generate a private key.
 * @param {Number} [bits=2048]
 * @returns {Buffer} Private key.
 */

gen.privateKeyGenerateAsync = async function privateKeyGenerateAsync(bits) {
  const key = await gen.generateKeyAsync(bits);
  return key.encode();
};

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
 * Generation
 */

// https://github.com/golang/go/blob/aadaec5/src/crypto/rsa/rsa.go#L220
// https://github.com/golang/go/blob/aadaec5/src/crypto/rsa/rsa.go#L429
function generateMultiPrime(total, bits, exponent) {
  assert((total >>> 0) === total);
  assert((bits >>> 0) === bits);
  assert((exponent >>> 0) === exponent);

  if (total < 2)
    throw new Error('RSA key requires at least 2 primes.');

  if (bits < 64) {
    let pi = Math.pow(2, Math.floor(bits / total));

    pi /= Math.log(pi) - 1;
    pi /= 4;
    pi /= 2;

    if (pi <= total)
      throw new Error('Too few primes for RSA key.');
  }

next:
  for (;;) {
    const primes = [];

    let todo = bits;

    if (total >= 7)
      todo += Math.floor((total - 2) / 5);

    for (let i = 0; i < total; i++) {
      const size = Math.floor(todo / (total - i));
      const prime = randomPrime(size);

      primes.push(prime);

      todo -= prime.bitLength();
    }

    for (let i = 0; i < total; i++) {
      const prime = primes[i];

      for (let j = 0; j < i; j++) {
        if (prime.cmp(primes[j]) === 0)
          continue next;
      }
    }

    const n = new BN(1);
    const t = new BN(1);

    for (const prime of primes) {
      n.imul(prime);
      t.imul(prime.subn(1));
    }

    if (n.bitLength() !== bits)
      continue next;

    const e = new BN(exponent);
    const d = e.invm(t);
    const p = primes[0];
    const q = primes[1];

    const dp = d.mod(p.subn(1));
    const dq = d.mod(q.subn(1));
    const qi = q.invm(p);

    const key = new RSAPrivateKey();

    key.n = toBuffer(n);
    key.e = toBuffer(e);
    key.d = toBuffer(d);
    key.p = toBuffer(p);
    key.q = toBuffer(q);
    key.dp = toBuffer(dp);
    key.dq = toBuffer(dq);
    key.qi = toBuffer(qi);

    const extra = [];

    for (let i = 2; i < primes.length; i++) {
      const prime = toBuffer(primes[i]);
      extra.push(prime);
    }

    return [key, extra];
  }
}

// https://github.com/golang/go/blob/aadaec5/src/crypto/rand/util.go#L31
function randomPrime(bits) {
  assert((bits >>> 0) === bits);
  assert(bits >= 2);

  let b = bits % 8;

  if (b === 0)
    b = 8;

  const s = Math.floor((bits + 7) / 8);
  const bytes = Buffer.allocUnsafe(s);

  for (;;) {
    random.randomFill(bytes, 0, s);

    bytes[0] &= (1 << b) - 1;

    if (b >= 2) {
      bytes[0] |= 3 << (b - 2);
    } else {
      bytes[0] |= 1;
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
        if (m.modn(prime) === 0 && (bits > 6 || m.cmpn(prime) !== 0))
          continue next;
      }

      if (delta > 0)
        p.iaddn(delta);

      break;
    }

    if (p.bitLength() !== bits)
      continue;

    if (!probablyPrime(p, 20))
      continue;

    return p;
  }
}

// https://github.com/golang/go/blob/aadaec5/src/math/big/prime.go#L26
function probablyPrime(x, n) {
  assert(x);
  assert(n >= 0);

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

  if (!millerRabinPrime2(x, n + 1, true))
    return false;

  if (!lucasPrime(x))
    return false;

  return true;
}

// https://github.com/golang/go/blob/aadaec5/src/math/big/prime.go#L81
function millerRabinPrime(n, reps, force2) {
  const nm1 = n.subn(1);
  const k = trailingZeroes(nm1);
  const q = nm1.ushrn(k);

  const nm3 = nm1.subn(2);
  const nm3Len = nm3.bitLength();

  // Miller-Rabin primality test.
next:
  for (let i = 0; i < reps; i++) {
    let x, y;

    if (i === reps - 1 && force2) {
      x = new BN(2);
    } else {
      x = randomN(nm3, nm3Len);
      x.iaddn(2);
    }

    y = expNN(x, q, n);

    if (y.cmpn(1) === 0 || y.cmp(nm1) === 0)
      continue;

    for (let j = 1; j < k; j++) {
      y.isqr();

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

// https://github.com/indutny/miller-rabin/blob/master/lib/mr.js
function millerRabinPrime2(n, reps, force2) {
  const nm1 = n.subn(1);
  const k = trailingZeroes(nm1);
  const q = nm1.ushrn(k);

  const nm3 = nm1.subn(2);
  const nm3Len = nm3.bitLength();

  const red = BN.mont(n);
  const rnm1 = nm1.toRed(red);
  const rone = new BN(1).toRed(red);

  // Miller-Rabin primality test.
next:
  for (let i = 0; i < reps; i++) {
    let x;

    if (i === reps - 1 && force2) {
      x = new BN(2);
    } else {
      x = randomN(nm3, nm3Len);
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
  // Ignore 0 and 1.
  if (n.isZero() || n.cmpn(1) === 0)
    return false;

  // Two is the only even prime.
  if (n.isEven())
    return n.cmpn(2) === 0;

  // Baillie-OEIS "method C" for choosing D, P, Q.
  // See: https://oeis.org/A217719/a217719.txt.
  let p = 3;

  const d = new BN(1);

  for (;;) {
    if (p > 10000) {
      // Thought to be impossible.
      throw new Error(`Cannot find (D/n) = -1 for ${n.toString(10)}.`);
    }

    // If we exceed 26 bits, we need two
    // words due to the design of bn.js.
    if (p > 8192) {
      const c = p * p - 4;
      d.length = 2;
      d.words[1] = c >>> 26;
      d.words[0] = c & 0x3ffffff;
    } else {
      d.words[0] = p * p - 4;
    }

    const j = jacobi(d, n);

    if (j === -1)
      break;

    if (j === 0)
      return n.cmpn(p + 2) === 0;

    if (p === 40) {
      const t1 = sqrt(n);
      t1.isqr();
      if (t1.cmp(n) === 0)
        return false;
    }

    p += 1;
  }

  // Check for Grantham definition of
  // "extra strong Lucas pseudoprime".
  const s = n.addn(1);
  const r = trailingZeroes(s);
  const nm2 = n.subn(2);

  s.iushrn(r);

  const natP = new BN(p);

  let vk = new BN(2);
  let vk1 = new BN(p);

  for (let i = s.bitLength(); i >= 0; i--) {
    let t1;

    if (s.testn(i)) {
      t1 = vk.mul(vk1);
      t1.iadd(n);
      t1.isub(natP);
      vk = t1.mod(n);
      t1 = vk1.sqr();
      t1.iadd(nm2);
      vk1 = t1.mod(n);
    } else {
      t1 = vk.mul(vk1);
      t1.iadd(n);
      t1.isub(natP);
      vk1 = t1.mod(n);
      t1 = vk.sqr();
      t1.iadd(nm2);
      vk = t1.mod(n);
    }
  }

  if (vk.cmpn(2) === 0 || vk.cmp(nm2) === 0) {
    let t1 = vk.mul(natP);
    let t2 = vk1.ushln(1);

    if (t1.cmp(t2) < 0) {
      const t = t1;
      t1 = t2;
      t2 = t;
    }

    t1.isub(t2);

    const t3 = t1.mod(n);

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
    vk = t1.mod(n);
  }

  return false;
}

// https://github.com/golang/go/blob/aadaec5/src/math/big/int.go#L754
function jacobi(x, y) {
  if (y.isZero() || y.isEven())
    throw new Error('jacobi: `y` must be odd.');

  // See chapter 2, section 2.4:
  // http://yacas.sourceforge.net/Algo.book.pdf
  let a = x.clone();
  let b = y.clone();
  let j = 1;

  if (b.isNeg()) {
    if (a.isNeg())
      j = -1;
    b.ineg();
  }

  for (;;) {
    if (b.cmpn(1) === 0)
      return j;

    if (a.isZero())
      return 0;

    a = a.mod(b);

    if (a.isZero())
      return 0;

    const s = trailingZeroes(a);

    if (s & 1) {
      const bmod8 = b.andln(7);

      if (bmod8 === 3 || bmod8 === 5)
        j = -j;
    }

    const c = a.iushrn(s);

    if (b.andln(3) === 3 && c.andln(3) === 3)
      j = -j;

    a = b;
    b = c;
  }
}

// https://github.com/golang/go/blob/aadaec5/src/math/big/nat.go#L1335
function sqrt(x) {
  if (x.cmpn(1) <= 0)
    return x;

  // See https://members.loria.fr/PZimmermann/mca/pub226.html.
  let z1 = new BN(1);

  z1.iushln((x.bitLength() >>> 1) + 1);

  for (;;) {
    const z2 = x.div(z1);
    z2.iadd(z1);
    z2.iushrn(1);

    if (z2.cmp(z1) >= 0)
      return z1;

    z1 = z2;
  }
}

// https://github.com/golang/go/blob/aadaec5/src/math/big/nat.go#L779
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

  assert(w !== 0);

  while ((w & 1) === 0) {
    t += 1;
    w >>>= 1;
  }

  return t;
}

// https://github.com/golang/go/blob/aadaec5/src/math/big/nat.go#L991
function randomN(limit, n) {
  const size = (n + 7) / 8 | 0;
  const bytes = Buffer.allocUnsafe(size);

  let z, d;

  for (;;) {
    random.randomFill(bytes, 0, size);

    z = new BN(bytes, 'be');
    d = z.bitLength();

    if (d > n)
      z.iushrn(d - n);

    if (z.cmp(limit) < 0)
      break;
  }

  return z;
}

// https://github.com/golang/go/blob/aadaec5/src/math/big/nat.go#L1027
function expNN(x, y, m) {
  if (m.cmpn(1) === 0)
    return new BN(0);

  if (y.isZero())
    return new BN(1);

  if (y.cmpn(1) === 0 && !m.isZero())
    return x.div(m);

  if (x.isZero())
    return x.clone();

  if (!m.isZero())
    return x.toRed(BN.mont(m)).redPow(y).fromRed();

  return x.pow(y);
}

/*
 * Subtle
 */

async function generateSubtle(bits) {
  const crypto = global.crypto || global.msCrypto;

  if (!crypto)
    throw new Error('Crypto API not available.');

  const subtle = crypto.subtle;

  if (!subtle)
    throw new Error('Subtle API not available.');

  if (!subtle.generateKey || !subtle.exportKey)
    throw new Error('Subtle key generation not available.');

  const exp = new Uint8Array(3);
  exp[0] = defaultExponent >>> 16;
  exp[1] = defaultExponent >>> 8;
  exp[2] = defaultExponent;

  const algo = {
    name: 'RSASSA-PKCS1-v1_5',
    modulusLength: bits,
    publicExponent: exp,
    hash: { name: 'SHA-256' }
  };

  const ck = await subtle.generateKey(algo, true, ['sign']);
  const jwk = await subtle.exportKey('jwk', ck.privateKey);

  return RSAPrivateKey.fromJSON(jwk);
}

/*
 * Helpers
 */

function toBuffer(n) {
  return n.toArrayLike(Buffer, 'be');
}

// Make eslint happy.
millerRabinPrime;
