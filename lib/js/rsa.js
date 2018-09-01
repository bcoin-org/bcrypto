/*!
 * rsa.js - RSA for javascript
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
 *   https://golang.org/src/crypto/rsa/pkcs1v15.go
 *   https://github.com/golang/go/blob/master/src/crypto/rsa/rsa.go
 *   https://github.com/golang/go/blob/master/src/math/big/prime.go
 *   https://github.com/golang/go/blob/master/src/math/big/int.go
 *   https://github.com/golang/go/blob/master/src/math/big/nat.go
 *   https://github.com/golang/go/blob/master/src/crypto/rand/util.go
 *   https://github.com/indutny/miller-rabin/blob/master/lib/mr.js
 */

'use strict';

const assert = require('bsert');
const BN = require('../../vendor/bn.js');
const rsakey = require('../internal/rsakey')(exports);
const {randomPrime} = require('../internal/primes');
const {countBits} = require('../internal/util');
const safeEqual = require('../safe-equal');
const rsa = exports;

const {
  RSAKey,
  RSAPrivateKey,
  RSAPublicKey,
  DEFAULT_BITS,
  DEFAULT_EXP,
  MIN_BITS,
  MAX_BITS,
  MIN_EXP,
  MAX_EXP,
  MIN_EXP_BITS,
  MAX_EXP_BITS
} = rsakey;

/**
 * PKCS signature prefixes.
 * @type {Object}
 */

const prefixes = {
  md5: Buffer.from('3020300c06082a864886f70d020505000410', 'hex'),
  ripemd160: Buffer.from('30203008060628cf060300310414', 'hex'),
  sha1: Buffer.from('3021300906052b0e03021a05000414', 'hex'),
  sha224: Buffer.from('302d300d06096086480165030402040500041c', 'hex'),
  sha256: Buffer.from('3031300d060960864801650304020105000420', 'hex'),
  sha384: Buffer.from('3041300d060960864801650304020205000430', 'hex'),
  sha512: Buffer.from('3051300d060960864801650304020305000440', 'hex'),
  // https://tools.ietf.org/html/draft-jivsov-openpgp-sha3-01
  keccak256: Buffer.from('3031300d060960864801650304020805000420', 'hex'),
  keccak384: Buffer.from('3041300d060960864801650304020905000430', 'hex'),
  keccak512: Buffer.from('3051300d060960864801650304020a05000440', 'hex'),
  'sha3-256': Buffer.from('3031300d060960864801650304020805000420', 'hex'),
  'sha3-384': Buffer.from('3041300d060960864801650304020905000430', 'hex'),
  'sha3-512': Buffer.from('3051300d060960864801650304020a05000440', 'hex')
};

/**
 * Whether the backend is a binding.
 * @const {Number}
 */

rsa.native = 0;

/**
 * RSAPrivateKey
 */

rsa.RSAPrivateKey = RSAPrivateKey;

/**
 * RSAPublicKey
 */

rsa.RSAPublicKey = RSAPublicKey;

/**
 * Generate a private key.
 * @param {Number} [bits=2048]
 * @param {Number} [exponent=65537]
 * @returns {RSAPrivateKey} Private key.
 */

rsa.privateKeyGenerate = function privateKeyGenerate(bits, exponent) {
  if (bits == null)
    bits = DEFAULT_BITS;

  if (exponent == null)
    exponent = DEFAULT_EXP;

  assert((bits >>> 0) === bits);
  assert(Number.isSafeInteger(exponent) && exponent >= 0);

  if (bits < MIN_BITS || bits > MAX_BITS)
    throw new RangeError(`"bits" ranges from ${MIN_BITS} to ${MAX_BITS}.`);

  if (exponent < MIN_EXP || exponent > MAX_EXP)
    throw new RangeError(`"exponent" ranges from ${MIN_EXP} to ${MAX_EXP}.`);

  if (exponent === 1 || (exponent % 2) === 0)
    throw new RangeError('"exponent" must be odd.');

  const [key] = generate(2, bits, exponent);

  return key;
};

/**
 * Generate a private key.
 * @param {Number} [bits=2048]
 * @param {Number} [exponent=65537]
 * @returns {RSAPrivateKey} Private key.
 */

rsa.privateKeyGenerateAsync = async function privateKeyGenerateAsync(bits, exponent) {
  if (bits == null)
    bits = DEFAULT_BITS;

  if (exponent == null)
    exponent = DEFAULT_EXP;

  assert((bits >>> 0) === bits);
  assert(Number.isSafeInteger(exponent) && exponent >= 0);

  if (bits < MIN_BITS || bits > MAX_BITS)
    throw new RangeError(`"bits" ranges from ${MIN_BITS} to ${MAX_BITS}.`);

  if (exponent < MIN_EXP || exponent > MAX_EXP)
    throw new RangeError(`"exponent" ranges from ${MIN_EXP} to ${MAX_EXP}.`);

  if (exponent === 1 || (exponent % 2) === 0)
    throw new RangeError('"exponent" must be odd.');

  try {
    return await generateSubtle(bits, exponent);
  } catch (e) {
    return rsa.privateKeyGenerate(bits, exponent);
  }
};

/**
 * Create a public key.
 * @param {RSAPrivateKey} key
 * @returns {RSAPublicKey}
 */

rsa.publicKeyCreate = function publicKeyCreate(key) {
  assert(key instanceof RSAPrivateKey);
  return key.toPublic();
};

/**
 * Verify a public key.
 * @param {RSAKey} key
 * @returns {Boolean}
 */

rsa.publicKeyVerify = function publicKeyVerify(key) {
  assert(key instanceof RSAPublicKey);
  return key.validate();
};

/**
 * Verify a private key.
 * @param {RSAPrivateKey} key
 * @returns {Boolean}
 */

rsa.privateKeyVerify = function privateKeyVerify(key) {
  assert(key instanceof RSAPrivateKey);

  key.compute();

  // https://github.com/golang/go/blob/aadaec5/src/crypto/rsa/rsa.go#L169
  if (!key.toPublic().validate())
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
 * Sign a message.
 * @param {Object|String} hash
 * @param {Buffer} msg
 * @param {RSAPrivateKey} key - Private key.
 * @returns {Buffer} PKCS#1v1.5-formatted signature.
 */

rsa.sign = function sign(hash, msg, key) {
  if (hash && typeof hash.id === 'string')
    hash = hash.id;

  assert(typeof hash === 'string', 'No algorithm selected.');
  assert(Buffer.isBuffer(msg));
  assert(key instanceof RSAPrivateKey);

  key.compute();

  const prefix = prefixes[hash];

  if (!Buffer.isBuffer(prefix))
    throw new Error('Unknown PKCS prefix.');

  const h = msg;
  const len = prefix.length + h.length;

  const n = new BN(key.n, 'be');
  const d = new BN(key.d, 'be');
  const k = Math.ceil(n.bitLength() / 8);

  if (k < len + 11)
    throw new Error('Message too long.');

  const em = Buffer.alloc(k, 0x00);

  em[1] = 0x01;

  for (let i = 2; i < k - len - 1; i++)
    em[i] = 0xff;

  prefix.copy(em, k - len);
  h.copy(em, k - h.length);

  return decrypt(n, d, em);
};

/**
 * Verify a signature.
 * @param {Object|String} hash
 * @param {Buffer} msg
 * @param {Buffer} sig - PKCS#1v1.5-formatted.
 * @param {RSAPublicKey} key
 * @returns {Boolean}
 */

rsa.verify = function verify(hash, msg, sig, key) {
  if (hash && typeof hash.id === 'string')
    hash = hash.id;

  assert(typeof hash === 'string', 'No algorithm selected.');
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(sig));
  assert(key instanceof RSAKey);

  if (key instanceof RSAPrivateKey)
    key.compute();

  try {
    return rsa._verify(hash, msg, sig, key);
  } catch (e) {
    return false;
  }
};

/**
 * Verify a signature.
 * @param {String} hash
 * @param {Buffer} msg
 * @param {Buffer} sig - PKCS#1v1.5-formatted.
 * @param {RSAPublicKey} key
 * @returns {Boolean}
 */

rsa._verify = function _verify(hash, msg, sig, key) {
  const prefix = prefixes[hash];

  if (!Buffer.isBuffer(prefix))
    throw new Error('Unknown PKCS prefix.');

  const h = msg;
  const len = prefix.length + h.length;

  const n = new BN(key.n, 'be');
  const e = new BN(key.e, 'be');
  const k = Math.ceil(n.bitLength() / 8);

  if (k < len + 11)
    throw new Error('Message too long.');

  const m = encrypt(n, e, sig);
  const em = leftPad(m, k);

  let ok = safeEqualByte(em[0], 0x00);
  ok &= safeEqualByte(em[1], 0x01);
  ok &= safeEqual(em.slice(k - h.length, k), h);
  ok &= safeEqual(em.slice(k - len, k - h.length), prefix);
  ok &= safeEqualByte(em[k - len - 1], 0x00);

  for (let i = 2; i < k - len - 1; i++)
    ok &= safeEqualByte(em[i], 0xff);

  return ok === 1;
};

/**
 * Pre-compute a private key.
 * @param {RSAPrivateKey}
 */

rsa.compute = function compute(key) {
  assert(key instanceof RSAPrivateKey);

  if (countBits(key.n) !== 0
      && countBits(key.d) !== 0
      && countBits(key.dp) !== 0
      && countBits(key.dq) !== 0
      && countBits(key.qi) !== 0) {
    return;
  }

  const eb = countBits(key.e);
  const nb = countBits(key.p) + countBits(key.q);

  if (eb < MIN_EXP_BITS || eb > MAX_EXP_BITS)
    throw new Error('Invalid exponent.');

  if (nb < eb || nb < MIN_BITS || nb > MAX_BITS)
    throw new Error('Invalid primes.');

  const e = new BN(key.e);
  const p = new BN(key.p);
  const q = new BN(key.q);

  if (e.cmpn(3) < 0 || e.isEven())
    throw new Error('Invalid exponent.');

  let n = new BN(key.n);
  let d = new BN(key.d);
  let dp = new BN(key.dp);
  let dq = new BN(key.dq);
  let qi = new BN(key.qi);

  if (n.bitLength() === 0)
    n = p.mul(q);

  if (d.bitLength() === 0) {
    const t = p.subn(1).imul(q.subn(1));
    d = e.invm(t);
  }

  if (dp.bitLength() === 0)
    dp = d.mod(p.subn(1));

  if (dq.bitLength() === 0)
    dq = d.mod(q.subn(1));

  if (qi.bitLength() === 0)
    qi = q.invm(p);

  key.n = toBuffer(n);
  key.d = toBuffer(d);
  key.dp = toBuffer(dp);
  key.dq = toBuffer(dq);
  key.qi = toBuffer(qi);
};

/*
 * Generation
 */

// https://github.com/golang/go/blob/aadaec5/src/crypto/rsa/rsa.go#L220
// https://github.com/golang/go/blob/aadaec5/src/crypto/rsa/rsa.go#L429
function generate(total, bits, exponent) {
  assert((total >>> 0) === total);
  assert((bits >>> 0) === bits);
  assert(Number.isSafeInteger(exponent) && exponent >= 0);
  assert(bits >= 4);
  assert(exponent >= 3 && (exponent % 2) !== 0);

  if (total < 2)
    throw new Error('RSA key requires at least 2 primes.');

  if (bits < 64) {
    let pi = 2 ** Math.floor(bits / total);

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

/*
 * Subtle
 */

async function generateSubtle(bits, exponent) {
  assert((bits >>> 0) === bits);
  assert(Number.isSafeInteger(exponent) && exponent >= 0);
  assert(bits >= 4);
  assert(exponent >= 3 && (exponent % 2) !== 0);

  const crypto = global.crypto || global.msCrypto;

  if (!crypto)
    throw new Error('Crypto API not available.');

  const subtle = crypto.subtle;

  if (!subtle)
    throw new Error('Subtle API not available.');

  if (!subtle.generateKey || !subtle.exportKey)
    throw new Error('Subtle key generation not available.');

  const hi = (exponent * (1 / 0x100000000)) >>> 0;
  const lo = exponent >>> 0;

  const exp = new Uint8Array(8);
  exp[0] = 0;
  exp[1] = 0;
  exp[2] = hi >>> 8;
  exp[3] = hi;
  exp[4] = lo >>> 24;
  exp[5] = lo >>> 16;
  exp[6] = lo >>> 8;
  exp[7] = lo;

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

function decrypt(n, d, m) {
  const c = new BN(m);

  if (c.cmp(n) > 0)
    throw new Error('Cannot decrypt.');

  return c
    .toRed(BN.mont(n))
    .redPow(d)
    .fromRed()
    .toArrayLike(Buffer, 'be');
}

function encrypt(n, e, m) {
  return new BN(m)
    .toRed(BN.mont(n))
    .redPow(e)
    .fromRed()
    .toArrayLike(Buffer, 'be');
}

function leftPad(input, size) {
  let n = input.length;

  if (n > size)
    n = size;

  const out = Buffer.allocUnsafe(size);

  out.fill(0x00, 0, out.length - n);
  input.copy(out, out.length - n);

  return out;
}

function safeEqualByte(a, b) {
  let r = ~(a ^ b) & 0xff;
  r &= r >>> 4;
  r &= r >>> 2;
  r &= r >>> 1;
  return r === 1;
}

function toBuffer(n) {
  return n.toArrayLike(Buffer, 'be');
}
