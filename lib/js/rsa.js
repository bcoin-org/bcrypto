/*!
 * rsa.js - RSA for javascript
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
 *   https://golang.org/src/crypto/rsa/pkcs1v15.go
 *   https://github.com/golang/go/blob/master/src/crypto/rsa/rsa.go
 *   https://github.com/golang/go/blob/master/src/math/big/prime.go
 *   https://github.com/golang/go/blob/master/src/math/big/int.go
 *   https://github.com/golang/go/blob/master/src/math/big/nat.go
 *   https://github.com/golang/go/blob/master/src/crypto/rand/util.go
 *   https://github.com/indutny/miller-rabin/blob/master/lib/mr.js
 *   https://github.com/golang/go/blob/master/src/crypto/rsa/pkcs1v15.go
 *   https://github.com/golang/go/blob/master/src/crypto/subtle/constant_time.go
 */

'use strict';

const assert = require('bsert');
const BN = require('../../vendor/bn.js');
const rsakey = require('../internal/rsakey');
const random = require('../random');
const {randomPrime, randomInt} = require('../internal/primes');
const {countBits} = require('../internal/util');
const base64 = require('../internal/base64');
const pkcs1 = require('../encoding/pkcs1');
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

const EMPTY = Buffer.alloc(0);

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
  sha512: Buffer.from('3051300d060960864801650304020305000440', 'hex')
  // https://tools.ietf.org/html/draft-jivsov-openpgp-sha3-01
  // keccak256: Buffer.from('3031300d060960864801650304020805000420', 'hex'),
  // keccak384: Buffer.from('3041300d060960864801650304020905000430', 'hex'),
  // keccak512: Buffer.from('3051300d060960864801650304020a05000440', 'hex'),
  // 'sha3-256': Buffer.from('3031300d060960864801650304020805000420', 'hex'),
  // 'sha3-384': Buffer.from('3041300d060960864801650304020905000430', 'hex'),
  // 'sha3-512': Buffer.from('3051300d060960864801650304020a05000440', 'hex')
};

/**
 * Whether the backend is a binding.
 * @const {Number}
 */

rsa.native = 0;

/**
 * RSAKey
 */

rsa.RSAKey = RSAKey;

/**
 * RSAPublicKey
 */

rsa.RSAPublicKey = RSAPublicKey;

/**
 * RSAPrivateKey
 */

rsa.RSAPrivateKey = RSAPrivateKey;

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

  const [key] = generateKey(2, bits, exponent);

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
 * Pre-compute a private key.
 * @param {RSAPrivateKey}
 */

rsa.privateKeyCompute = function privateKeyCompute(key) {
  assert(key instanceof RSAPrivateKey);

  if (!isSaneCompute(key))
    throw new Error('Invalid RSA private key.');

  if (!needsCompute(key))
    return;

  const p = new BN(key.p);
  const q = new BN(key.q);

  let n = new BN(key.n);
  let e = new BN(key.e);
  let d = new BN(key.d);
  let dp = new BN(key.dp);
  let dq = new BN(key.dq);
  let qi = new BN(key.qi);

  if (n.bitLength() === 0) {
    n = p.mul(q);
    key.n = toBuffer(n);
  }

  if (e.bitLength() === 0) {
    const t = p.subn(1).imul(q.subn(1));
    e = d.invm(t);
    key.e = toBuffer(e);
  }

  if (d.bitLength() === 0) {
    const t = p.subn(1).imul(q.subn(1));
    d = e.invm(t);
    key.d = toBuffer(d);
  }

  if (dp.bitLength() === 0) {
    dp = d.mod(p.subn(1));
    key.dp = toBuffer(dp);
  }

  if (dq.bitLength() === 0) {
    dq = d.mod(q.subn(1));
    key.dq = toBuffer(dq);
  }

  if (qi.bitLength() === 0) {
    qi = q.invm(p);
    key.qi = toBuffer(qi);
  }
};

/**
 * Verify a private key.
 * @param {RSAPrivateKey} key
 * @returns {Boolean}
 */

rsa.privateKeyVerify = function privateKeyVerify(key) {
  assert(key instanceof RSAPrivateKey);

  if (!isSanePrivateKey(key))
    return false;

  // https://github.com/golang/go/blob/aadaec5/src/crypto/rsa/rsa.go#L169
  const mod = new BN(1);
  const primes = [
    new BN(key.p),
    new BN(key.q)
  ];

  for (const prime of primes) {
    if (prime.cmpn(1) <= 0)
      return false;

    mod.imul(prime);
  }

  const n = new BN(key.n);

  if (mod.cmp(n) !== 0)
    return false;

  const d = new BN(key.d);
  const de = new BN(key.e);

  de.imul(d);

  for (const prime of primes) {
    const cg = de.mod(prime.subn(1));

    if (cg.cmpn(1) !== 0)
      return false;
  }

  return true;
};

/**
 * Export a private key to PKCS1 ASN.1 format.
 * @param {RSAPrivateKey} key
 * @returns {Buffer}
 */

rsa.privateKeyExport = function privateKeyExport(key) {
  assert(key instanceof RSAPrivateKey);

  if (!isSanePrivateKey(key))
    throw new Error('Invalid RSA private key.');

  return new pkcs1.RSAPrivateKey(
    0,
    key.n,
    key.e,
    key.d,
    key.p,
    key.q,
    key.dp,
    key.dq,
    key.qi
  ).encode();
};

/**
 * Import a private key from PKCS1 ASN.1 format.
 * @param {Buffer} raw
 * @returns {RSAPrivateKey}
 */

rsa.privateKeyImport = function privateKeyImport(raw) {
  const key = pkcs1.RSAPrivateKey.decode(raw);

  assert(key.version.toNumber() === 0);

  return new RSAPrivateKey(
    key.n.value,
    key.e.value,
    key.d.value,
    key.p.value,
    key.q.value,
    key.dp.value,
    key.dq.value,
    key.qi.value
  );
};

/**
 * Create a public key from a private key.
 * @param {RSAPrivateKey} key
 * @returns {RSAPublicKey}
 */

rsa.publicKeyCreate = function publicKeyCreate(key) {
  assert(key instanceof RSAPrivateKey);

  const pub = new RSAPublicKey();

  pub.n = key.n;
  pub.e = key.e;

  return pub;
};

/**
 * Verify a public key.
 * @param {RSAKey} key
 * @returns {Boolean}
 */

rsa.publicKeyVerify = function publicKeyVerify(key) {
  assert(key instanceof RSAKey);
  return isSanePublicKey(key);
};

/**
 * Export a public key to PKCS1 ASN.1 format.
 * @param {RSAKey} key
 * @returns {Buffer}
 */

rsa.publicKeyExport = function publicKeyExport(key) {
  assert(key instanceof RSAKey);

  if (!isSanePublicKey(key))
    throw new Error('Invalid RSA public key.');

  return new pkcs1.RSAPublicKey(key.n, key.e).encode();
};

/**
 * Import a public key from PKCS1 ASN.1 format.
 * @param {Buffer} raw
 * @returns {RSAPublicKey}
 */

rsa.publicKeyImport = function publicKeyImport(raw) {
  const key = pkcs1.RSAPublicKey.decode(raw);
  return new RSAPublicKey(key.n.value, key.e.value);
};

/**
 * Sign a message (PKCS1v1.5).
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

  if (!prefixes.hasOwnProperty(hash))
    throw new Error('Unknown PKCS1v1.5 padding.');

  if (msg.length < 1 || msg.length > 64)
    throw new Error('Invalid RSA message size.');

  if (!isSanePrivateKey(key))
    throw new Error('Invalid RSA private key.');

  const prefix = prefixes[hash];
  const h = msg;
  const len = prefix.length + h.length;
  const k = key.size();

  if (k < len + 11)
    throw new Error('Message too long.');

  const em = Buffer.alloc(k, 0x00);

  em[1] = 0x01;

  for (let i = 2; i < k - len - 1; i++)
    em[i] = 0xff;

  prefix.copy(em, k - len);
  h.copy(em, k - h.length);

  return decrypt(key, em);
};

/**
 * Verify a signature (PKCS1v1.5).
 * @param {Object|String} hash
 * @param {Buffer} msg
 * @param {Buffer} sig - PKCS#1v1.5-formatted.
 * @param {RSAKey} key
 * @returns {Boolean}
 */

rsa.verify = function verify(hash, msg, sig, key) {
  if (hash && typeof hash.id === 'string')
    hash = hash.id;

  assert(typeof hash === 'string', 'No algorithm selected.');
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(sig));
  assert(key instanceof RSAKey);

  if (!prefixes.hasOwnProperty(hash))
    return false;

  if (msg.length < 1 || msg.length > 64)
    return false;

  if (sig.length < 1 || sig.length > 3072)
    return false;

  if (!isSanePublicKey(key))
    return false;

  const prefix = prefixes[hash];
  const h = msg;
  const len = prefix.length + h.length;
  const k = key.size();

  if (k < len + 11)
    return false;

  const m = encrypt(key, sig);
  const em = leftPad(m, k);

  let ok = 1;

  ok &= safeEqualByte(em[0], 0x00);
  ok &= safeEqualByte(em[1], 0x01);
  ok &= safeEqual(em.slice(k - h.length, k), h);
  ok &= safeEqual(em.slice(k - len, k - h.length), prefix);
  ok &= safeEqualByte(em[k - len - 1], 0x00);

  for (let i = 2; i < k - len - 1; i++)
    ok &= safeEqualByte(em[i], 0xff);

  return ok === 1;
};

/**
 * Encrypt a message with public key (PKCS1v1.5).
 * @param {Buffer} msg
 * @param {RSAKey} key
 * @returns {Buffer}
 */

// eslint-disable-next-line func-name-matching
rsa.encrypt = function _encrypt(msg, key) {
  assert(Buffer.isBuffer(msg));
  assert(key instanceof RSAKey);

  if (msg.length < 1)
    throw new Error('Invalid RSA message size.');

  if (!isSanePublicKey(key))
    throw new Error('Invalid RSA public key.');

  const k = key.size();

  if (msg.length > k - 11)
    throw new Error('Invalid RSA message size.');

  const em = Buffer.alloc(k);
  em[1] = 0x02;

  const ps = em.slice(2, em.length - msg.length - 1);
  const mm = em.slice(em.length - msg.length);

  randomNonzero(ps, 0, ps.length);

  em[em.length - msg.length - 1] = 0x00;

  msg.copy(mm, 0);

  const c = encrypt(key, em);

  copyLeftPad(em, c);

  return em;
};

/**
 * Decrypt a message with private key (PKCS1v1.5).
 * @param {Buffer} msg
 * @param {RSAPrivateKey} key
 * @returns {Buffer}
 */

rsa.decrypt = function decrypt(msg, key) {
  assert(Buffer.isBuffer(msg));
  assert(key instanceof RSAPrivateKey);

  const [valid, out, index] = rsa._decrypt(msg, key);

  if (valid === 0)
    throw new Error('Invalid ciphertext.');

  return out.slice(index);
};

/**
 * Decrypt a session key with private key (PKCS1v1.5).
 * @param {Buffer} msg
 * @param {Buffer} out
 * @param {RSAPrivateKey} key
 * @returns {Buffer}
 */

rsa.decryptKey = function decryptKey(msg, out, key) {
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(out));
  assert(key instanceof RSAPrivateKey);

  const k = key.size();

  if (k - (out.length + 3 + 8) < 0)
    throw new Error('Invalid session key size.');

  let [valid, em, index] = rsa._decrypt(msg, key);

  if (em.length !== k)
    throw new Error('Invalid ciphertext.');

  valid &= safeEqualInt(em.length - index, out.length);

  safeCopy(valid, out, em.slice(em.length - out.length));
};

/**
 * Decrypt a message with private key (PKCS1v1.5).
 * @param {Buffer} msg
 * @param {RSAPrivateKey} key
 * @returns {Buffer}
 */

rsa._decrypt = function _decrypt(msg, key) {
  assert(Buffer.isBuffer(msg));
  assert(key instanceof RSAPrivateKey);

  if (msg.length < 1)
    throw new Error('Invalid RSA message size.');

  if (!isSanePrivateKey(key))
    throw new Error('Invalid RSA private key.');

  const k = key.size();

  if (k < 11)
    throw new Error('Invalid RSA private key.');

  const m = decrypt(key, msg);

  const em = leftPad(m, k);
  const fbiz = safeEqualByte(em[0], 0x00);
  const sbit = safeEqualByte(em[1], 0x02);

  let index = 0;
  let lookingFor = 1;

  for (let i = 2; i < em.length; i++) {
    const equals0 = safeEqualByte(em[i], 0x00);

    index = safeSelect(lookingFor & equals0, i, index);
    lookingFor = safeSelect(equals0, 0, lookingFor);
  }

  const validPS = safeLTE(2 + 8, index);
  const valid = ((fbiz & sbit) & (~lookingFor & 1)) & validPS;

  index = safeSelect(valid, index + 1, 0);

  return [valid, em, index];
};

/**
 * Encrypt a message with public key (OAEP).
 * @param {Object} hash
 * @param {Buffer} msg
 * @param {Buffer} label
 * @param {RSAKey} key
 * @returns {Buffer}
 */

rsa.encryptOAEP = function encryptOAEP(hash, msg, label, key) {
  if (label == null)
    label = EMPTY;

  assert(hash && typeof hash.id === 'string');
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(label));
  assert(key instanceof RSAKey);
  assert(hash.id === 'sha1');
  assert(label.length === 0);

  if (msg.length < 1)
    throw new Error('Invalid RSA message size.');

  if (!isSanePublicKey(key))
    throw new Error('Invalid RSA public key.');

  const ctx = hash.ctx;
  const k = key.size();

  if (msg.length > k - 2 * hash.size - 2)
    throw new Error('Invalid RSA message size.');

  ctx.init();
  ctx.update(label);

  const lhash = ctx.final();

  const em = Buffer.alloc(k);
  const seed = em.slice(1, 1 + hash.size);
  const db = em.slice(1 + hash.size);

  lhash.copy(db, 0);
  db[db.length - msg.length - 1] = 0x01;
  msg.copy(db, db.length - msg.length);

  random.randomFill(seed, 0, seed.length);

  mgf1XOR(hash, seed, db);
  mgf1XOR(hash, db, seed);

  const c = encrypt(key, em);

  let out = c;

  if (out.length < k) {
    const t = Buffer.alloc(k);
    out.copy(t, k - out.length);
    out = t;
  }

  return out;
};

/**
 * Decrypt a message with private key (OAEP).
 * @param {Object} hash
 * @param {Buffer} msg
 * @param {Buffer} label
 * @param {RSAPrivateKey} key
 * @returns {Buffer}
 */

rsa.decryptOAEP = function decryptOAEP(hash, msg, label, key) {
  if (label == null)
    label = EMPTY;

  assert(hash && typeof hash.id === 'string');
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(label));
  assert(key instanceof RSAPrivateKey);
  assert(hash.id === 'sha1');
  assert(label.length === 0);

  if (msg.length < 1)
    throw new Error('Invalid RSA message size.');

  if (!isSanePrivateKey(key))
    throw new Error('Invalid RSA private key.');

  const k = key.size();
  const ctx = hash.ctx;

  if (msg.length > k || k < hash.size * 2 + 2)
    throw new Error('Invalid RSA message size.');

  const m = decrypt(key, msg);

  ctx.init();
  ctx.update(label);

  const lhash = ctx.final();

  const em = leftPad(m, k);
  const fbiz = safeEqualByte(em[0], 0x00);
  const seed = em.slice(1, hash.size + 1);
  const db = em.slice(hash.size + 1);

  mgf1XOR(hash, db, seed);
  mgf1XOR(hash, seed, db);

  const lhash2 = db.slice(0, hash.size);
  const lhash2Good = safeEqual(lhash, lhash2);

  let lookingFor = 1;
  let index = 0;
  let invalid = 0;

  const rest = db.slice(hash.size);

  for (let i = 0; i < rest.length; i++) {
    const equals0 = safeEqualByte(rest[i], 0x00);
    const equals1 = safeEqualByte(rest[i], 0x01);

    index = safeSelect(lookingFor & equals1, i, index);
    lookingFor = safeSelect(equals1, 0, lookingFor);
    invalid = safeSelect(lookingFor & ~equals0, 1, invalid);
  }

  if ((((fbiz & lhash2Good) & ~invalid) & ~lookingFor) !== 1)
    throw new Error('Invalid ciphertext.');

  return rest.slice(index + 1);
};

/*
 * Generation
 */

// https://github.com/golang/go/blob/aadaec5/src/crypto/rsa/rsa.go#L220
// https://github.com/golang/go/blob/aadaec5/src/crypto/rsa/rsa.go#L429
function generateKey(total, bits, exponent) {
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
  const key = new RSAPrivateKey();

  key.n = base64.decodeURL(jwk.n);
  key.e = base64.decodeURL(jwk.e);
  key.d = base64.decodeURL(jwk.d);
  key.p = base64.decodeURL(jwk.p);
  key.q = base64.decodeURL(jwk.q);
  key.dp = base64.decodeURL(jwk.dp);
  key.dq = base64.decodeURL(jwk.dq);
  key.qi = base64.decodeURL(jwk.qi);

  return key;
}

/*
 * Sanity Checking
 */

function isSanePublicKey(key) {
  const nb = countBits(key.n);

  if (nb < MIN_BITS || nb > MAX_BITS)
    return false;

  const eb = countBits(key.e);

  if (eb < MIN_EXP_BITS || eb > MAX_EXP_BITS)
    return false;

  if ((key.e[key.e.length - 1] & 1) === 0)
    return false;

  return true;
}

function isSanePrivateKey(key) {
  if (!isSanePublicKey(key))
    return false;

  const nb = countBits(key.n);
  const db = countBits(key.d);

  if (db === 0 || db > nb)
    return false;

  const pb = countBits(key.p);
  const qb = countBits(key.q);

  if (pb + qb !== nb)
    return false;

  const dpb = countBits(key.dp);

  if (dpb === 0 || dpb > pb)
    return false;

  const dqb = countBits(key.dq);

  if (dqb === 0 || dqb > qb)
    return false;

  const qib = countBits(key.qi);

  if (qib === 0 || qib > pb)
    return false;

  return true;
}

function isSaneCompute(key) {
  const nb = countBits(key.n);
  const eb = countBits(key.e);
  const db = countBits(key.d);
  const pb = countBits(key.p);
  const qb = countBits(key.q);
  const dpb = countBits(key.dp);
  const dqb = countBits(key.dq);
  const qib = countBits(key.qi);

  if (pb === 0 || qb === 0)
    return false;

  if (eb === 0 && db === 0)
    return false;

  if (nb !== 0) {
    if (nb < MIN_BITS || nb > MAX_BITS)
      return false;

    if (pb + qb !== nb)
      return false;
  }

  if (eb !== 0) {
    if (eb < MIN_EXP_BITS || eb > MAX_EXP_BITS)
      return false;

    if ((key.e[key.e.length - 1] & 1) === 0)
      return false;
  }

  if (db !== 0) {
    if (db > pb + qb)
      return false;
  }

  if (dpb !== 0) {
    if (dpb > pb)
      return false;
  }

  if (dqb !== 0) {
    if (dqb > qb)
      return false;
  }

  if (qib !== 0) {
    if (qib > pb)
      return false;
  }

  return true;
}

function needsCompute(key) {
  return countBits(key.n) === 0
      || countBits(key.e) === 0
      || countBits(key.d) === 0
      || countBits(key.dp) === 0
      || countBits(key.dq) === 0
      || countBits(key.qi) === 0;
}

/*
 * Helpers
 */

function decrypt(key, msg) {
  assert(key instanceof RSAPrivateKey);
  assert(Buffer.isBuffer(msg));

  if (countBits(msg) > countBits(key.n))
    throw new Error('Invalid RSA message size.');

  const n = new BN(key.n);
  const d = new BN(key.d);

  let c = new BN(msg);

  if (c.cmp(n) > 0 || n.isZero())
    throw new Error('Invalid RSA message size.');

  let inv = null;

  // Generate blinding factor.
  if (countBits(key.e) > 0) {
    const e = new BN(key.e);
    const r = randomInt(n);

    if (r.isZero())
      r.iaddn(1);

    inv = r.invm(n);
    c.imul(modPow(r, e, n));
    c = c.mod(n);
  }

  let m = null;

  // Potentially use precomputed values.
  if (needsCompute(key)) {
    m = modPow(c, d, n);
  } else {
    const p = new BN(key.p);
    const q = new BN(key.q);
    const dp = new BN(key.dp);
    const dq = new BN(key.dq);
    const qi = new BN(key.qi);

    const m1 = modPow(c, dp, p);
    const m2 = modPow(c, dq, q);

    m = m1.isub(m2);

    if (m.isNeg())
      m.iadd(p);

    m.imul(qi);
    m = m.mod(p);
    m.imul(q);
    m.iadd(m2);
  }

  // Unblind.
  if (inv) {
    m.imul(inv);
    m = m.mod(n);
  }

  return toBuffer(m);
}

function encrypt(key, msg) {
  assert(key instanceof RSAKey);
  assert(Buffer.isBuffer(msg));

  const n = new BN(key.n);
  const e = new BN(key.e);
  const m = new BN(msg);
  const c = modPow(m, e, n);

  return toBuffer(c);
}

function modPow(x, y, m) {
  return x.toRed(BN.red(m)).redPow(y).fromRed();
}

function leftPad(input, size) {
  assert(Buffer.isBuffer(input));
  assert((size >>> 0) === size);

  let n = input.length;

  if (n > size)
    n = size;

  const out = Buffer.allocUnsafe(size);

  out.fill(0x00, 0, out.length - n);
  input.copy(out, out.length - n);

  return out;
}

function safeEqual(x, y) {
  assert(Buffer.isBuffer(x));
  assert(Buffer.isBuffer(y));

  if (x.length !== y.length)
    return 0;

  let v = 0;

  for (let i = 0; i < x.length; i++)
    v |= x[i] ^ y[i];

  return safeEqualByte(v, 0);
}

function safeEqualByte(x, y) {
  return safeEqualInt(x & 0xff, y & 0xff);
}

function safeEqualInt(x, y) {
  return ((x ^ y) - 1) >>> 31;
}

function safeSelect(v, x, y) {
  return (~(v - 1) & x) | ((v - 1) & y);
}

function safeLTE(x, y) {
  return ((x - y - 1) >>> 31) & 1;
}

function safeCopy(v, x, y) {
  assert(Number.isSafeInteger(v));
  assert(Buffer.isBuffer(x));
  assert(Buffer.isBuffer(y));

  assert(x.length === y.length);

  const xmask = (v - 1) & 0xff;
  const ymask = ~(v - 1) & 0xff;

  for (let i = 0; i < x.length; i++)
    x[i] = (x[i] & xmask) | (y[i] & ymask);
}

function copyLeftPad(dest, src) {
  assert(Buffer.isBuffer(dest));
  assert(Buffer.isBuffer(src));
  assert(src.length <= dest.length);

  const pad = dest.length - src.length;

  for (let i = 0; i < pad; i++)
    dest[i] = 0x00;

  src.copy(dest, pad);
}

function randomNonzero(buf, offset, size) {
  assert(Buffer.isBuffer(buf));
  assert((offset >>> 0) === offset);
  assert((size >>> 0) === size);

  random.randomFill(buf, offset, size);

  const len = offset + size;

  for (let i = offset; i < len; i++) {
    while (buf[i] === 0x00)
      random.randomFill(buf, i, 1);
  }
}

function mgf1XOR(hash, seed, out) {
  assert(hash && typeof hash.id === 'string');
  assert(Buffer.isBuffer(seed));
  assert(Buffer.isBuffer(out));

  const counter = Buffer.allocUnsafe(4);
  const ctx = hash.ctx;

  counter.fill(0x00);

  let done = 0;

  while (done < out.length) {
    ctx.init();
    ctx.update(seed);
    ctx.update(counter);

    const digest = ctx.final();

    for (let i = 0; i < digest.length && done < out.length; i++) {
      out[done] ^= digest[i];
      done += 1;
    }

    for (let i = 3; i >= 0; i--) {
      if (counter[i] !== 0xff) {
        counter[i] += 1;
        break;
      }

      counter[i] = 0x00;
    }
  }
}

function toBuffer(n) {
  return n.toArrayLike(Buffer, 'be');
}
