/*!
 * rsa.js - RSA for javascript
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
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
 *   https://en.wikipedia.org/wiki/RSA_(cryptosystem)
 *   https://tools.ietf.org/html/rfc3447
 *   https://tools.ietf.org/html/rfc8017
 *   https://github.com/openssl/openssl/blob/master/crypto/rsa/rsa_ossl.c
 *   https://github.com/openssl/openssl/blob/master/crypto/rsa/rsa_sign.c
 *   https://github.com/openssl/openssl/blob/master/crypto/rsa/rsa_oaep.c
 *   https://github.com/openssl/openssl/blob/master/crypto/rsa/rsa_pss.c
 *   https://github.com/openssl/openssl/blob/master/crypto/rsa/rsa_pkcs1.c
 *   https://github.com/golang/go/blob/master/src/crypto/rsa/rsa.go
 *   https://github.com/golang/go/blob/master/src/crypto/rsa/pkcs1v15.go
 *   https://github.com/golang/go/blob/master/src/crypto/rsa/pss.go
 *   https://github.com/golang/go/blob/master/src/crypto/subtle/constant_time.go
 *
 * References:
 *
 *   [RFC8017] PKCS #1: RSA Cryptography Specifications Version 2.2
 *     K. Moriarty, B. Kaliski, J. Jonsson, A. Rusch
 *     https://tools.ietf.org/html/rfc8017
 */

'use strict';

const assert = require('bsert');
const BN = require('../bn.js');
const rsakey = require('../internal/rsakey');
const rng = require('../random');
const {randomPrime} = require('../internal/primes');
const {countLeft} = require('../encoding/util');
const base64 = require('../encoding/base64');
const asn1 = require('../encoding/asn1');
const pkcs1 = require('../encoding/pkcs1');
const pkcs8 = require('../encoding/pkcs8');
const x509 = require('../encoding/x509');
const safe = require('../safe');

const {
  DEFAULT_BITS,
  DEFAULT_EXP,
  MIN_BITS,
  MAX_BITS,
  MIN_EXP,
  MAX_EXP,
  MIN_EXP_BITS,
  MAX_EXP_BITS,
  RSAKey,
  RSAPrivateKey,
  RSAPublicKey
} = rsakey;

const {
  safeEqual,
  safeEqualByte,
  safeSelect,
  safeLTE
} = safe;

/*
 * Constants
 */

const EMPTY = Buffer.alloc(0);
const PREFIX = Buffer.alloc(8, 0x00);

/**
 * PKCS1v1.5+ASN.1 DigestInfo prefixes.
 * @see [RFC8017] Page 45, Section 9.2.
 * @see [RFC8017] Page 63, Section B.1.
 * @const {Object}
 */

const digestInfo = {
  BLAKE2B160: Buffer.from('3027300f060b2b060104018d3a0c02010505000414', 'hex'),
  BLAKE2B256: Buffer.from('3033300f060b2b060104018d3a0c02010805000420', 'hex'),
  BLAKE2B384: Buffer.from('3043300f060b2b060104018d3a0c02010c05000430', 'hex'),
  BLAKE2B512: Buffer.from('3053300f060b2b060104018d3a0c02011005000440', 'hex'),
  BLAKE2S128: Buffer.from('3023300f060b2b060104018d3a0c02020405000410', 'hex'),
  BLAKE2S160: Buffer.from('3027300f060b2b060104018d3a0c02020505000414', 'hex'),
  BLAKE2S224: Buffer.from('302f300f060b2b060104018d3a0c0202070500041c', 'hex'),
  BLAKE2S256: Buffer.from('3033300f060b2b060104018d3a0c02020805000420', 'hex'),
  GOST94: Buffer.from('302e300a06062a850302021405000420', 'hex'),
  KECCAK224: Buffer.from('302d300d06096086480165030402070500041c', 'hex'),
  KECCAK256: Buffer.from('3031300d060960864801650304020805000420', 'hex'),
  KECCAK384: Buffer.from('3041300d060960864801650304020905000430', 'hex'),
  KECCAK512: Buffer.from('3051300d060960864801650304020a05000440', 'hex'),
  MD2: Buffer.from('3020300c06082a864886f70d020205000410', 'hex'),
  MD4: Buffer.from('3020300c06082a864886f70d020405000410', 'hex'),
  MD5: Buffer.from('3020300c06082a864886f70d020505000410', 'hex'),
  MD5SHA1: Buffer.alloc(0),
  RIPEMD160: Buffer.from('3022300a060628cf0603003105000414', 'hex'),
  SHA1: Buffer.from('3021300906052b0e03021a05000414', 'hex'),
  SHA224: Buffer.from('302d300d06096086480165030402040500041c', 'hex'),
  SHA256: Buffer.from('3031300d060960864801650304020105000420', 'hex'),
  SHA384: Buffer.from('3041300d060960864801650304020205000430', 'hex'),
  SHA512: Buffer.from('3051300d060960864801650304020305000440', 'hex'),
  SHA3_224: Buffer.from('302d300d06096086480165030402070500041c', 'hex'),
  SHA3_256: Buffer.from('3031300d060960864801650304020805000420', 'hex'),
  SHA3_384: Buffer.from('3041300d060960864801650304020905000430', 'hex'),
  SHA3_512: Buffer.from('3051300d060960864801650304020a05000440', 'hex'),
  SHAKE128: Buffer.from('3021300d060960864801650304020b05000410', 'hex'),
  SHAKE256: Buffer.from('3031300d060960864801650304020c05000420', 'hex'),
  WHIRLPOOL: Buffer.from('304e300a060628cf0603003705000440', 'hex')
};

/**
 * Generate a private key.
 * @param {Number} [bits=2048]
 * @param {Number} [exponent=65537]
 * @returns {RSAPrivateKey} Private key.
 */

function privateKeyGenerate(bits, exponent) {
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
}

/**
 * Generate a private key.
 * @param {Number} [bits=2048]
 * @param {Number} [exponent=65537]
 * @returns {RSAPrivateKey} Private key.
 */

async function privateKeyGenerateAsync(bits, exponent) {
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
    return privateKeyGenerate(bits, exponent);
  }
}

/**
 * Pre-compute a private key.
 * @param {RSAPrivateKey}
 * @returns {RSAPrivateKey}
 */

function privateKeyCompute(key) {
  // [RFC8017] Page 9, Section 3.2.
  assert(key instanceof RSAPrivateKey);

  if (!isSaneCompute(key))
    throw new Error('Invalid RSA private key.');

  if (!needsCompute(key))
    return key;

  const p = BN.decode(key.p);
  const q = BN.decode(key.q);

  let n = BN.decode(key.n);
  let e = BN.decode(key.e);
  let d = BN.decode(key.d);
  let dp = BN.decode(key.dp);
  let dq = BN.decode(key.dq);
  let qi = BN.decode(key.qi);

  if (n.isZero()) {
    n = p.mul(q);
    key.n = n.encode();
  }

  if (e.isZero()) {
    const t = p.subn(1).imul(q.subn(1));
    e = d.invert(t);
    key.e = e.encode();
  }

  if (d.isZero()) {
    const t = p.subn(1).imul(q.subn(1));
    d = e.invert(t);
    key.d = d.encode();
  }

  if (dp.isZero()) {
    dp = d.mod(p.subn(1));
    key.dp = dp.encode();
  }

  if (dq.isZero()) {
    dq = d.mod(q.subn(1));
    key.dq = dq.encode();
  }

  if (qi.isZero()) {
    qi = q.invert(p);
    key.qi = qi.encode();
  }

  return key;
}

/**
 * Verify a private key.
 * @param {RSAPrivateKey} key
 * @returns {Boolean}
 */

function privateKeyVerify(key) {
  // [RFC8017] Page 9, Section 3.2.
  assert(key instanceof RSAPrivateKey);

  if (!isSanePrivateKey(key))
    return false;

  const mod = new BN(1);

  const primes = [
    BN.decode(key.p),
    BN.decode(key.q)
  ];

  for (const prime of primes) {
    if (prime.cmpn(1) <= 0)
      return false;

    mod.imul(prime);
  }

  const n = BN.decode(key.n);

  if (mod.cmp(n) !== 0)
    return false;

  const d = BN.decode(key.d);
  const e = BN.decode(key.e);
  const de = e.imul(d);

  for (const prime of primes) {
    const cg = de.mod(prime.subn(1));

    if (cg.cmpn(1) !== 0)
      return false;
  }

  return true;
}

/**
 * Export a private key to PKCS1 ASN.1 format.
 * @param {RSAPrivateKey} key
 * @returns {Buffer}
 */

function privateKeyExport(key) {
  // [RFC8017] Page 55, Section A.1.2.
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
}

/**
 * Import a private key from PKCS1 ASN.1 format.
 * @param {Buffer} raw
 * @returns {RSAPrivateKey}
 */

function privateKeyImport(raw) {
  // [RFC8017] Page 55, Section A.1.2.
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
}

/**
 * Export a private key to PKCS8 ASN.1 format.
 * @param {RSAPrivateKey} key
 * @returns {Buffer}
 */

function privateKeyExportPKCS8(key) {
  assert(key instanceof RSAPrivateKey);

  return new pkcs8.PrivateKeyInfo(
    0,
    asn1.objects.keyAlgs.RSA,
    new asn1.Null(),
    privateKeyExport(key)
  ).encode();
}

/**
 * Import a private key from PKCS8 ASN.1 format.
 * @param {Buffer} raw
 * @returns {RSAPrivateKey}
 */

function privateKeyImportPKCS8(raw) {
  const pki = pkcs8.PrivateKeyInfo.decode(raw);
  const {algorithm, parameters} = pki.algorithm;

  assert(pki.version.toNumber() === 0);
  assert(algorithm.toString() === asn1.objects.keyAlgs.RSA);
  assert(parameters.node.type === asn1.types.NULL);

  return privateKeyImport(pki.privateKey.value);
}

/**
 * Export a private key to JWK JSON format.
 * @param {RSAPrivateKey} key
 * @returns {Object}
 */

function privateKeyExportJWK(key) {
  assert(key instanceof RSAPrivateKey);
  return key.toJSON();
}

/**
 * Import a private key from JWK JSON format.
 * @param {Object} json
 * @returns {RSAPrivateKey}
 */

function privateKeyImportJWK(json) {
  const key = RSAPrivateKey.fromJSON(json);

  privateKeyCompute(key);

  return key;
}

/**
 * Create a public key from a private key.
 * @param {RSAPrivateKey} key
 * @returns {RSAPublicKey}
 */

function publicKeyCreate(key) {
  assert(key instanceof RSAPrivateKey);

  const pub = new RSAPublicKey();

  pub.n = key.n;
  pub.e = key.e;

  return pub;
}

/**
 * Verify a public key.
 * @param {RSAKey} key
 * @returns {Boolean}
 */

function publicKeyVerify(key) {
  // [RFC8017] Page 8, Section 3.1.
  assert(key instanceof RSAKey);
  return isSanePublicKey(key);
}

/**
 * Export a public key to PKCS1 ASN.1 format.
 * @param {RSAKey} key
 * @returns {Buffer}
 */

function publicKeyExport(key) {
  // [RFC8017] Page 54, Section A.1.1.
  assert(key instanceof RSAKey);

  if (!isSanePublicKey(key))
    throw new Error('Invalid RSA public key.');

  return new pkcs1.RSAPublicKey(key.n, key.e).encode();
}

/**
 * Import a public key from PKCS1 ASN.1 format.
 * @param {Buffer} raw
 * @returns {RSAPublicKey}
 */

function publicKeyImport(raw) {
  // [RFC8017] Page 54, Section A.1.1.
  const key = pkcs1.RSAPublicKey.decode(raw);
  return new RSAPublicKey(key.n.value, key.e.value);
}

/**
 * Export a public key to SubjectPublicKeyInfo ASN.1 format.
 * @param {RSAKey} key
 * @returns {Buffer}
 */

function publicKeyExportSPKI(key) {
  return new x509.SubjectPublicKeyInfo(
    asn1.objects.keyAlgs.RSA,
    new asn1.Null(),
    publicKeyExport(key)
  ).encode();
}

/**
 * Import a public key from SubjectPublicKeyInfo ASN.1 format.
 * @param {Buffer} raw
 * @returns {RSAPublicKey}
 */

function publicKeyImportSPKI(raw) {
  const spki = x509.SubjectPublicKeyInfo.decode(raw);
  const {algorithm, parameters} = spki.algorithm;

  assert(algorithm.toString() === asn1.objects.keyAlgs.RSA);
  assert(parameters.node.type === asn1.types.NULL);

  return publicKeyImport(spki.publicKey.rightAlign());
}

/**
 * Export a public key to JWK JSON format.
 * @param {RSAKey} key
 * @returns {Object}
 */

function publicKeyExportJWK(key) {
  assert(key instanceof RSAKey);
  return key.toPublic().toJSON();
}

/**
 * Import a public key from JWK JSON format.
 * @param {Object} json
 * @returns {RSAPublicKey}
 */

function publicKeyImportJWK(json) {
  return RSAPublicKey.fromJSON(json);
}

/**
 * Sign a message (PKCS1v1.5).
 * @param {Object|String|null} hash
 * @param {Buffer} msg
 * @param {RSAPrivateKey} key - Private key.
 * @returns {Buffer} PKCS#1v1.5-formatted signature.
 */

function sign(hash, msg, key, decipher = decryptRaw) {
  // [RFC8017] Page 36, Section 8.2.1.
  //           Page 45, Section 9.2.
  if (hash && typeof hash.id === 'string')
    hash = hash.id;

  assert(hash == null || typeof hash === 'string');
  assert(Buffer.isBuffer(msg));
  assert(key instanceof RSAPrivateKey);
  assert(typeof decipher === 'function');

  const [prefix, hlen] = getDigestInfo(hash, msg);

  if (!prefix)
    throw new Error('Unknown RSA hash function.');

  if (msg.length !== hlen)
    throw new Error('Invalid RSA message size.');

  if (!isSanePrivateKey(key))
    throw new Error('Invalid RSA private key.');

  const tlen = prefix.length + hlen;
  const klen = key.size();

  if (klen < tlen + 11)
    throw new Error('Message too long.');

  // EM = 0x00 || 0x01 || PS || 0x00 || T
  const em = Buffer.allocUnsafe(klen);

  em[0] = 0x00;
  em[1] = 0x01;

  for (let i = 2; i < klen - tlen - 1; i++)
    em[i] = 0xff;

  em[klen - tlen - 1] = 0x00;

  prefix.copy(em, klen - tlen);
  msg.copy(em, klen - hlen);

  return decipher(em, key);
}

/**
 * Verify a signature (PKCS1v1.5).
 * @param {Object|String|null} hash
 * @param {Buffer} msg
 * @param {Buffer} sig - PKCS#1v1.5-formatted.
 * @param {RSAKey} key
 * @returns {Boolean}
 */

function verify(hash, msg, sig, key, encipher = encryptRaw) {
  if (hash && typeof hash.id === 'string')
    hash = hash.id;

  assert(hash == null || typeof hash === 'string');
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(sig));
  assert(key instanceof RSAKey);
  assert(typeof encipher === 'function');

  try {
    return _verify(hash, msg, sig, key, encipher);
  } catch (e) {
    return false;
  }
}

/**
 * Verify a signature (PKCS1v1.5).
 * @private
 * @param {Object|String|null} hash
 * @param {Buffer} msg
 * @param {Buffer} sig - PKCS#1v1.5-formatted.
 * @param {RSAKey} key
 * @returns {Boolean}
 */

function _verify(hash, msg, sig, key, encipher) {
  // [RFC8017] Page 37, Section 8.2.2.
  //           Page 45, Section 9.2.
  if (hash && typeof hash.id === 'string')
    hash = hash.id;

  assert(hash == null || typeof hash === 'string');
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(sig));
  assert(key instanceof RSAKey);
  assert(typeof encipher === 'function');

  const [prefix, hlen] = getDigestInfo(hash, msg);

  if (!prefix)
    return false;

  if (msg.length !== hlen)
    return false;

  const klen = key.size();

  if (sig.length !== klen)
    return false;

  if (!isSanePublicKey(key))
    return false;

  const tlen = prefix.length + hlen;

  if (klen < tlen + 11)
    return false;

  const em = encipher(sig, key);

  // EM = 0x00 || 0x01 || PS || 0x00 || T
  let ok = 1;

  ok &= safeEqualByte(em[0], 0x00);
  ok &= safeEqualByte(em[1], 0x01);

  for (let i = 2; i < klen - tlen - 1; i++)
    ok &= safeEqualByte(em[i], 0xff);

  ok &= safeEqualByte(em[klen - tlen - 1], 0x00);
  ok &= safeEqual(em.slice(klen - tlen, klen - hlen), prefix);
  ok &= safeEqual(em.slice(klen - hlen, klen), msg);

  return ok === 1;
}

/**
 * Verify a signature (PKCS1v1.5).
 * @param {Object|String|null} hash
 * @param {Buffer} msg
 * @param {Buffer} sig - PKCS#1v1.5-formatted.
 * @param {RSAKey} key
 * @returns {Boolean}
 */

function verifyLax(hash, msg, sig, key, encipher) {
  assert(key instanceof RSAKey);
  return verify(hash, msg, key.pad(sig), key, encipher);
}

/**
 * Encrypt a message with public key (PKCS1v1.5).
 * @param {Buffer} msg
 * @param {RSAKey} key
 * @returns {Buffer}
 */

function encrypt(msg, key, encipher = encryptRaw) {
  // [RFC8017] Page 28, Section 7.2.1.
  assert(Buffer.isBuffer(msg));
  assert(key instanceof RSAKey);
  assert(typeof encipher === 'function');

  if (!isSanePublicKey(key))
    throw new Error('Invalid RSA public key.');

  const klen = key.size();

  if (msg.length > klen - 11)
    throw new Error('Invalid RSA message size.');

  // EM = 0x00 || 0x02 || PS || 0x00 || M
  const em = Buffer.allocUnsafe(klen);
  const mlen = msg.length;
  const plen = klen - mlen - 3;

  em[0] = 0x00;
  em[1] = 0x02;

  randomNonzero(em, 2, plen);

  em[klen - mlen - 1] = 0x00;

  msg.copy(em, klen - mlen);

  return encipher(em, key);
}

/**
 * Decrypt a message with private key (PKCS1v1.5).
 * @param {Buffer} msg
 * @param {RSAPrivateKey} key
 * @returns {Buffer}
 */

function decrypt(msg, key, decipher = decryptRaw) {
  // [RFC8017] Page 29, Section 7.2.2.
  assert(Buffer.isBuffer(msg));
  assert(key instanceof RSAPrivateKey);
  assert(typeof decipher === 'function');

  const klen = key.size();

  if (msg.length !== klen)
    throw new Error('Invalid RSA message size.');

  if (!isSanePrivateKey(key))
    throw new Error('Invalid RSA private key.');

  if (klen < 11)
    throw new Error('Invalid RSA private key.');

  // EM = 0x00 || 0x02 || PS || 0x00 || M
  const em = decipher(msg, key);
  const fbiz = safeEqualByte(em[0], 0x00);
  const sbit = safeEqualByte(em[1], 0x02);

  let index = 0;
  let looking = 1;

  for (let i = 2; i < em.length; i++) {
    const equals0 = safeEqualByte(em[i], 0x00);

    index = safeSelect(index, i, looking & equals0);
    looking = safeSelect(looking, 0, equals0);
  }

  const validPS = safeLTE(2 + 8, index);
  const valid = fbiz & sbit & (~looking & 1) & validPS;
  const offset = safeSelect(0, index + 1, valid);

  // This line leaks timing information and there's
  // nothing we can do about it (PKCS1v1.5 is broken).
  if (valid === 0)
    throw new Error('Invalid ciphertext.');

  return em.slice(offset);
}

/**
 * Decrypt a message with private key (PKCS1v1.5).
 * @param {Buffer} msg
 * @param {RSAPrivateKey} key
 * @returns {Buffer}
 */

function decryptLax(msg, key, decipher) {
  assert(key instanceof RSAKey);
  return decrypt(key.pad(msg), key, decipher);
}

/**
 * Encrypt a message with public key (OAEP).
 * @param {Object} hash
 * @param {Buffer} msg
 * @param {RSAKey} key
 * @param {Buffer?} label
 * @returns {Buffer}
 */

function encryptOAEP(hash, msg, key, label, encipher = encryptRaw) {
  // [RFC8017] Page 22, Section 7.1.1.
  if (label == null)
    label = EMPTY;

  assert(hash && typeof hash.id === 'string');
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(label));
  assert(key instanceof RSAKey);
  assert(typeof encipher === 'function');

  if (!isSanePublicKey(key))
    throw new Error('Invalid RSA public key.');

  const klen = key.size();
  const mlen = msg.length;
  const hlen = hash.size;

  if (mlen > klen - 2 * hlen - 2)
    throw new Error('Invalid RSA message size.');

  // EM = 0x00 || mgf1(SEED) || mgf1(DB)
  const em = Buffer.allocUnsafe(klen);
  const seed = em.slice(1, 1 + hlen);
  const db = em.slice(1 + hlen);
  const dlen = db.length;

  em[0] = 0x00;

  // SEED = Random Bytes
  rng.randomFill(seed, 0, seed.length);

  // DB = HASH(LABEL) || PS || 0x01 || M
  hash.digest(label).copy(db, 0);
  db.fill(0x00, hlen, dlen - mlen - 1);
  db[dlen - mlen - 1] = 0x01;
  msg.copy(db, dlen - mlen);

  mgf1XOR(hash, seed, db);
  mgf1XOR(hash, db, seed);

  return encipher(em, key);
}

/**
 * Decrypt a message with private key (OAEP).
 * @param {Object} hash
 * @param {Buffer} msg
 * @param {RSAPrivateKey} key
 * @param {Buffer?} label
 * @returns {Buffer}
 */

function decryptOAEP(hash, msg, key, label, decipher = decryptRaw) {
  // [RFC8017] Page 25, Section 7.1.2.
  if (label == null)
    label = EMPTY;

  assert(hash && typeof hash.id === 'string');
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(label));
  assert(key instanceof RSAPrivateKey);
  assert(typeof decipher === 'function');

  const klen = key.size();
  const mlen = msg.length;
  const hlen = hash.size;

  if (mlen !== klen)
    throw new Error('Invalid RSA message size.');

  if (!isSanePrivateKey(key))
    throw new Error('Invalid RSA private key.');

  if (klen < hlen * 2 + 2)
    throw new Error('Invalid RSA private key size.');

  const em = decipher(msg, key);
  const expect = hash.digest(label);
  const fbiz = safeEqualByte(em[0], 0x00);
  const seed = em.slice(1, hlen + 1);
  const db = em.slice(hlen + 1);

  mgf1XOR(hash, db, seed);
  mgf1XOR(hash, seed, db);

  const lhash = db.slice(0, hlen);
  const lvalid = safeEqual(lhash, expect);

  let looking = 1;
  let index = 0;
  let invalid = 0;

  const rest = db.slice(hlen);

  for (let i = 0; i < rest.length; i++) {
    const equals0 = safeEqualByte(rest[i], 0x00);
    const equals1 = safeEqualByte(rest[i], 0x01);

    index = safeSelect(index, i, looking & equals1);
    looking = safeSelect(looking, 0, equals1);
    invalid = safeSelect(invalid, 1, looking & ~equals0);
  }

  if ((fbiz & lvalid & ~invalid & ~looking) !== 1)
    throw new Error('Invalid RSA ciphertext.');

  return rest.slice(index + 1);
}

/**
 * Decrypt a message with private key (OAEP).
 * @param {Object} hash
 * @param {Buffer} msg
 * @param {RSAPrivateKey} key
 * @param {Buffer?} label
 * @returns {Buffer}
 */

function decryptOAEPLax(hash, msg, key, label, decipher) {
  assert(key instanceof RSAKey);
  return decryptOAEP(hash, key.pad(msg), key, label, decipher);
}

/**
 * Sign a message (PSS).
 * @param {Object} hash
 * @param {Buffer} msg
 * @param {RSAPrivateKey} key - Private key.
 * @param {Number} [saltLen=-1]
 * @returns {Buffer} PSS-formatted signature.
 */

function signPSS(hash, msg, key, saltLen = -1, decipher = decryptRaw) {
  // [RFC8017] Page 33, Section 8.1.1.
  assert(hash && typeof hash.id === 'string');
  assert(Buffer.isBuffer(msg));
  assert(key instanceof RSAPrivateKey);
  assert(saltLen === -1 || (saltLen >>> 0) === saltLen);
  assert(typeof decipher === 'function');

  if (msg.length !== hash.size)
    throw new Error('Invalid RSA message size.');

  if (!isSanePrivateKey(key))
    throw new Error('Invalid RSA private key.');

  if (saltLen === 0) // Auto
    saltLen = key.size() - 2 - hash.size;
  else if (saltLen === -1) // Equals
    saltLen = hash.size;

  const salt = rng.randomBytes(saltLen);
  const bits = key.bits();
  const em = pssEncode(hash, msg, bits - 1, salt);

  return decipher(em, key);
}

/**
 * Verify a signature (PSS).
 * @param {Object} hash
 * @param {Buffer} msg
 * @param {Buffer} sig - PSS-formatted.
 * @param {RSAKey} key
 * @param {Number} [saltLen=-1]
 * @returns {Boolean}
 */

function verifyPSS(hash, msg, sig, key, saltLen = -1, encipher = encryptRaw) {
  assert(hash && typeof hash.id === 'string');
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(sig));
  assert(key instanceof RSAKey);
  assert(saltLen === -1 || (saltLen >>> 0) === saltLen);
  assert(typeof encipher === 'function');

  try {
    return _verifyPSS(hash, msg, sig, key, saltLen, encipher);
  } catch (e) {
    return false;
  }
}

/**
 * Verify a signature (PSS).
 * @private
 * @param {Object} hash
 * @param {Buffer} msg
 * @param {Buffer} sig - PSS-formatted.
 * @param {RSAKey} key
 * @param {Number} [saltLen=-1]
 * @returns {Boolean}
 */

function _verifyPSS(hash, msg, sig, key, saltLen = -1, encipher) {
  // [RFC8017] Page 34, Section 8.1.2.
  assert(hash && typeof hash.id === 'string');
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(sig));
  assert(key instanceof RSAKey);
  assert(saltLen === -1 || (saltLen >>> 0) === saltLen);
  assert(typeof encipher === 'function');

  if (msg.length !== hash.size)
    return false;

  if (sig.length !== key.size())
    return false;

  if (!isSanePublicKey(key))
    return false;

  const em = encipher(sig, key);
  const bits = key.bits();

  if (saltLen === -1) // Equals
    saltLen = hash.size;

  return pssVerify(hash, msg, em, bits - 1, saltLen);
}

/**
 * Verify a signature (PSS).
 * @param {Object} hash
 * @param {Buffer} msg
 * @param {Buffer} sig - PSS-formatted.
 * @param {RSAKey} key
 * @param {Number} [saltLen=-1]
 * @returns {Boolean}
 */

function verifyPSSLax(hash, msg, sig, key, saltLen, encipher) {
  assert(key instanceof RSAKey);
  return verifyPSS(hash, msg, key.pad(sig), key, saltLen, encipher);
}

/**
 * Raw encryption.
 * @private
 * @param {Buffer} msg
 * @param {RSAKey} key
 * @returns {Buffer}
 */

function encryptRaw(msg, key) {
  // [RFC8017] Page 13, Section 5.1.1.
  //           Page 16, Section 5.2.2.
  assert(Buffer.isBuffer(msg));
  assert(key instanceof RSAKey);

  // OpenSSL behavior for public encryption.
  if (msg.length !== key.size())
    throw new Error('Invalid RSA message size.');

  const n = BN.decode(key.n);
  const e = BN.decode(key.e);

  if (n.isZero() || e.isZero())
    throw new Error('Invalid RSA public key.');

  const m = BN.decode(msg);

  if (m.cmp(n) >= 0)
    throw new Error('Invalid RSA message size.');

  // c = m^e mod n
  const c = m.powm(e, n);

  return c.encode('be', n.byteLength());
}

/**
 * Raw decryption.
 * @private
 * @param {Buffer} msg
 * @param {RSAPrivateKey} key
 * @returns {Buffer}
 */

function decryptRaw(msg, key) {
  // [RFC8017] Page 13, Section 5.1.2.
  //           Page 15, Section 5.2.1.
  assert(Buffer.isBuffer(msg));
  assert(key instanceof RSAPrivateKey);

  let n = BN.decode(key.n);
  let e = BN.decode(key.e);

  // Recompute modulus.
  if (n.isZero()) {
    const p = BN.decode(key.p);
    const q = BN.decode(key.q);

    if (p.isZero() || q.isZero())
      throw new Error('Invalid RSA private key.');

    // n = p * q
    n = p.imul(q);
  }

  // Recompute public exponent.
  if (e.isZero()) {
    const d = BN.decode(key.d);
    const p = BN.decode(key.p);
    const q = BN.decode(key.q);

    if (d.isZero() || p.isZero() || q.isZero())
      throw new Error('Invalid RSA private key.');

    // t = (p - 1) * (q - 1)
    const t = p.isubn(1).imul(q.isubn(1));

    // e = d^-1 mod t
    try {
      e = d.invert(t);
    } catch (e) {
      throw new Error('Invalid RSA private key.');
    }
  }

  // Decode message.
  const c = BN.decode(msg);

  // Validate params.
  if (c.cmp(n) >= 0 || n.isZero())
    throw new Error('Invalid RSA message size.');

  // Generate blinding factor.
  const [b, bi] = getBlinding(n, e);

  // Blind.
  c.imul(b).imod(n);

  // Decrypt.
  let m = null;

  // Potentially use precomputed values.
  if (needsCompute(key)) {
    // Decrypt with private exponent.
    let d = BN.decode(key.d);

    // Recompute private exponent.
    if (d.isZero()) {
      const p = BN.decode(key.p);
      const q = BN.decode(key.q);

      if (p.isZero() || q.isZero())
        throw new Error('Invalid RSA private key.');

      // t = (p - 1) * (q - 1)
      const t = p.isubn(1).imul(q.isubn(1));

      // d = e^-1 mod t
      try {
        d = e.invert(t);
      } catch (e) {
        throw new Error('Invalid RSA private key.');
      }
    }

    // m = c^d mod n
    m = c.powm(d, n);
  } else {
    // Decrypt with precomputed values.
    //
    // This will leverage Chinese Remainder
    // Theorem to avoid a large exponentiation.
    //
    // We can use Montgomery reduction here
    // since our moduli are prime.
    const p = BN.decode(key.p);
    const q = BN.decode(key.q);
    const dp = BN.decode(key.dp);
    const dq = BN.decode(key.dq);
    const qi = BN.decode(key.qi);

    // mp = c^(d mod p-1) mod p
    // mq = c^(d mod q-1) mod q
    // md = (mp - mq) / q mod p
    const mp = c.powm(dp, p, true);
    const mq = c.powm(dq, q, true);
    const md = mp.isub(mq).imul(qi).imod(p);

    // m = (md * q + mq) mod n
    m = md.imul(q).iadd(mq).imod(n);

    // Check for congruency.
    // (m^e - c) mod n == 0
    const v = m.powm(e, n).isub(c).imod(n);

    // In reality we would want to
    // error here, but OpenSSL
    // swallows the error and does
    // a slower exponentation (wtf?).
    if (!v.isZero()) {
      const d = BN.decode(key.d);

      // m = c^d mod n
      m = c.powm(d, n);
    }
  }

  // Unblind.
  m.imul(bi).imod(n);

  return m.encode('be', n.byteLength());
}

/**
 * "Veil" an RSA ciphertext to hide the key size.
 * @param {Buffer} msg
 * @param {Number} bits
 * @param {RSAKey} key
 * @returns {Buffer}
 */

function veil(msg, bits, key) {
  assert(Buffer.isBuffer(msg));
  assert((bits >>> 0) === bits);
  assert(key instanceof RSAKey);

  if (!isSanePublicKey(key))
    throw new Error('Invalid RSA public key.');

  if (msg.length !== key.size())
    throw new Error('Invalid RSA ciphertext.');

  if (bits < key.bits())
    throw new Error('Cannot make ciphertext smaller.');

  const bytes = (bits + 7) >>> 3;
  const n = BN.decode(key.n);
  const c = BN.decode(msg);

  if (c.cmp(n) >= 0)
    throw new Error('Invalid ciphertext.');

  const cmax = BN.shift(1, bits);
  const rmax = cmax.sub(c).iadd(n).isubn(1).div(n);

  assert(rmax.sign() > 0);

  let v = cmax;

  while (v.cmp(cmax) >= 0) {
    const r = BN.random(rng, 0, rmax);

    v = c.add(r.imul(n));
  }

  assert(v.mod(n).cmp(c) === 0);
  assert(v.bitLength() <= bits);

  return v.encode('be', bytes);
}

/**
 * "Veil" an RSA ciphertext to hide the key size.
 * @param {Buffer} msg
 * @param {Number} bits
 * @param {RSAKey} key
 * @returns {Buffer}
 */

function veilLax(msg, bits, key) {
  assert(key instanceof RSAKey);
  return veil(key.pad(msg), bits, key);
}

/**
 * "Unveil" a veiled RSA ciphertext.
 * @param {Buffer} msg
 * @param {Number} bits
 * @param {RSAKey} key
 * @returns {Buffer}
 */

function unveil(msg, bits, key) {
  assert(Buffer.isBuffer(msg));
  assert((bits >>> 0) === bits);
  assert(key instanceof RSAKey);

  if (!isSanePublicKey(key))
    throw new Error('Invalid RSA public key.');

  const klen = key.size();

  if (msg.length < klen)
    throw new Error('Invalid RSA ciphertext.');

  if (countLeft(msg) > bits)
    throw new Error('Invalid RSA ciphertext.');

  const n = BN.decode(key.n);
  const v = BN.decode(msg);
  const c = v.imod(n);

  return c.encode('be', klen);
}

/**
 * "Unveil" a veiled RSA ciphertext.
 * @param {Buffer} msg
 * @param {Number} bits
 * @param {RSAKey} key
 * @returns {Buffer}
 */

function unveilLax(msg, bits, key) {
  assert(key instanceof RSAKey);
  return unveil(key.pad(msg), bits, key);
}

/**
 * Generate multi-prime key.
 * @private
 * @param {Number} total
 * @param {Number} bits
 * @param {Number} exponent
 * @returns {Array}
 */

function generateKey(total, bits, exponent) {
  // [RFC8017] Page 9, Section 3.2.
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
      continue;

    const e = new BN(exponent);

    let d = null;

    try {
      d = e.invert(t);
    } catch (e) {
      continue;
    }

    const [p, q] = primes;
    const dp = d.mod(p.subn(1));
    const dq = d.mod(q.subn(1));
    const qi = q.invert(p);
    const key = new RSAPrivateKey();

    key.n = n.encode();
    key.e = e.encode();
    key.d = d.encode();
    key.p = p.encode();
    key.q = q.encode();
    key.dp = dp.encode();
    key.dq = dq.encode();
    key.qi = qi.encode();

    const extra = [];

    for (let i = 2; i < primes.length; i++) {
      const prime = primes[i].encode();
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
 * Randomization
 */

function getBlinding(n, e) {
  assert(n instanceof BN);
  assert(e instanceof BN);

  // Generate blinding factor.
  for (;;) {
    // s = random integer in [1,n-1]
    const s = BN.random(rng, 1, n);

    // bi = s^-1 mod n
    let bi;
    try {
      bi = s.invert(n);
    } catch (e) {
      continue;
    }

    // b = s^e mod n
    const b = s.powm(e, n);

    return [b, bi];
  }
}

/*
 * PSS
 */

function pssEncode(hash, msg, embits, salt) {
  // [RFC8017] Page 42, Section 9.1.1.
  assert(hash && typeof hash.id === 'string');
  assert(Buffer.isBuffer(msg));
  assert((embits >>> 0) === embits);
  assert(Buffer.isBuffer(salt));

  const hlen = hash.size;
  const slen = salt.length;
  const emlen = (embits + 7) >>> 3;

  if (msg.length !== hlen)
    throw new Error('RSA input must be hashed message.');

  if (emlen < hlen + slen + 2)
    throw new Error('RSA key size too small for PSS signature.');

  const em = Buffer.alloc(emlen, 0x00);
  const db = em.slice(0, emlen - slen - hlen - 2 + 1 + slen);
  const h = em.slice(emlen - slen - hlen - 2 + 1 + slen, emlen - 1);
  const h0 = hash.multi(PREFIX, msg, salt);

  h0.copy(h, 0);
  db[emlen - slen - hlen - 2] = 0x01;
  salt.copy(db, emlen - slen - hlen - 1);

  mgf1XOR(hash, h, db);

  db[0] &= 0xff >>> (8 * emlen - embits);
  em[emlen - 1] = 0xbc;

  return em;
}

function pssVerify(hash, msg, em, embits, slen) {
  // [RFC8017] Page 44, Section 9.1.2.
  assert(hash && typeof hash.id === 'string');
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(em));
  assert((embits >>> 0) === embits);
  assert((slen >>> 0) === slen);

  const hlen = hash.size;

  if (msg.length !== hlen)
    return false;

  const emlen = (embits + 7) >>> 3;

  if (emlen < hlen + slen + 2)
    return false;

  if (em[em.length - 1] !== 0xbc)
    return false;

  const db = em.slice(0, emlen - hlen - 1);
  const h = em.slice(emlen - hlen - 1, em.length - 1);
  const bit = (0xff << (8 - (8 * emlen - embits))) & 0xff;

  if ((em[0] & bit) !== 0)
    return false;

  mgf1XOR(hash, h, db);

  db[0] &= 0xff >>> (8 * emlen - embits);

  if (slen === 0) { // Auto
    slen = emlen - (hlen + 2);

outer:
    for (; slen >= 0; slen--) {
      const e = db[emlen - hlen - slen - 2];

      switch (e) {
        case 0x01:
          break outer;
        case 0x00:
          continue;
        default:
          return false;
      }
    }

    if (slen < 0)
      return false;
  } else {
    const len = emlen - hlen - slen - 2;

    for (let i = 0; i < len; i++) {
      if (db[i] !== 0x00)
        return false;
    }

    if (db[len] !== 0x01)
      return false;
  }

  const salt = db.slice(db.length - slen);
  const h0 = hash.multi(PREFIX, msg, salt);

  return h0.equals(h);
}

/*
 * Sanity Checking
 */

function isSanePublicKey(key) {
  // [RFC8017] Page 8, Section 3.1.
  assert(key instanceof RSAKey);

  const nb = countLeft(key.n);

  if (nb < MIN_BITS || nb > MAX_BITS)
    return false;

  const eb = countLeft(key.e);

  if (eb < MIN_EXP_BITS || eb > MAX_EXP_BITS)
    return false;

  if ((key.e[key.e.length - 1] & 1) === 0)
    return false;

  return true;
}

function isSanePrivateKey(key) {
  // [RFC8017] Page 9, Section 3.2.
  assert(key instanceof RSAPrivateKey);

  if (!isSanePublicKey(key))
    return false;

  const nb = countLeft(key.n);
  const db = countLeft(key.d);

  if (db === 0 || db > nb)
    return false;

  const pb = countLeft(key.p);
  const qb = countLeft(key.q);

  if (nb > pb + qb)
    return false;

  const dpb = countLeft(key.dp);

  if (dpb === 0 || dpb > pb)
    return false;

  const dqb = countLeft(key.dq);

  if (dqb === 0 || dqb > qb)
    return false;

  const qib = countLeft(key.qi);

  if (qib === 0 || qib > pb)
    return false;

  return true;
}

function isSaneCompute(key) {
  // [RFC8017] Page 9, Section 3.2.
  assert(key instanceof RSAPrivateKey);

  const nb = countLeft(key.n);
  const eb = countLeft(key.e);
  const db = countLeft(key.d);
  const pb = countLeft(key.p);
  const qb = countLeft(key.q);
  const dpb = countLeft(key.dp);
  const dqb = countLeft(key.dq);
  const qib = countLeft(key.qi);

  if (pb === 0 || qb === 0)
    return false;

  if (eb === 0 && db === 0)
    return false;

  if (nb !== 0) {
    if (nb < MIN_BITS || nb > MAX_BITS)
      return false;

    if (nb > pb + qb)
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
  assert(key instanceof RSAPrivateKey);

  return countLeft(key.n) === 0
      || countLeft(key.e) === 0
      || countLeft(key.d) === 0
      || countLeft(key.dp) === 0
      || countLeft(key.dq) === 0
      || countLeft(key.qi) === 0;
}

/*
 * Helpers
 */

function randomNonzero(buf, offset, size) {
  assert(Buffer.isBuffer(buf));
  assert((offset >>> 0) === offset);
  assert((size >>> 0) === size);

  rng.randomFill(buf, offset, size);

  const len = offset + size;

  for (let i = offset; i < len; i++) {
    while (buf[i] === 0x00)
      rng.randomFill(buf, i, 1);
  }
}

function mgf1XOR(hash, seed, out) {
  // [RFC8017] Page 67, Section B.2.1.
  assert(hash && typeof hash.id === 'string');
  assert(Buffer.isBuffer(seed));
  assert(Buffer.isBuffer(out));

  const counter = Buffer.alloc(4, 0x00);

  let done = 0;

  while (done < out.length) {
    const digest = hash.multi(seed, counter);

    for (let i = 0; i < digest.length && done < out.length; i++) {
      out[done] ^= digest[i];
      done += 1;
    }

    for (let i = 3; i >= 0; i--) {
      counter[i] += 1;

      if (counter[i] !== 0x00)
        break;
    }
  }
}

function getDigestInfo(name, msg) {
  // [RFC8017] Page 63, Section B.1.
  assert(name == null || typeof name === 'string');
  assert(Buffer.isBuffer(msg));

  if (name == null)
    return [EMPTY, msg.length];

  const prefix = digestInfo[name];

  if (!Buffer.isBuffer(prefix))
    return [null, 0];

  return [
    prefix,
    prefix.length > 0
      ? prefix[prefix.length - 1]
      : 36
  ];
}

/*
 * Expose
 */

exports.native = 0;
exports.RSAKey = RSAKey;
exports.RSAPublicKey = RSAPublicKey;
exports.RSAPrivateKey = RSAPrivateKey;
exports.privateKeyGenerate = privateKeyGenerate;
exports.privateKeyGenerateAsync = privateKeyGenerateAsync;
exports.privateKeyCompute = privateKeyCompute;
exports.privateKeyVerify = privateKeyVerify;
exports.privateKeyExport = privateKeyExport;
exports.privateKeyImport = privateKeyImport;
exports.privateKeyExportPKCS8 = privateKeyExportPKCS8;
exports.privateKeyImportPKCS8 = privateKeyImportPKCS8;
exports.privateKeyExportJWK = privateKeyExportJWK;
exports.privateKeyImportJWK = privateKeyImportJWK;
exports.publicKeyCreate = publicKeyCreate;
exports.publicKeyVerify = publicKeyVerify;
exports.publicKeyExport = publicKeyExport;
exports.publicKeyImport = publicKeyImport;
exports.publicKeyExportSPKI = publicKeyExportSPKI;
exports.publicKeyImportSPKI = publicKeyImportSPKI;
exports.publicKeyExportJWK = publicKeyExportJWK;
exports.publicKeyImportJWK = publicKeyImportJWK;
exports.sign = sign;
exports.verify = verify;
exports.verifyLax = verifyLax;
exports.encrypt = encrypt;
exports.decrypt = decrypt;
exports.decryptLax = decryptLax;
exports.encryptOAEP = encryptOAEP;
exports.decryptOAEP = decryptOAEP;
exports.decryptOAEPLax = decryptOAEPLax;
exports.signPSS = signPSS;
exports.verifyPSS = verifyPSS;
exports.verifyPSSLax = verifyPSSLax;
exports.encryptRaw = encryptRaw;
exports.decryptRaw = decryptRaw;
exports.veil = veil;
exports.veilLax = veilLax;
exports.unveil = unveil;
exports.unveilLax = unveilLax;
