/*!
 * rsa.js - RSA for javascript
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const {trimZeroes, countBits} = require('../internal/util');
const binding = require('./binding').rsa;

if (!binding)
  throw new Error('RSA native support not available.');

const rsakey = require('../internal/rsakey');
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
  MAX_EXP_BITS
} = rsakey;

const EMPTY = Buffer.alloc(0);

/**
 * Whether the backend is a binding.
 * @const {Number}
 */

rsa.native = 2;

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

  const key = new RSAPrivateKey();
  const items = binding.privateKeyGenerate(bits, exponent);

  [
    key.n,
    key.e,
    key.d,
    key.p,
    key.q,
    key.dp,
    key.dq,
    key.qi
  ] = items;

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

  return new Promise(function(resolve, reject) {
    const cb = function(err, items) {
      if (err) {
        reject(err);
        return;
      }

      const key = new RSAPrivateKey();

      [
        key.n,
        key.e,
        key.d,
        key.p,
        key.q,
        key.dp,
        key.dq,
        key.qi
      ] = items;

      resolve(key);
    };

    try {
      binding.privateKeyGenerateAsync(bits, exponent, cb);
    } catch (e) {
      reject(e);
    }
  });
};

/**
 * Pre-compute a private key.
 * @param {RSAPrivateKey}
 */

rsa.privateKeyCompute = function privateKeyCompute(key) {
  assert(key instanceof RSAPrivateKey);

  const items = binding.privateKeyCompute(
    key.n,
    key.e,
    key.d,
    key.p,
    key.q,
    key.dp,
    key.dq,
    key.qi
  );

  if (!items)
    return;

  [
    key.n,
    key.d,
    key.dp,
    key.dq,
    key.qi
  ] = items;
};

/**
 * Verify a private key.
 * @param {RSAPrivateKey} key
 * @returns {Boolean}
 */

rsa.privateKeyVerify = function privateKeyVerify(key) {
  assert(key instanceof RSAPrivateKey);

  rsa.privateKeyCompute(key);

  if (!rsa.publicKeyVerify(key))
    return false;

  return binding.privateKeyVerify(
    key.n,
    key.e,
    key.d,
    key.p,
    key.q,
    key.dp,
    key.dq,
    key.qi
  );
};

/**
 * Export a private key to PKCS1 ASN.1 format.
 * @param {RSAPrivateKey} key
 * @returns {Buffer}
 */

rsa.privateKeyExport = function privateKeyExport(key) {
  assert(key instanceof RSAPrivateKey);

  rsa.privateKeyCompute(key);

  return binding.privateKeyExport(
    key.n,
    key.e,
    key.d,
    key.p,
    key.q,
    key.dp,
    key.dq,
    key.qi
  );
};

/**
 * Import a private key from PKCS1 ASN.1 format.
 * @param {Buffer} raw
 * @returns {RSAPrivateKey}
 */

rsa.privateKeyImport = function privateKeyImport(raw) {
  const items = binding.privateKeyImport(raw);
  const key = new RSAPrivateKey();

  [
    key.n,
    key.e,
    key.d,
    key.p,
    key.q,
    key.dp,
    key.dq,
    key.qi
  ] = items;

  return key;
};

/**
 * Create a public key from a private key.
 * @param {RSAPrivateKey} key
 * @returns {RSAPublicKey}
 */

rsa.publicKeyCreate = function publicKeyCreate(key) {
  assert(key instanceof RSAPrivateKey);

  rsa.privateKeyCompute(key);

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

  // https://www.imperialviolet.org/2012/03/16/rsae.html
  // https://www.imperialviolet.org/2012/03/17/rsados.html
  const n = trimZeroes(key.n);
  const e = trimZeroes(key.e);
  const nb = countBits(n);
  const eb = countBits(e);

  // https://github.com/golang/go/blob/aadaec5/src/crypto/rsa/rsa.go#L74
  // https://github.com/openssl/openssl/blob/0396401/crypto/rsa/rsa_ossl.c#L85
  // Note: Lots of people use 0x0100000001 for DNSSEC.
  // - Use a 31 bit limit to match golang and older impls.
  // - Use a 33 bit limit to be compatible with dnssec-keygen.
  if (eb > MAX_EXP_BITS) // e > (1 << 33) - 1
    return false;

  // https://github.com/golang/go/blob/aadaec5/src/crypto/rsa/rsa.go#L74
  // https://github.com/openssl/openssl/blob/0396401/crypto/rsa/rsa_chk.c#L55
  if (e.length === 1 && e[0] === 1) // e == 1
    return false;

  // https://github.com/openssl/openssl/blob/0396401/crypto/rsa/rsa_chk.c#L59
  if ((e[e.length - 1] & 1) === 0) // !is_odd(e)
    return false;

  // https://github.com/openssl/openssl/blob/0396401/crypto/rsa/rsa_ossl.c#L80
  if (nb < eb || (nb === eb && n.compare(e) <= 0)) // n <= e
    return false;

  // https://github.com/openssl/openssl/blob/0396401/crypto/rsa/rsa_locl.h#L14
  if (nb < MIN_BITS) // RSA_MIN_MODULUS_BITS
    return false;

  // https://github.com/openssl/openssl/blob/0396401/crypto/rsa/rsa_ossl.c#L74
  if (nb > MAX_BITS) // OPENSSL_RSA_MAX_MODULUS_BITS
    return false;

  return true;
};

/**
 * Export a public key to PKCS1 ASN.1 format.
 * @param {RSAKey} key
 * @returns {Buffer}
 */

rsa.publicKeyExport = function publicKeyExport(key) {
  assert(key instanceof RSAKey);
  return binding.publicKeyExport(key.n, key.e);
};

/**
 * Import a public key from PKCS1 ASN.1 format.
 * @param {Buffer} raw
 * @returns {RSAPublicKey}
 */

rsa.publicKeyImport = function publicKeyImport(raw) {
  const items = binding.publicKeyImport(raw);
  const key = new RSAPublicKey();

  [
    key.n,
    key.e
  ] = items;

  return key;
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

  rsa.privateKeyCompute(key);

  return binding.sign(
    hash,
    msg,
    key.n,
    key.e,
    key.d,
    key.p,
    key.q,
    key.dp,
    key.dq,
    key.qi
  );
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

  if (!rsa.publicKeyVerify(key))
    return false;

  return binding.verify(
    hash,
    msg,
    sig,
    key.n,
    key.e
  );
};

/**
 * Encrypt a message with public key (PKCS1v1.5).
 * @param {Buffer} msg
 * @param {RSAKey} key
 * @returns {Buffer}
 */

rsa.encrypt = function encrypt(msg, key) {
  assert(Buffer.isBuffer(msg));
  assert(key instanceof RSAKey);

  if (!rsa.publicKeyVerify(key))
    throw new Error('Invalid public key.');

  return binding.encrypt(0, msg, key.n, key.e);
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

  rsa.privateKeyCompute(key);

  return binding.decrypt(
    0,
    msg,
    key.n,
    key.e,
    key.d,
    key.p,
    key.q,
    key.dp,
    key.dq,
    key.qi
  );
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

  // Note: unsafe for now.
  let pt;
  try {
    pt = rsa.decrypt(msg, key);
  } catch (e) {
    return;
  }

  if (pt.length !== out.length)
    return;

  pt.copy(key, 0);
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

  if (!rsa.publicKeyVerify(key))
    throw new Error('Invalid public key.');

  return binding.encrypt(1, msg, key.n, key.e);
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

  return binding.decrypt(
    1,
    msg,
    key.n,
    key.e,
    key.d,
    key.p,
    key.q,
    key.dp,
    key.dq,
    key.qi
  );
};
