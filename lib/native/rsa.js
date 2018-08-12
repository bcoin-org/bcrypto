/*!
 * rsa.js - RSA for javascript
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
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
  MAX_EXP
} = rsakey;

/**
 * Whether the backend is a binding.
 * @const {Number}
 */

rsa.native = 2;

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

rsa.generateKey = function generateKey(bits, exponent) {
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

rsa.generateKeyAsync = async function generateKeyAsync(bits, exponent) {
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
 * Verify a public key.
 * @param {RSAKey} key
 * @returns {Boolean}
 */

rsa.publicVerify = function publicVerify(key) {
  assert(key instanceof RSAKey);
  return key.verify();
};

/**
 * Verify a private key.
 * @param {RSAPrivateKey} key
 * @returns {Boolean}
 */

rsa.privateVerify = function privateVerify(key) {
  assert(key instanceof RSAPrivateKey);

  if (!rsa.publicVerify(key))
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
 * Generate a private key.
 * @param {Number} [bits=2048]
 * @param {Number} [exponent=65537]
 * @returns {Buffer} Private key.
 */

rsa.privateKeyGenerate = function privateKeyGenerate(bits, exponent) {
  const key = rsa.generateKey(bits, exponent);
  return key.encode();
};

/**
 * Generate a private key.
 * @param {Number} [bits=2048]
 * @param {Number} [exponent=65537]
 * @returns {Buffer} Private key.
 */

rsa.generatePrivateKey = rsa.privateKeyGenerate;

/**
 * Generate a private key.
 * @param {Number} [bits=2048]
 * @param {Number} [exponent=65537]
 * @returns {Buffer} Private key.
 */

rsa.privateKeyGenerateAsync = async function privateKeyGenerateAsync(bits, e) {
  const key = await rsa.generateKeyAsync(bits, e);
  return key.encode();
};

/**
 * Create a public key from a private key.
 * @param {Buffer} key
 * @returns {Buffer}
 */

rsa.publicKeyCreate = function publicKeyCreate(key) {
  const k = RSAPrivateKey.decode(key);
  const p = k.toPublic();
  return p.encode();
};

/**
 * Validate a public key.
 * @param {Number} bits
 * @param {Buffer} key
 * @returns {Boolean} True if buffer is a valid public key.
 */

rsa.publicKeyVerify = function publicKeyVerify(key) {
  assert(Buffer.isBuffer(key));

  let k;

  try {
    k = RSAPublicKey.decode(key);
  } catch (e) {
    return false;
  }

  return rsa.publicVerify(k);
};

/**
 * Validate a private key.
 * @param {Buffer} key
 * @returns {Boolean} True if buffer is a valid private key.
 */

rsa.privateKeyVerify = function privateKeyVerify(key) {
  assert(Buffer.isBuffer(key));

  let k;

  try {
    k = RSAPrivateKey.decode(key);
  } catch (e) {
    return false;
  }

  return rsa.privateVerify(k);
};

/**
 * Sign a message.
 * @param {Object} hash
 * @param {Buffer} msg
 * @param {Buffer} key - Private key.
 * @returns {Buffer} PKCS#1v1.5-formatted signature.
 */

rsa.sign = function sign(hash, msg, key) {
  const k = RSAPrivateKey.decode(key);
  return rsa.signKey(hash, msg, k);
};

/**
 * Sign a message.
 * @param {Object} hash
 * @param {Buffer} msg
 * @param {RSAPrivateKey} key - Private key.
 * @returns {Buffer} PKCS#1v1.5-formatted signature.
 */

rsa.signKey = function signKey(hash, msg, key) {
  assert(hash && typeof hash.id === 'string', 'No algorithm selected.');
  assert(Buffer.isBuffer(msg));
  assert(key instanceof RSAPrivateKey);

  const m = hash.digest(msg);

  return binding.sign(
    hash.id,
    m,
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
 * Verify a signature.
 * @param {Object} hash
 * @param {Buffer} msg
 * @param {Buffer} sig - PKCS#1v1.5-formatted.
 * @param {Buffer} key
 * @returns {Boolean}
 */

rsa.verify = function verify(hash, msg, sig, key) {
  assert(Buffer.isBuffer(key));

  let k;

  try {
    k = RSAPublicKey.decode(key);
  } catch (e) {
    return false;
  }

  return rsa.verifyKey(hash, msg, sig, k);
};

/**
 * Verify a signature.
 * @param {Object} hash
 * @param {Buffer} msg
 * @param {Buffer} sig - PKCS#1v1.5-formatted.
 * @param {RSAPublicKey} key
 * @returns {Boolean}
 */

rsa.verifyKey = function verifyKey(hash, msg, sig, key) {
  assert(hash && typeof hash.id === 'string', 'No algorithm selected.');
  assert(Buffer.isBuffer(msg));
  assert(Buffer.isBuffer(sig));
  assert(key instanceof RSAPublicKey);

  const m = hash.digest(msg);

  return binding.verify(
    hash.id,
    m,
    sig,
    key.n,
    key.e
  );
};
