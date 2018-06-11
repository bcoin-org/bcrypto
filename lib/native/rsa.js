/*!
 * rsa.js - RSA for javascript
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const binding = require('./binding').rsa;
const rsakey = require('../internal/rsakey');
const rsa = exports;

const {
  RSAKey,
  RSAPrivateKey,
  RSAPublicKey
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
 * @returns {RSAPrivateKey} Private key.
 */

rsa.generateKey = function generateKey(bits = 2048) {
  assert(isPOT(bits), '`bits` must be a power of two.');

  const key = new RSAPrivateKey();
  const items = binding.privateKeyGenerate(bits);

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
 * Verify a public key.
 * @param {RSAKey} key
 * @returns {Boolean}
 */

rsa.publicVerify = function publicVerify(key) {
  assert(key instanceof RSAKey);

  const e = trimZeroes(key.e);

  if (e.length === 1 && e[0] < 2)
    return false;

  if (e.length > 4)
    return false;

  if (e.length === 4 && e[0] & 0x80)
    return false;

  return true;
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
 * @returns {Buffer} Private key.
 */

rsa.privateKeyGenerate = function privateKeyGenerate(bits) {
  const key = rsa.generateKey(bits);
  return key.encode();
};

/**
 * Generate a private key.
 * @param {Number} [bits=2048]
 * @returns {Buffer} Private key.
 */

rsa.generatePrivateKey = rsa.privateKeyGenerate;

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

/*
 * Helpers
 */

function isPOT(n) {
  if ((n >>> 0) !== n)
    return false;

  if (n === 0)
    return false;

  return (n & (n - 1)) === 0;
}

function trimZeroes(e) {
  if (e.length === 0)
    return Buffer.from([0x00]);

  if (e[0] !== 0)
    return e;

  for (let i = 1; i < e.length; i++) {
    if (e[i] !== 0)
      return e.slice(i);
  }

  return e.slice(-1);
}
