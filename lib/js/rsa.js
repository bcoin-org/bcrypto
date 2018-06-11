/*!
 * rsa.js - RSA for javascript
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 *
 * Parts of this software are based on golang/go:
 *   Copyright (c) 2009 The Go Authors. All rights reserved.
 *   https://github.com/golang/go
 *
 * Resources:
 *   https://golang.org/src/crypto/rsa/pkcs1v15.go
 */

'use strict';

const assert = require('assert');
const BN = require('bn.js');
const key = require('../internal/rsakey');
const gen = require('../internal/rsagen');
const ccmp = require('../ccmp');
const {RSAPrivateKey, RSAPublicKey} = key;
const rsa = exports;

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
 * @returns {RSAPrivateKey} Private key.
 */

rsa.generateKey = gen.generateKey;

/**
 * Generate a private key.
 * @param {Number} [bits=2048]
 * @returns {RSAPrivateKey} Private key.
 */

rsa.generateKeyAsync = gen.generateKeyAsync;

/**
 * Verify a public key.
 * @param {RSAKey} key
 * @returns {Boolean}
 */

rsa.publicVerify = gen.publicVerify;

/**
 * Verify a private key.
 * @param {RSAPrivateKey} key
 * @returns {Boolean}
 */

rsa.privateVerify = gen.privateVerify;

/**
 * Generate a private key.
 * @param {Number} [bits=2048]
 * @returns {Buffer} Private key.
 */

rsa.privateKeyGenerate = gen.privateKeyGenerate;

/**
 * Generate a private key.
 * @param {Number} [bits=2048]
 * @returns {Buffer} Private key.
 */

rsa.generatePrivateKey = gen.generatePrivateKey;

/**
 * Generate a private key.
 * @param {Number} [bits=2048]
 * @returns {Buffer} Private key.
 */

rsa.privateKeyGenerateAsync = gen.privateKeyGenerateAsync;

/**
 * Create a public key from a private key.
 * @param {Buffer} key
 * @returns {Buffer}
 */

rsa.publicKeyCreate = gen.publicKeyCreate;

/**
 * Validate a public key.
 * @param {Number} bits
 * @param {Buffer} key
 * @returns {Boolean} True if buffer is a valid public key.
 */

rsa.publicKeyVerify = gen.publicKeyVerify;

/**
 * Validate a private key.
 * @param {Buffer} key
 * @returns {Boolean} True if buffer is a valid private key.
 */

rsa.privateKeyVerify = gen.privateKeyVerify;

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

  const prefix = prefixes[hash.id];

  if (!Buffer.isBuffer(prefix))
    throw new Error('Unknown PKCS prefix.');

  const h = hash.digest(msg);
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

  try {
    return rsa._verifyKey(hash, msg, sig, key);
  } catch (e) {
    return false;
  }
};

/**
 * Verify a signature.
 * @param {Object} hash
 * @param {Buffer} msg
 * @param {Buffer} sig - PKCS#1v1.5-formatted.
 * @param {RSAPublicKey} key
 * @returns {Boolean}
 */

rsa._verifyKey = function _verifyKey(hash, msg, sig, key) {
  const prefix = prefixes[hash.id];

  if (!Buffer.isBuffer(prefix))
    throw new Error('Unknown PKCS prefix.');

  const h = hash.digest(msg);
  const len = prefix.length + h.length;

  const n = new BN(key.n, 'be');
  const e = new BN(key.e, 'be');
  const k = Math.ceil(n.bitLength() / 8);

  if (k < len + 11)
    throw new Error('Message too long.');

  const m = encrypt(n, e, sig);
  const em = leftpad(m, k);

  let ok = ceq(em[0], 0x00);
  ok &= ceq(em[1], 0x01);
  ok &= ccmp(em.slice(k - h.length, k), h);
  ok &= ccmp(em.slice(k - len, k - h.length), prefix);
  ok &= ceq(em[k - len - 1], 0x00);

  for (let i = 2; i < k - len - 1; i++)
    ok &= ceq(em[i], 0xff);

  return ok === 1;
};

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

function leftpad(input, size) {
  let n = input.length;

  if (n > size)
    n = size;

  const out = Buffer.allocUnsafe(size);

  out.fill(0, 0, out.length - n);
  input.copy(out, out.length - n);

  return out;
}

function ceq(a, b) {
  let r = ~(a ^ b) & 0xff;
  r &= r >>> 4;
  r &= r >>> 2;
  r &= r >>> 1;
  return r === 1;
}
