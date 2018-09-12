/*!
 * rsa.js - RSA for javascript
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const crypto = require('crypto');
const BN = require('../../vendor/bn.js');
const pkcs1 = require('../encoding/pkcs1');
const base = require('../js/rsa');
const rsa = Object.setPrototypeOf(exports, base);
const {constants} = crypto;
const {RSAKey, RSAPrivateKey} = base;

/**
 * Whether the backend is a binding.
 * @const {Number}
 */

rsa.native = 1;

/**
 * Generate random prime.
 * @private
 * @param {Number} bits
 * @returns {BN}
 */

rsa.randomPrime = function randomPrime(bits) {
  assert((bits >>> 0) === bits);
  assert(bits >= 2);

  const dh = crypto.createDiffieHellman(bits);
  return new BN(dh.getPrime());
};

/**
 * Raw encryption.
 * @private
 * @param {DSAKey} key
 * @param {Buffer} msg
 * @returns {Buffer}
 */

rsa.encryptRaw = function encryptRaw(key, msg) {
  assert(key instanceof RSAKey);
  assert(Buffer.isBuffer(msg));

  const pub = new pkcs1.RSAPublicKey(key.n, key.e);

  return crypto.publicEncrypt({
    key: pub.toPEM(),
    padding: constants.RSA_NO_PADDING
  }, msg);
};

/**
 * Raw decryption.
 * @private
 * @param {DSAPrivateKey} key
 * @param {Buffer} msg
 * @returns {Buffer}
 */

rsa.decryptRaw = function decryptRaw(key, msg) {
  assert(key instanceof RSAPrivateKey);
  assert(Buffer.isBuffer(msg));

  const priv = new pkcs1.RSAPrivateKey(
    0,
    key.n,
    key.e,
    key.d,
    key.p,
    key.q,
    key.dp,
    key.dq,
    key.qi
  );

  return crypto.privateDecrypt({
    key: priv.toPEM(),
    padding: constants.RSA_NO_PADDING
  }, msg);
};
