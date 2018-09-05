/*!
 * ed25519.js - ed25519 for bcoin
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('bsert');
const binding = require('./binding').ed25519;
const random = require('./random');
const sha512 = require('./sha512');
const ed25519 = exports;

/*
 * Constants
 */

const ZERO = Buffer.alloc(32, 0x00);

const ORDER = Buffer.from(
  '1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed',
  'hex');

/**
 * Name of the curve.
 * @const {String}
 */

ed25519.id = 'ed25519';

/**
 * Size of the curve in bits.
 * @const {Number}
 */

ed25519.bits = 253;

/**
 * Size of the curve in bytes.
 * @const {Buffer}
 */

ed25519.size = 32;

/**
 * Zero value of the curve.
 * @const {Buffer}
 */

ed25519.zero = ZERO;

/**
 * Order of the curve.
 * @const {Buffer}
 */

ed25519.order = ORDER;

/**
 * Whether the backend is a binding.
 * @const {Number}
 */

ed25519.native = 2;

/**
 * Generate a secret.
 * @returns {Buffer}
 */

ed25519.secretGenerate = function secretGenerate() {
  return random.randomBytes(32);
};

/**
 * Validate a secret.
 * @param {Buffer} secret
 * @returns {Boolean}
 */

ed25519.secretVerify = function secretVerify(secret) {
  assert(Buffer.isBuffer(secret));
  return secret.length === 32;
};

/**
 * Create a private key from a secret.
 * @param {Buffer} secret
 * @returns {Buffer}
 */

ed25519.privateKeyCreate = function privateKeyCreate(secret) {
  assert(Buffer.isBuffer(secret));
  assert(secret.length === 32);

  const priv = sha512.digest(secret);

  priv[0] &= 248;
  priv[31] &= 127;
  priv[31] |= 64;

  return priv.slice(0, 32);
};

/**
 * Create a public key from a secret.
 * @param {Buffer} secret
 * @returns {Buffer}
 */

ed25519.publicKeyCreate = function publicKeyCreate(secret) {
  return binding.publicKeyCreate(secret);
};

/**
 * Validate a public key.
 * @param {Buffer} key
 * @returns {Boolean}
 */

ed25519.publicKeyVerify = function publicKeyVerify(key) {
  return binding.publicKeyVerify(key);
};

/**
 * Sign a message.
 * @param {Buffer} msg
 * @param {Buffer} secret
 * @returns {Buffer}
 */

ed25519.sign = function sign(msg, secret) {
  return binding.sign(msg, secret);
};

/**
 * Verify a signature.
 * @param {Buffer} msg
 * @param {Buffer} sig
 * @param {Buffer} key
 * @returns {Boolean}
 */

ed25519.verify = function verify(msg, sig, key) {
  return binding.verify(msg, sig, key);
};
