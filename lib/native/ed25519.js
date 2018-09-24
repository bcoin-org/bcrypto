/*!
 * ed25519.js - ed25519 for bcrypto
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const binding = require('./binding').ed25519;
const random = require('./random');
const sha512 = require('./sha512');
const ed25519 = exports;

let elliptic = null;
let x25519 = null;

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

ed25519.id = 'ED25519';

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
 * Convert key to an X25519 key.
 * @param {Buffer} key
 * @returns {Buffer}
 */

ed25519.publicKeyConvert = function publicKeyConvert(key) {
  return binding.publicKeyConvert(key);
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

/**
 * Perform an ECDH (X25519).
 * @param {Buffer} edpub
 * @param {Buffer} secret
 * @returns {Buffer}
 */

ed25519.ecdh = function ecdh(edpub, secret) {
  const pub = ed25519.publicKeyConvert(edpub);
  const priv = ed25519.privateKeyCreate(secret);

  // We can't do this in openssl (yet).
  if (!x25519) {
    elliptic = require('../../vendor/elliptic');
    x25519 = elliptic.ec('curve25519');
  }

  const pk = x25519.keyFromPublic(reverse(pub));
  const sk = x25519.keyFromPrivate(reverse(priv));
  const point = pk.getPublic().mul(sk.priv);

  return reverse(encodePoint(point));
};

/*
 * Helpers
 */

function encodePoint(point) {
  const arr = point.encode('array', false);
  return Buffer.from(arr);
}

function reverse(key) {
  let i = key.length - 1;
  let j = 0;

  while (i > j) {
    const t = key[i];
    key[i] = key[j];
    key[j] = t;
    i -= 1;
    j += 1;
  }

  return key;
}
