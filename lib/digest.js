/*!
 * digest.js - hash functions for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('assert');
const RIPEMD160 = require('./ripemd160');
const SHA1 = require('./sha1');
const SHA256 = require('./sha256');
const SHA512 = require('./sha512');
const Hash160 = require('./hash160');
const Hash256 = require('./hash256');
const Keccak = require('./keccak');
const SHA3 = require('./sha3');
const Blake2b = require('./blake2b');

/*
 * Constants
 */

const hashes = {
  ripemd160: RIPEMD160,
  sha1: SHA1,
  sha256: SHA256,
  sha512: SHA512,
  hash160: Hash160,
  hash256: Hash256,
  keccak: Keccak,
  sha3: SHA3,
  blake2b: Blake2b
};

/*
 * Helpers
 */

function wrap(alg, func) {
  func.hash = alg.hash;
  func.hmac = alg.hmac;
  func.digest = alg.digest;
  func.root = alg.root;
  func.mac = alg.mac;
  return func;
}

/**
 * Get hash function.
 * @param {String} name
 * @returns {Function}
 */

exports.get = function get(name) {
  assert(typeof name === 'string');

  if (!hashes.hasOwnProperty(name))
    throw new Error(`Hash ${name} not supported.`);

  return hashes[name];
};

/**
 * Hash with chosen algorithm.
 * @param {String} alg
 * @param {Buffer} data
 * @returns {Buffer}
 */

exports.hash = function hash(alg, ...args) {
  return exports.get(alg).digest(...args);
};

/**
 * Create an HMAC.
 * @param {String} alg
 * @param {Buffer} data
 * @param {Buffer} key
 * @returns {Buffer}
 */

exports.hmac = function hmac(alg, ...args) {
  return exports.get(alg).mac(...args);
};

/**
 * Hash with ripemd160.
 * @param {Buffer} data
 * @returns {Buffer}
 */

exports.ripemd160 = wrap(RIPEMD160, function ripemd160(data) {
  return RIPEMD160.digest(data);
});

/**
 * Hash with sha1.
 * @param {Buffer} data
 * @returns {Buffer}
 */

exports.sha1 = wrap(SHA1, function sha1(data) {
  return SHA1.digest(data);
});

/**
 * Hash with sha256.
 * @param {Buffer} data
 * @returns {Buffer}
 */

exports.sha256 = wrap(SHA256, function sha256(data) {
  return SHA256.digest(data);
});

/**
 * Hash with sha512.
 * @param {Buffer} data
 * @returns {Buffer}
 */

exports.sha512 = wrap(SHA512, function sha512(data) {
  return SHA512.digest(data);
});

/**
 * Hash with sha256 and ripemd160 (OP_HASH160).
 * @param {Buffer} data
 * @returns {Buffer}
 */

exports.hash160 = wrap(Hash160, function hash160(data) {
  return Hash160.digest(data);
});

/**
 * Hash with sha256 twice (OP_HASH256).
 * @param {Buffer} data
 * @returns {Buffer}
 */

exports.hash256 = wrap(Hash256, function hash256(data) {
  return Hash256.digest(data);
});

/**
 * Hash with keccak.
 * @param {Buffer} data
 * @param {Number} [bits=256]
 * @returns {Buffer}
 */

exports.keccak = wrap(Keccak, function keccak(data, bits) {
  return Keccak.digest(data, bits);
});

/**
 * Hash with sha3.
 * @param {Buffer} data
 * @param {Number} [bits=256]
 * @returns {Buffer}
 */

exports.sha3 = wrap(SHA3, function sha3(data, bits) {
  return SHA3.digest(data, bits);
});

/**
 * Hash with blake2b.
 * @param {Buffer} data
 * @param {Number} [size=32]
 * @param {Buffer?} key
 * @returns {Buffer}
 */

exports.blake2b = wrap(Blake2b, function blake2b(data, size, key) {
  return Blake2b.digest(data, size, key);
});
