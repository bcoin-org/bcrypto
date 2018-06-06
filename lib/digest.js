/*!
 * digest.js - hash functions for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('assert');
const Blake160 = require('./blake160');
const Blake256 = require('./blake256');
const Blake2b = require('./blake2b');
const Hash160 = require('./hash160');
const Hash256 = require('./hash256');
const Keccak = require('./keccak');
const MD5 = require('./md5');
const RIPEMD160 = require('./ripemd160');
const SHA1 = require('./sha1');
const SHA224 = require('./sha224');
const SHA256 = require('./sha256');
const SHA3 = require('./sha3');
const SHA384 = require('./sha384');
const SHA512 = require('./sha512');

/*
 * Constants
 */

const hashes = {
  blake160: Blake160,
  blake256: Blake256,
  blake2b: Blake2b,
  hash160: Hash160,
  hash256: Hash256,
  keccak: Keccak,
  md5: MD5,
  ripemd160: RIPEMD160,
  sha1: SHA1,
  sha224: SHA224,
  sha256: SHA256,
  sha3: SHA3,
  sha384: SHA384,
  sha512: SHA512
};

/*
 * Helpers
 */

function wrap(alg, func) {
  func.alg = alg;
  func.hash = alg.hash;
  func.hmac = alg.hmac;
  func.digest = alg.digest;
  func.root = alg.root;
  func.mac = alg.mac;
  func.id = alg.id;
  func.size = alg.size;
  func.bits = alg.bits;
  func.blockSize = alg.blockSize;
  func.zero = alg.zero;
  func.ctx = alg.ctx;
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
 * Hash with blake160.
 * @param {Buffer} data
 * @param {Buffer?} key
 * @returns {Buffer}
 */

exports.blake160 = wrap(Blake160, function blake160(data, key) {
  return Blake160.digest(data, key);
});

/**
 * Hash with blake256.
 * @param {Buffer} data
 * @param {Buffer?} key
 * @returns {Buffer}
 */

exports.blake256 = wrap(Blake256, function blake256(data, key) {
  return Blake256.digest(data, key);
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
 * Hash with MD5.
 * @param {Buffer} data
 * @returns {Buffer}
 */

exports.md5 = wrap(MD5, function md5(data) {
  return MD5.digest(data);
});

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
 * Hash with sha224.
 * @param {Buffer} data
 * @returns {Buffer}
 */

exports.sha224 = wrap(SHA224, function sha224(data) {
  return SHA224.digest(data);
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
 * Hash with sha3.
 * @param {Buffer} data
 * @param {Number} [bits=256]
 * @returns {Buffer}
 */

exports.sha3 = wrap(SHA3, function sha3(data, bits) {
  return SHA3.digest(data, bits);
});

/**
 * Hash with sha384.
 * @param {Buffer} data
 * @returns {Buffer}
 */

exports.sha384 = wrap(SHA384, function sha384(data) {
  return SHA384.digest(data);
});

/**
 * Hash with sha512.
 * @param {Buffer} data
 * @returns {Buffer}
 */

exports.sha512 = wrap(SHA512, function sha512(data) {
  return SHA512.digest(data);
});
