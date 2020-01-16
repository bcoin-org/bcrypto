/*!
 * bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

if (process.env.NODE_BACKEND && process.env.NODE_BACKEND !== 'native')
  throw new Error('Non-native backend selected.');

const crypto = require('crypto');
const randomBytes = crypto.randomBytes.bind(crypto);
const assert = require('bsert');
const binding = require('loady')('bcrypto', __dirname);

binding.hashes = {
  __proto__: null,
  BLAKE2B160: 0,
  BLAKE2B256: 1,
  BLAKE2B384: 2,
  BLAKE2B512: 3,
  BLAKE2S128: 4,
  BLAKE2S160: 5,
  BLAKE2S224: 6,
  BLAKE2S256: 7,
  GOST94: 8,
  HASH160: 9,
  HASH256: 10,
  KECCAK224: 11,
  KECCAK256: 12,
  KECCAK384: 13,
  KECCAK512: 14,
  MD2: 15,
  MD4: 16,
  MD5: 17,
  MD5SHA1: 18,
  RIPEMD160: 19,
  SHA1: 20,
  SHA224: 21,
  SHA256: 22,
  SHA384: 23,
  SHA512: 24,
  SHA3_224: 25,
  SHA3_256: 26,
  SHA3_384: 27,
  SHA3_512: 28,
  SHAKE128: 29,
  SHAKE256: 30,
  WHIRLPOOL: 31
};

binding.load = () => {};

binding.hash = function _hash(hash) {
  assert(hash && typeof hash.id === 'string');

  const type = binding.hashes[hash.id];

  assert((type >>> 0) === type);

  return type;
};

binding.entropy = function entropy() {
  return randomBytes(32);
};

Object.freeze(binding);

module.exports = binding;
