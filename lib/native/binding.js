/*!
 * bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

if (process.env.NODE_BACKEND && process.env.NODE_BACKEND !== 'native')
  throw new Error('Non-native backend selected.');

const binding = require('loady')('bcrypto', __dirname);

const parts = process.version.split(/[^\d]/);
const major = parts[1] >>> 0;
const minor = parts[2] >>> 0;
const patch = parts[3] >>> 0;

if (major !== binding.major
    || minor !== binding.minor
    || Math.abs(patch - binding.patch) > 5) {
  const expect = [
    binding.major,
    binding.minor,
    binding.patch
  ].join('.');

  console.error('WARNING: Bcrypto built for node.js v%s, not %s!',
                expect, process.version);
}

let loaded = false;

binding.load = function load() {
  if (!loaded && major < 10) {
    require('crypto');
    loaded = true;
  }
};

binding.hashes = {
  BLAKE2B160: 1,
  BLAKE2B256: 2,
  BLAKE2B384: 3,
  BLAKE2B512: 4,
  BLAKE2S128: 5,
  BLAKE2S160: 6,
  BLAKE2S224: 7,
  BLAKE2S256: 8,
  GOST94: 9,
  KECCAK224: 10,
  KECCAK256: 11,
  KECCAK384: 12,
  KECCAK512: 13,
  MD2: 14,
  MD4: 15,
  MD5: 16,
  MD5SHA1: 17,
  RIPEMD160: 18,
  SHA1: 19,
  SHA224: 20,
  SHA256: 21,
  SHA384: 22,
  SHA512: 23,
  SHA3_224: 24,
  SHA3_256: 25,
  SHA3_384: 26,
  SHA3_512: 27,
  SHAKE128: 28,
  SHAKE256: 29,
  WHIRLPOOL: 30
};

binding.ciphers = {
  'AES-128': 1,
  'AES-192': 2,
  'AES-256': 3,
  'BF': 4,
  'CAMELLIA-128': 5,
  'CAMELLIA-192': 6,
  'CAMELLIA-256': 7,
  'CAST5': 8,
  'DES': 9,
  'DES-EDE': 10,
  'DES-EDE3': 11,
  'IDEA': 12,
  'RC2-64': 13,
  'TWOFISH-128': 14,
  'TWOFISH-192': 15,
  'TWOFISH-256': 16
};

binding.modes = {
  ECB: 1,
  CBC: 2,
  CTR: 3,
  CFB: 4,
  OFB: 5,
  GCM: 6
};

module.exports = binding;
