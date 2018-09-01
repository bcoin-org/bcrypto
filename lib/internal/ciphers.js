'use strict';

const assert = require('bsert');

/*
 * Constants
 */

const CBC = 1;
const CTR = 2;
const CFB = 3;

const ciphers = {
  // SSH
  'DES-EDE3-CBC': [8, 24, CBC],
  'AES-128-CBC': [16, 16, CBC],
  'AES-192-CBC': [16, 24, CBC],
  'AES-256-CBC': [16, 32, CBC],
  'AES-128-CTR': [16, 16, CTR],
  'AES-192-CTR': [16, 24, CTR],
  'AES-256-CTR': [16, 32, CTR],

  // PGP
  'IDEA-CFB': [8, 16, CFB],
  'DES-EDE3-CFB': [8, 24, CFB], // 16 - 24
  'CAST5-CFB': [8, 16, CFB],
  'BF-CFB': [8, 32, CFB], // 4 - 56
  'AES-128-CFB': [16, 16, CFB],
  'AES-192-CFB': [16, 24, CFB],
  'AES-256-CFB': [16, 32, CFB],
  'TWOFISH-CFB': [16, 32, CFB], // 16, 24, 32
  'CAMELLIA-128-CFB': [16, 16, CFB],
  'CAMELLIA-192-CFB': [16, 24, CFB],
  'CAMELLIA-256-CFB': [16, 32, CFB]
};

/*
 * Ciphers
 */

function get(name) {
  assert(typeof name === 'string');

  if (!ciphers.hasOwnProperty(name)) {
    name = name.toUpperCase();

    if (!ciphers.hasOwnProperty(name))
      throw new Error('Unknown cipher.');
  }

  const [blockSize, keySize, mode] = ciphers[name];

  return {
    name,
    blockSize,
    keySize,
    mode
  };
}

/*
 * Expose
 */

exports.get = get;
