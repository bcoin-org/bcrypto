'use strict';

const assert = require('bsert');

let crypto;

/*
 * Constants
 */

const CBC = 1;
const CTR = 2;
const CFB = 3;

// https://github.com/openssh/openssh-portable/blob/master/cipher.c
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
  'DES-EDE3-CFB': [8, 24, CFB], // key size?
  'CAST5-CFB': [8, 16, CFB],
  'BF-CFB': [8, 32, CFB], // key size ??
  'AES-128-CFB': [16, 16, CFB],
  'AES-192-CFB': [16, 24, CFB],
  'AES-256-CFB': [16, 32, CFB],
  // 'TWOFISH-CFB': [16, 32, CFB], // key size ??
  'CAMELLIA-128-CFB': [16, 16, CFB],
  'CAMELLIA-192-CFB': [16, 24, CFB],
  'CAMELLIA-256-CFB': [16, 32, CFB]
};

/*
 * Crypto
 */

function getCipher(name) {
  assert(typeof name === 'string');

  if (!ciphers.hasOwnProperty(name)) {
    name = name.toUpperCase();

    if (!ciphers.hasOwnProperty(name))
      throw new Error('Unknown cipher.');
  }

  const [blockSize, keySize, type] = ciphers[name];

  return {
    name,
    blockSize,
    keySize,
    type
  };
}

function createCipher(name, key, iv) {
  verify(name, key, iv);
  ensure();
  return crypto.createCipheriv(name, key, iv);
}

function createDecipher(name, key, iv) {
  verify(name, key, iv);
  ensure();
  return crypto.createDecipheriv(name, key, iv);
}

function randomBytes(size) {
  ensure();
  return crypto.randomBytes(size);
}

/*
 * Helpers
 */

function verify(name, key, iv) {
  assert.enforce(Buffer.isBuffer(key), 'key', 'buffer');
  assert.enforce(Buffer.isBuffer(iv), 'iv', 'buffer');

  const {blockSize, keySize} = getCipher(name);

  if (key.length !== keySize)
    throw new Error(`Incorrect key size for ${name}.`);

  if (iv.length !== blockSize)
    throw new Error(`Incorrect IV size for ${name}.`);
}

function ensure() {
  if (!crypto)
    crypto = require('crypto');
  return crypto;
}

/*
 * Expose
 */

exports.getCipher = getCipher;
exports.encipher = createCipher;
exports.decipher = createDecipher;
exports.createCipher = createCipher;
exports.createDecipher = createDecipher;
exports.createCipheriv = createCipher;
exports.createDecipheriv = createDecipher;
exports.randomBytes = randomBytes;
