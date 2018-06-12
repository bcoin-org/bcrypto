'use strict';

const Path = require('path');

module.exports = {
  // Both
  'bn.js': require.resolve('bn.js'),

  // Secp256k1
  'create-hash': Path.resolve(__dirname, './create-hash'),
  'drbg.js': Path.resolve(__dirname, './drbg.js'),
  'elliptic': require.resolve('elliptic'),
  'safe-buffer': Path.resolve(__dirname, './safe-buffer'),

  // Elliptic
  'brorand': Path.resolve(__dirname, './brorand'),
  'hash.js': Path.resolve(__dirname, './hash'),
  'hmac-drbg': Path.resolve(__dirname, './hmac-drbg')
};
