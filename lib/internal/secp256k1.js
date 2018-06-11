'use strict';

try {
  if (process.env.NODE_BACKEND && process.env.NODE_BACKEND !== 'native')
    throw new Error('Non-native backend selected.');

  const secp256k1 = require('secp256k1/bindings');
  secp256k1._bcryptoBinding = true;
  module.exports = secp256k1;
} catch (e) {
  const secp256k1 = require('secp256k1/js');
  secp256k1._bcryptoBinding = false;
  module.exports = secp256k1;
}
