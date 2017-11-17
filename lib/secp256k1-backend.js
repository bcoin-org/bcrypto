'use strict';

try {
  if (process.env.NODE_BACKEND && process.env.NODE_BACKEND !== 'native')
    throw new Error('Non-native backend selected.');

  module.exports = require('secp256k1/bindings');
} catch (e) {
  module.exports = require('secp256k1/js');
}
