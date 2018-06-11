'use strict';

const secp256k1 = require('secp256k1/js');

secp256k1._bcryptoBinding = false;

module.exports = secp256k1;
