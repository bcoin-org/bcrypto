/*!
 * cipher.js - ciphers for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const {CipherBase} = require('./binding');

/**
 * Cipher
 * @param {String} name
 */

class Cipher extends CipherBase {
  constructor(name) {
    super(name, true);
  }
}

/**
 * Decipher
 * @param {String} name
 */

class Decipher extends CipherBase {
  constructor(name) {
    super(name, false);
  }
}

/*
 * Expose
 */

exports.native = 2;
exports.Cipher = Cipher;
exports.Decipher = Decipher;
