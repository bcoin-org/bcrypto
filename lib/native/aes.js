/*!
 * aes.js - aes for bcrypto
 * Copyright (c) 2014-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const cipher = require('./cipher');

/**
 * Encrypt data with aes 256 cbc.
 * @param {Buffer} data
 * @param {Buffer} key
 * @param {Buffer} iv
 * @returns {Buffer}
 */

function encipher(data, key, iv) {
  return cipher.encrypt('AES-256-CBC', key, iv, data);
}

/**
 * Decrypt data with aes 256 cbc.
 * @param {Buffer} data
 * @param {Buffer} key
 * @param {Buffer} iv
 * @returns {Buffer}
 */

function decipher(data, key, iv) {
  return cipher.decrypt('AES-256-CBC', key, iv, data);
}

/*
 * Expose
 */

exports.native = 2;
exports.encipher = encipher;
exports.decipher = decipher;
