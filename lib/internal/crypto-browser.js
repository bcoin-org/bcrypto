'use strict';

function unsupported() {
  throw new Error('Cipher is unsupported.');
}

exports.getCipher = unsupported;
exports.encipher = unsupported;
exports.decipher = unsupported;
exports.createCipher = unsupported;
exports.createCipheriv = unsupported;
exports.createDecipher = unsupported;
exports.createDecipheriv = unsupported;
