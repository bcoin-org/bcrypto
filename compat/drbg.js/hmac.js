'use strict';

const SHA256 = require('../../lib/js/sha256');
const DRBG = require('../../lib/drbg');

class HmacDRBG extends DRBG {
  constructor(alg, entropy, nonce, pers) {
    super(getHash(alg));
    this.init(entropy, nonce, pers);
  }
}

function getHash(name) {
  switch (name) {
    case 'sha256':
      return SHA256;
    default:
      throw new Error('Unknown hash.');
  }
}

module.exports = HmacDRBG;
