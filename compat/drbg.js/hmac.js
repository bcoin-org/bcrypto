'use strict';

// const MD5 = require('../../lib/js/md5');
// const RIPEMD160 = require('../../lib/js/ripemd160');
// const SHA1 = require('../../lib/js/sha1');
// const SHA224 = require('../../lib/js/sha224');
const SHA256 = require('../../lib/js/sha256');
// const SHA384 = require('../../lib/js/sha384');
// const SHA512 = require('../../lib/js/sha512');
const DRBG = require('../../lib/drbg');

class DRBGJS extends DRBG {
  constructor(alg, entropy, nonce, pers) {
    super(getHash(alg));
    this.init(entropy, nonce, pers);
  }
}

function getHash(name) {
  switch (name) {
    // case 'md5':
    //   return MD5;
    // case 'rmd160':
    // case 'ripemd160':
    //   return RIPEMD160;
    // case 'sha1':
    //   return SHA1;
    // case 'sha224':
    //   return SHA224;
    case 'sha256':
      return SHA256;
    // case 'sha384':
    //   return SHA384;
    // case 'sha512':
    //   return SHA512;
    default:
      throw new Error('Unknown hash.');
  }
}

module.exports = DRBGJS;
