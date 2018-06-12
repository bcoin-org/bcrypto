'use strict';

// const MD5 = require('../lib/js/md5');
// const RIPEMD160 = require('../lib/js/ripemd160');
// const SHA1 = require('../lib/js/sha1');
// const SHA224 = require('../lib/js/sha224');
const SHA256 = require('../lib/js/sha256');
// const SHA384 = require('../lib/js/sha384');
// const SHA512 = require('../lib/js/sha512');

class NodeHmac {
  constructor(Hash, key) {
    if (typeof key === 'string')
      key = Buffer.from(key);

    this.ctx = Hash.hmac();
    this.ctx.init(key);
  }

  update(data, enc) {
    if (typeof data === 'string')
      data = Buffer.from(data, enc || 'utf8');

    this.ctx.update(data);
    return this;
  }

  digest(enc) {
    if (enc)
      return this.ctx.final().toString(enc);

    return this.ctx.final();
  }
}

module.exports = function createHmac(name, key) {
  switch (name) {
    // case 'md5':
    //   return new NodeHmac(MD5, key);
    // case 'rmd160':
    // case 'ripemd160':
    //   return new NodeHmac(RIPEMD160, key);
    // case 'sha1':
    //   return new NodeHmac(SHA1, key);
    // case 'sha224':
    //   return new NodeHmac(SHA224, key);
    case 'sha256':
      return new NodeHmac(SHA256, key);
    // case 'sha384':
    //   return new NodeHmac(SHA384, key);
    // case 'sha512':
    //   return new NodeHmac(SHA512, key);
    default:
      throw new Error('Unknown hash.');
  }
};
