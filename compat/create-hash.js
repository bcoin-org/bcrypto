'use strict';

// const MD5 = require('../lib/js/md5');
// const RIPEMD160 = require('../lib/js/ripemd160');
// const SHA1 = require('../lib/js/sha1');
// const SHA224 = require('../lib/js/sha224');
const SHA256 = require('../lib/js/sha256');
// const SHA384 = require('../lib/js/sha384');
// const SHA512 = require('../lib/js/sha512');

class NodeHash {
  constructor(Hash) {
    this.ctx = new Hash();
    this.ctx.init();
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

module.exports = function createHash(name) {
  switch (name) {
    // case 'md5':
    //   return new NodeHash(MD5);
    // case 'rmd160':
    // case 'ripemd160':
    //   return new NodeHash(RIPEMD160);
    // case 'sha1':
    //   return new NodeHash(SHA1);
    // case 'sha224':
    //   return new NodeHash(SHA224);
    case 'sha256':
      return new NodeHash(SHA256);
    // case 'sha384':
    //   return new NodeHash(SHA384);
    // case 'sha512':
    //   return new NodeHash(SHA512);
    default:
      throw new Error('Unknown hash.');
  }
};
