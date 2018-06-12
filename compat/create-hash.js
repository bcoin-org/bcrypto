'use strict';

const SHA256 = require('../lib/js/sha256');

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
    case 'sha256':
      return new NodeHash(SHA256);
    default:
      throw new Error('Unknown hash.');
  }
};
