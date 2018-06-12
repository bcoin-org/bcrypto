'use strict';

const SHA256 = require('../lib/js/sha256');
const SHA384 = require('../lib/js/sha384');
const SHA512 = require('../lib/js/sha512');

function toHash(Hash, hmacStrength, padLength) {
  const BlockHash = function BlockHash() {
    if (!(this instanceof BlockHash))
      return new BlockHash();
    this.ctx = new Hash();
    this.ctx.init();
  };

  BlockHash.prototype.update = function update(data, enc) {
    this.ctx.update(toBuffer(data, enc));
    return this;
  };

  BlockHash.prototype.digest = function digest(enc) {
    if (enc === 'hex')
      return this.ctx.final().toString('hex');
    return Array.prototype.slice.call(this.ctx.final());
  };

  BlockHash.bcrypto = Hash;
  BlockHash.blockSize = Hash.blockSize * 8;
  BlockHash.outSize = Hash.bits;
  BlockHash.hmacStrength = hmacStrength;
  BlockHash.padLength = padLength;

  return BlockHash;
}

function toBuffer(buf, enc) {
  if (!buf)
    return Buffer.alloc(0);

  if (typeof buf === 'string')
    return Buffer.from(buf, enc || 'ascii');

  if (Array.isArray(buf))
    return Buffer.from(buf);

  return buf;
}

exports.sha256 = toHash(SHA256, 192, 64);
exports.sha384 = toHash(SHA384, 192, 128);
exports.sha512 = toHash(SHA512, 192, 128);
