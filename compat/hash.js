'use strict';

// const SHA1 = require('../lib/js/sha1');
// const SHA224 = require('../lib/js/sha224');
const SHA256 = require('../lib/js/sha256');
const SHA384 = require('../lib/js/sha384');
const SHA512 = require('../lib/js/sha512');
// const RIPEMD160 = require('../lib/js/ripemd160');

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

  return hash;
}

function HMAC(hash, key, enc) {
  if (!(this instanceof HMAC))
    return new HMAC(hash, key, enc);

  this.ctx = hash.bcrypto.hmac();
  this.ctx.init(toBuffer(key, enc));
}

HMAC.prototype.update = function update(data, enc) {
  this.ctx.update(toBuffer(data, enc));
  return this;
};

HMAC.prototype.digest = function digest(enc) {
  if (enc === 'hex')
    return this.ctx.final().toString('hex');
  return Array.prototype.slice.call(this.ctx.final());
};

function toBuffer(buf, enc) {
  if (!buf)
    return Buffer.alloc(0);

  if (typeof buf === 'string')
    return Buffer.from(buf, enc || 'ascii');

  if (Array.isArray(buf))
    return Buffer.from(buf);

  return buf;
}

const sha = {
  // sha1: toHash(SHA1, 80, 64),
  // sha224: toHash(SHA224, 192, 64),
  sha256: toHash(SHA256, 192, 64),
  sha384: toHash(SHA384, 192, 128),
  sha512: toHash(SHA512, 192, 128)
};

const ripemd = {
  // ripemd160: toHash(RIPEMD160, 192, 64)
};

const hmac = HMAC;

exports.sha = sha;
exports.ripemd = ripemd;
exports.hmac = hmac;

exports.sha1 = sha.sha1;
exports.sha256 = sha.sha256;
exports.sha224 = sha.sha224;
exports.sha384 = sha.sha384;
exports.sha512 = sha.sha512;
exports.ripemd160 = ripemd.ripemd160;
