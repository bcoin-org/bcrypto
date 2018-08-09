'use strict';

const DRBG = require('../lib/drbg');

function HmacDRBG(options) {
  if (!(this instanceof HmacDRBG))
    return new HmacDRBG(options);

  const Hash = options.hash;
  const entropy = toBuffer(options.entropy, options.entropyEnc || 'hex');
  const nonce = toBuffer(options.nonce, options.nonceEnc || 'hex');
  const pers = toBuffer(options.pers, options.persEnc || 'hex');

  this.hash = Hash;
  this.predResist = Boolean(options.predResist);
  this.outLen = Hash.outSize;
  this.minEntropy = options.minEntropy || Hash.hmacStrength;
  this.reseedInterval = 0x1000000000000;
  this.ctx = new DRBG(Hash.bcrypto);
  this.ctx.init(entropy, nonce, pers);
}

HmacDRBG.prototype.reseed = function reseed(entropy, entropyEnc, add, addEnc) {
  if (typeof entropyEnc !== 'string') {
    addEnc = add;
    add = entropyEnc;
    entropyEnc = null;
  }

  entropy = toBuffer(entropy, entropyEnc);
  add = toBuffer(add, addEnc);

  this.ctx.reseed(entropy, add);

  return this;
};

HmacDRBG.prototype.generate = function generate(len, enc, add, addEnc) {
  if (typeof enc !== 'string') {
    addEnc = add;
    add = enc;
    enc = null;
  }

  if (add)
    add = toBuffer(add, addEnc || 'hex');

  const data = this.ctx.generate(len, add);

  if (enc === 'hex')
    return data.toString('hex');

  return Array.prototype.slice.call(data);
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

module.exports = HmacDRBG;
