/*!
 * sha512.js - SHA512 implementation for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const crypto = require('crypto');
const HMAC = require('../hmac');

/**
 * SHA512
 */

class SHA512 {
  constructor() {
    this.ctx = null;
  }

  init() {
    this.ctx = crypto.createHash('sha512');
    return this;
  }

  update(data) {
    assert(Buffer.isBuffer(data));
    assert(this.ctx, 'Context already finalized.');
    this.ctx.update(data);
    return this;
  }

  final() {
    assert(this.ctx, 'Context already finalized.');
    const hash = this.ctx.digest();
    this.ctx = null;
    return hash;
  }

  static hash() {
    return new SHA512();
  }

  static hmac() {
    return new HMAC(SHA512, 128);
  }

  static digest(data) {
    return SHA512.ctx.init().update(data).final();
  }

  static root(left, right) {
    assert(Buffer.isBuffer(left) && left.length === 64);
    assert(Buffer.isBuffer(right) && right.length === 64);
    return SHA512.ctx.init().update(left).update(right).final();
  }

  static multi(one, two, three) {
    const ctx = SHA512.ctx;
    ctx.init();
    ctx.update(one);
    ctx.update(two);
    if (three)
      ctx.update(three);
    return ctx.final();
  }

  static mac(data, key) {
    return SHA512.hmac().init(key).update(data).final();
  }
}

SHA512.native = 1;
SHA512.id = 'sha512';
SHA512.size = 64;
SHA512.bits = 512;
SHA512.blockSize = 128;
SHA512.zero = Buffer.alloc(64, 0x00);
SHA512.ctx = new SHA512();

/*
 * Expose
 */

module.exports = SHA512;
