/*!
 * sha256.js - SHA256 implementation for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const crypto = require('crypto');
const HMAC = require('../hmac');

/**
 * SHA256
 */

class SHA256 {
  constructor() {
    this.ctx = null;
  }

  init() {
    this.ctx = crypto.createHash('sha256');
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
    return new SHA256();
  }

  static hmac() {
    return new HMAC(SHA256, 64);
  }

  static digest(data) {
    return SHA256.ctx.init().update(data).final();
  }

  static root(left, right) {
    assert(Buffer.isBuffer(left) && left.length === 32);
    assert(Buffer.isBuffer(right) && right.length === 32);
    return SHA256.ctx.init().update(left).update(right).final();
  }

  static multi(one, two, three) {
    const ctx = SHA256.ctx;
    ctx.init();
    ctx.update(one);
    ctx.update(two);
    if (three)
      ctx.update(three);
    return ctx.final();
  }

  static mac(data, key) {
    return SHA256.hmac().init(key).update(data).final();
  }
}

SHA256.native = 1;
SHA256.id = 'sha256';
SHA256.size = 32;
SHA256.bits = 256;
SHA256.blockSize = 64;
SHA256.zero = Buffer.alloc(32, 0x00);
SHA256.ctx = new SHA256();

/*
 * Expose
 */

module.exports = SHA256;
