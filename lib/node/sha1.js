/*!
 * sha1.js - SHA1 implementation for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const crypto = require('crypto');
const HMAC = require('../hmac');

/**
 * SHA1
 */

class SHA1 {
  constructor() {
    this.ctx = null;
  }

  init() {
    this.ctx = crypto.createHash('sha1');
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
    return new SHA1();
  }

  static hmac() {
    return new HMAC(SHA1, 64);
  }

  static digest(data) {
    return new SHA1().init().update(data).final();
  }

  static root(left, right) {
    assert(Buffer.isBuffer(left) && left.length === 20);
    assert(Buffer.isBuffer(right) && right.length === 20);
    return new SHA1().init().update(left).update(right).final();
  }

  static mac(data, key) {
    return SHA1.hmac().init(key).update(data).final();
  }
}

/*
 * Expose
 */

module.exports = SHA1;
