/*!
 * hash256.js - Hash256 implementation for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const crypto = require('crypto');
const HMAC = require('../hmac');

/**
 * Hash256
 */

class Hash256 {
  constructor() {
    this.ctx = null;
  }

  init() {
    this.ctx = crypto.createHash('sha256');
    return this;
  }

  update(data) {
    assert(Buffer.isBuffer(data));
    this.ctx.update(data);
    return this;
  }

  final() {
    const sha = crypto.createHash('sha256');
    sha.update(this.ctx.digest());
    return sha.digest();
  }

  static hash() {
    return new Hash256();
  }

  static hmac() {
    return new HMAC(Hash256, 64);
  }

  static digest(data) {
    return new Hash256().init().update(data).final();
  }

  static root(left, right) {
    assert(Buffer.isBuffer(left) && left.length === 32);
    assert(Buffer.isBuffer(right) && right.length === 32);
    return new Hash256().init().update(left).update(right).final();
  }

  static mac(data, key) {
    return this.hmac().init(key).update(data).final();
  }
}

/*
 * Expose
 */

module.exports = Hash256;
