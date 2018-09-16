/*!
 * blake2b.js - BLAKE2b implementation for bcrypto
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');
const crypto = require('crypto');
const Backend = require('../js/blake2b');
const hashes = crypto.getHashes();

/*
 * Constants
 */

const names = {
  20: hashes.indexOf('blake2b160') !== -1
    ? 'blake2b160'
    : null,
  32: hashes.indexOf('blake2b256') !== -1
    ? 'blake2b256'
    : null,
  48: hashes.indexOf('blake2b384') !== -1
    ? 'blake2b384'
    : null,
  64: hashes.indexOf('blake2b512') !== -1
    ? 'blake2b512'
    : null
};

/**
 * Blake2b
 */

class Blake2b {
  /**
   * Create a Blake2b context.
   * @constructor
   */

  constructor() {
    this.node = null;
    this.js = null;
  }

  init(size = 32, key = null) {
    assert((size >>> 0) === size);

    if (key && key.length === 0)
      key = null;

    if (!key && typeof names[size] === 'string') {
      this.node = crypto.createHash(names[size]);
      this.js = null;
    } else {
      this.node = null;
      this.js = new Backend();
      this.js.init(size, key);
    }

    return this;
  }

  update(data) {
    if (this.node) {
      assert(Buffer.isBuffer(data));
      this.node.update(data);
    } else {
      assert(this.js);
      this.js.update(data);
    }
    return this;
  }

  final() {
    let ret;

    if (this.node) {
      ret = this.node.digest();
      this.node = null;
    } else {
      assert(this.js);
      ret = this.js.final();
      this.js = null;
    }

    return ret;
  }

  static hash() {
    return new Blake2b();
  }

  static hmac() {
    return Backend.hmac();
  }

  static digest(data, size = 32, key = null) {
    const ctx = Blake2b.ctx;
    ctx.init(size, key);
    ctx.update(data);
    return ctx.final();
  }

  static root(left, right, size = 32) {
    assert(Buffer.isBuffer(left) && left.length === size);
    assert(Buffer.isBuffer(right) && right.length === size);
    const ctx = Blake2b.ctx;
    ctx.init(size);
    ctx.update(left);
    ctx.update(right);
    return ctx.final();
  }

  static multi(one, two, three, size = 32) {
    const ctx = Blake2b.ctx;
    ctx.init(size);
    ctx.update(one);
    ctx.update(two);
    if (three)
      ctx.update(three);
    return ctx.final();
  }

  static mac(data, key, size = 32) {
    return Backend.mac(data, size, key);
  }
}

Blake2b.native = 1;
Blake2b.id = 'BLAKE2B256';
Blake2b.ossl = 'blake2b256';
Blake2b.size = 32;
Blake2b.bits = 256;
Blake2b.blockSize = 128;
Blake2b.zero = Buffer.alloc(32, 0x00);
Blake2b.ctx = new Blake2b();

/*
 * Expose
 */

module.exports = Blake2b;
