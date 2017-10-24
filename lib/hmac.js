/*!
 * hmac.js - hmac for bcoin
 * Copyright (c) 2016-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 * Parts of this software based on hash.js.
 */

'use strict';

const assert = require('assert');

/**
 * HMAC
 */

class HMAC {
  /**
   * Create an HMAC.
   * @param {Function} Hash
   * @param {Number} blockSize
   */

  constructor(Hash, blockSize) {
    assert(typeof Hash === 'function');
    assert((blockSize >>> 0) === blockSize);

    this.Hash = Hash;
    this.blockSize = blockSize;

    this.inner = new Hash();
    this.outer = new Hash();
  }

  /**
   * Initialize HMAC context.
   * @param {Buffer} data
   */

  init(key) {
    assert(Buffer.isBuffer(key));

    const Hash = this.Hash;

    // Shorten key
    if (key.length > this.blockSize)
      key = Hash.digest(key);

    assert(key.length <= this.blockSize);

    // Pad key
    if (key.length < this.blockSize) {
      const padded = Buffer.allocUnsafe(this.blockSize);
      key.copy(padded, 0);
      padded.fill(0, key.length, padded.length);
      key = padded;
    } else {
      key = Buffer.from(key);
    }

    for (let i = 0; i < key.length; i++)
      key[i] ^= 0x36;

    this.inner.init();
    this.inner.update(key);

    // 0x36 ^ 0x5c = 0x6a
    for (let i = 0; i < key.length; i++)
      key[i] ^= 0x6a;

    this.outer.init();
    this.outer.update(key);

    return this;
  }

  /**
   * Update HMAC context.
   * @param {Buffer} data
   */

  update(data) {
    this.inner.update(data);
    return this;
  }

  /**
   * Finalize HMAC context.
   * @returns {Buffer}
   */

  final() {
    this.outer.update(this.inner.final());
    return this.outer.final();
  }
}

/*
 * Expose
 */

module.exports = HMAC;
