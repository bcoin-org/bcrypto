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
   * @param {Number} size
   */

  constructor(Hash, size) {
    assert(typeof Hash === 'function');
    assert((size >>> 0) === size);

    this.hash = Hash;
    this.size = size;

    this.inner = new Hash();
    this.outer = new Hash();
  }

  /**
   * Initialize HMAC context.
   * @param {Buffer} data
   */

  init(key) {
    assert(Buffer.isBuffer(key));

    // Shorten key
    if (key.length > this.size) {
      key = this.hash.digest(key);
      assert(key.length <= this.size);
    }

    // Pad key
    const pad = Buffer.allocUnsafe(this.size);

    for (let i = 0; i < key.length; i++)
      pad[i] = key[i] ^ 0x36;

    for (let i = key.length; i < pad.length; i++)
      pad[i] = 0x36;

    this.inner.init();
    this.inner.update(pad);

    for (let i = 0; i < key.length; i++)
      pad[i] = key[i] ^ 0x5c;

    for (let i = key.length; i < pad.length; i++)
      pad[i] = 0x5c;

    this.outer.init();
    this.outer.update(pad);

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
