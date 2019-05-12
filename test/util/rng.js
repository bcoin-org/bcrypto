'use strict';

const assert = require('bsert');
const SHA256 = require('../../lib/sha256');

// Super dumb deterministic RNG.
class RNG {
  constructor() {
    this.prev = Buffer.alloc(32, 0x00);
  }

  randomBytes(len) {
    assert((len >>> 0) === len);

    const out = Buffer.alloc(len);

    let pos = 0;

    while (pos < len) {
      this.prev = SHA256.digest(this.prev);
      pos += this.prev.copy(out, pos);
    }

    return out;
  }
}

module.exports = RNG;
