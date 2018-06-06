/*!
 * hash.js - hash wrapper for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const crypto = require('crypto');
const HMAC = require('../hmac');

/**
 * createHash
 */

function createHash(id, bits, blockSize) {
  const size = bits >>> 3;

  const NodeHash = class NodeHash {
    constructor() {
      this.ctx = null;
    }

    init() {
      this.ctx = crypto.createHash(id);
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
      return new NodeHash();
    }

    static hmac() {
      return new HMAC(NodeHash, blockSize);
    }

    static digest(data) {
      return NodeHash.ctx.init().update(data).final();
    }

    static root(left, right) {
      assert(Buffer.isBuffer(left) && left.length === size);
      assert(Buffer.isBuffer(right) && right.length === size);
      return NodeHash.ctx.init().update(left).update(right).final();
    }

    static multi(one, two, three) {
      const ctx = NodeHash.ctx;
      ctx.init();
      ctx.update(one);
      ctx.update(two);
      if (three)
        ctx.update(three);
      return ctx.final();
    }

    static mac(data, key) {
      return NodeHash.hmac().init(key).update(data).final();
    }
  };

  NodeHash.id = id;
  NodeHash.size = size;
  NodeHash.bits = bits;
  NodeHash.blockSize = blockSize;
  NodeHash.zero = Buffer.alloc(size, 0x00);
  NodeHash.ctx = new NodeHash();

  return NodeHash;
}

/*
 * Expose
 */

module.exports = createHash;
