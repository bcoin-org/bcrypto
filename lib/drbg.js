/*!
 * drbg.js - hmac-drbg implementation for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 * Parts of this software based on hmac-drbg.
 */

'use strict';

const assert = require('assert');

/*
 * Constants
 */

const RESEED_INTERVAL = 0x1000000000000;
const ZERO = Buffer.from([0x00]);
const ONE = Buffer.from([0x01]);

class DRBG {
  /**
   * DRBG
   * @constructor
   */

  constructor(alg, size, entropy, nonce, pers) {
    assert(alg && typeof alg.name === 'string');
    assert((size >>> 0) === size);

    this.alg = alg;
    this.size = size;

    this.K = Buffer.allocUnsafe(size);
    this.V = Buffer.allocUnsafe(size);
    this.rounds = 0;

    if (entropy)
      this.init(entropy, nonce, pers);
  }

  mac(data) {
    return this.alg.mac(data, this.K);
  }

  hmac() {
    return this.alg.hmac().init(this.K);
  }

  init(entropy, nonce, pers) {
    assert(Buffer.isBuffer(entropy));
    assert(Buffer.isBuffer(nonce));
    assert(Buffer.isBuffer(pers));

    for (let i = 0; i < this.V.length; i++) {
      this.K[i] = 0x00;
      this.V[i] = 0x01;
    }

    const seed = Buffer.concat([entropy, nonce, pers]);

    this.update(seed);
    this.rounds = 1;

    return this;
  }

  update(seed) {
    assert(!seed || Buffer.isBuffer(seed));

    const kmac = this.hmac();

    kmac.update(this.V);
    kmac.update(ZERO);

    if (seed)
      kmac.update(seed);

    this.K = kmac.final();
    this.V = this.mac(this.V);

    if (seed) {
      const kmac = this.hmac();

      kmac.update(this.V);
      kmac.update(ONE);
      kmac.update(seed);

      this.K = kmac.final();
      this.V = this.mac(this.V);
    }

    return this;
  }

  reseed(entropy, add) {
    assert(!entropy || Buffer.isBuffer(entropy));
    assert(!add || Buffer.isBuffer(add));

    if (entropy && add)
      entropy = Buffer.concat([entropy, add]);

    this.update(entropy);
    this.rounds = 1;

    return this;
  }

  generate(len, add) {
    assert((len >>> 0) === len);
    assert(!add || Buffer.isBuffer(add));

    if (this.rounds > RESEED_INTERVAL)
      throw new Error('Reseed is required.');

    if (add)
      this.update(add);

    const data = Buffer.allocUnsafe(len);

    let pos = 0;

    while (pos < len) {
      this.V = this.mac(this.V);
      this.V.copy(data, pos);
      pos += this.size;
    }

    this.update(add);
    this.rounds += 1;

    return data;
  }
}

/*
 * Expose
 */

module.exports = DRBG;
