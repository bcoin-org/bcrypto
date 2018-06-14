/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const random = require('../lib/random');
const safeEqual = require('../lib/safe-equal');
const bytes = Buffer.allocUnsafe(32);

for (let i = 0; i < 32; i++)
  bytes[i] = i;

describe('Safe Equal', function() {
  it('should compare bytes', () => {
    const bytes2 = Buffer.allocUnsafe(32);

    for (let i = 0; i < 32; i++)
      bytes2[i] = i;

    assert(safeEqual(bytes, bytes));
    assert(safeEqual(bytes, bytes2));
  });

  it('should fail comparing bytes', () => {
    assert(!safeEqual(bytes, random.randomBytes(32)));
    assert(!safeEqual(random.randomBytes(32), bytes));
    assert(!safeEqual(bytes, bytes.slice(31)));
    assert(!safeEqual(bytes.slice(31), bytes));

    const buf = Buffer.concat([bytes, Buffer.from([0x00])]);

    assert(!safeEqual(bytes, buf));
    assert(!safeEqual(buf, bytes));
    assert(!safeEqual(bytes, Buffer.alloc(0)));
    assert(!safeEqual(Buffer.alloc(0), bytes));
  });
});
