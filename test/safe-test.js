'use strict';

const assert = require('bsert');
const safe = require('../lib/safe');
const bytes = Buffer.allocUnsafe(32);
const rbytes = Buffer.allocUnsafe(32);

for (let i = 0; i < 32; i++)
  bytes[i] = i;

for (let i = 0; i < 32; i++)
  rbytes[i] = 32 - i;

describe('Safe', function() {
  for (const safeEqual of [safe.safeEqual, safe.safeCompare]) {
    it('should compare bytes', () => {
      const bytes2 = Buffer.allocUnsafe(32);

      for (let i = 0; i < 32; i++)
        bytes2[i] = i;

      assert.strictEqual(safeEqual(bytes, bytes), 1);
      assert.strictEqual(safeEqual(bytes, bytes2), 1);
      assert.strictEqual(safeEqual(Buffer.alloc(0), Buffer.alloc(0)), 1);
    });

    it('should fail comparing bytes', () => {
      assert.strictEqual(safeEqual(bytes, rbytes), 0);
      assert.strictEqual(safeEqual(rbytes, bytes), 0);
      assert.strictEqual(safeEqual(bytes, bytes.slice(31)), 0);
      assert.strictEqual(safeEqual(bytes.slice(31), bytes), 0);

      const buf = Buffer.concat([bytes, Buffer.from([0x00])]);

      assert.strictEqual(safeEqual(bytes, buf), 0);
      assert.strictEqual(safeEqual(buf, bytes), 0);
      assert.strictEqual(safeEqual(bytes, Buffer.alloc(0)), 0);
      assert.strictEqual(safeEqual(Buffer.alloc(0), bytes), 0);
    });
  }

  it('should compare uint8', () => {
    assert.strictEqual(safe.safeEqualByte(0, 0), 1);
    assert.strictEqual(safe.safeEqualByte(1, 1), 1);
    assert.strictEqual(safe.safeEqualByte(0xff, 0xff), 1);
    assert.strictEqual(safe.safeEqualByte(0xffff, 0xff), 1);
    assert.strictEqual(safe.safeEqualByte(-1, 0xff), 1);
    assert.strictEqual(safe.safeEqualByte(-1, -1), 1);
    assert.strictEqual(safe.safeEqualByte(-1, 0xff - 1), 0);
    assert.strictEqual(safe.safeEqualByte(0, 1), 0);
  });

  it('should compare ints', () => {
    assert.strictEqual(safe.safeEqualInt(0, 0), 1);
    assert.strictEqual(safe.safeEqualInt(1, 1), 1);
    assert.strictEqual(safe.safeEqualInt(0xffffffff, 0xffffffff), 1);
    assert.strictEqual(safe.safeEqualInt(-1, 0xffffffff), 1);
    assert.strictEqual(safe.safeEqualInt(-1, -1), 1);
    assert.strictEqual(safe.safeEqualInt(-1, 0xffffffff - 1), 0);
    assert.strictEqual(safe.safeEqualInt(0, 1), 0);
  });

  it('should select int', () => {
    assert.strictEqual(safe.safeSelect(0, 1, 2), 2);
    assert.strictEqual(safe.safeSelect(1, 1, 2), 1);
  });

  it('should compare int (LTE)', () => {
    assert.strictEqual(safe.safeLTE(1, 2), 1);
    assert.strictEqual(safe.safeLTE(2, 2), 1);
    assert.strictEqual(safe.safeLTE(3, 2), 0);
  });

  it('should copy', () => {
    const zero = Buffer.alloc(6, 0x00);
    const out = Buffer.alloc(6, 0x00);
    const foo = Buffer.from('foobar');

    safe.safeCopy(0, out, foo);
    assert(out.equals(zero));

    safe.safeCopy(1, out, foo);
    assert(out.equals(foo));
  });
});
