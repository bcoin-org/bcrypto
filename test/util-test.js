'use strict';

const assert = require('bsert');
const util = require('../lib/encoding/util');

const {
  countLeft,
  countRight,
  compareLeft,
  compareRight,
  trimLeft,
  trimRight,
  padLeft,
  padRight
} = util;

describe('Util', function() {
  it('should count bits (BE)', () => {
    const a = Buffer.from('dde5180064264fb915227539ab9173d2077a2896', 'hex');
    const b = Buffer.from('0b8d6ee639d0be56e0ed9249cc606cc246802ed3', 'hex');
    const c = Buffer.from('0000069f1d5a50bfeb63de5022d1a2d69eee3ba8', 'hex');

    assert.strictEqual(countLeft(Buffer.alloc(0, 0x00)), 0);
    assert.strictEqual(countLeft(Buffer.alloc(32, 0x00)), 0);
    assert.strictEqual(countLeft(Buffer.alloc(32, 0xaa)), 256);
    assert.strictEqual(countLeft(a), 160);
    assert.strictEqual(countLeft(b), 156);
    assert.strictEqual(countLeft(c), 139);
  });

  it('should count bits (LE)', () => {
    const a = Buffer.from('6c5034a300ae5955cff22b79f37e86bbc811b367', 'hex');
    const b = Buffer.from('638b076c969f0b2ed7c90d031dbbbe23e2806d60', 'hex');
    const c = Buffer.from('55ab1c1cc05672e13d4141f65c84227a39000000', 'hex');

    assert.strictEqual(countRight(Buffer.alloc(0, 0x00)), 0);
    assert.strictEqual(countRight(Buffer.alloc(32, 0x00)), 0);
    assert.strictEqual(countRight(Buffer.alloc(32, 0xaa)), 256);
    assert.strictEqual(countRight(a), 159);
    assert.strictEqual(countRight(b), 159);
    assert.strictEqual(countRight(c), 134);
  });

  it('should compare buffers (BE)', () => {
    const a = Buffer.from('dde5180064264fb915227539ab9173d2077a2896', 'hex');
    const b = Buffer.from('0b8d6ee639d0be56e0ed9249cc606cc246802ed3', 'hex');
    const c = Buffer.from('0000069f1d5a50bfeb63de5022d1a2d69eee3ba8', 'hex');

    assert(compareLeft(a, b) > 0);
    assert(compareLeft(b, a) < 0);
    assert(compareLeft(a, c) > 0);
    assert(compareLeft(c, a) < 0);
    assert(compareLeft(b, c) > 0);
    assert(compareLeft(c, b) < 0);
    assert(compareLeft(a, a) === 0);
    assert(compareLeft(b, b) === 0);
    assert(compareLeft(c, c) === 0);
  });

  it('should compare buffers (LE)', () => {
    const a = Buffer.from('6c5034a300ae5955cff22b79f37e86bbc811b367', 'hex');
    const b = Buffer.from('638b076c969f0b2ed7c90d031dbbbe23e2806d60', 'hex');
    const c = Buffer.from('55ab1c1cc05672e13d4141f65c84227a39000000', 'hex');

    assert(compareRight(a, b) > 0);
    assert(compareRight(b, a) < 0);
    assert(compareRight(a, c) > 0);
    assert(compareRight(c, a) < 0);
    assert(compareRight(b, c) > 0);
    assert(compareRight(c, b) < 0);
    assert(compareRight(a, a) === 0);
    assert(compareRight(b, b) === 0);
    assert(compareRight(c, c) === 0);
  });

  it('should compare buffers of different lengths (BE)', () => {
    const a = Buffer.from('dde5180064264fb915227539ab9173d2077a2896', 'hex');
    const b = Buffer.from('8d6ee639d0be56e0ed9249cc606cc246802ed3', 'hex');
    const c = Buffer.from('069f1d5a50bfeb63de5022d1a2d69eee3ba8', 'hex');

    assert(compareLeft(a, b) > 0);
    assert(compareLeft(b, a) < 0);
    assert(compareLeft(a, c) > 0);
    assert(compareLeft(c, a) < 0);
    assert(compareLeft(b, c) > 0);
    assert(compareLeft(c, b) < 0);
    assert(compareLeft(a, a) === 0);
    assert(compareLeft(b, b) === 0);
    assert(compareLeft(c, c) === 0);
  });

  it('should compare buffers of different lengths (LE)', () => {
    const a = Buffer.from('6c5034a300ae5955cff22b79f37e86bbc811b367', 'hex');
    const b = Buffer.from('638b076c969f0b2ed7c90d031dbbbe23e2806d', 'hex');
    const c = Buffer.from('55ab1c1cc05672e13d4141f65c84227a39', 'hex');

    assert(compareRight(a, b) > 0);
    assert(compareRight(b, a) < 0);
    assert(compareRight(a, c) > 0);
    assert(compareRight(c, a) < 0);
    assert(compareRight(b, c) > 0);
    assert(compareRight(c, b) < 0);
    assert(compareRight(a, a) === 0);
    assert(compareRight(b, b) === 0);
    assert(compareRight(c, c) === 0);
  });

  it('should recognize equal buffers (BE)', () => {
    const a = Buffer.from('e5180064264fb915227539ab9173d2077a2896', 'hex');
    const b = Buffer.from('0000e5180064264fb915227539ab9173d2077a2896', 'hex');

    assert(compareLeft(a, b) === 0);
    assert(compareLeft(b, a) === 0);
  });

  it('should recognize equal buffers (LE)', () => {
    const a = Buffer.from('34a300ae5955cff22b79f37e86bbc811b367', 'hex');
    const b = Buffer.from('34a300ae5955cff22b79f37e86bbc811b3670000', 'hex');

    assert(compareRight(a, b) === 0);
    assert(compareRight(b, a) === 0);
  });

  it('should trim buffers (BE)', () => {
    const a = Buffer.from('0000e5180064264fb915227539ab9173d2077a2896', 'hex');
    const b = Buffer.from('e5180064264fb915227539ab9173d2077a2896', 'hex');

    assert.bufferEqual(trimLeft(), Buffer.alloc(1, 0x00));
    assert.bufferEqual(trimLeft(null), Buffer.alloc(1, 0x00));
    assert.bufferEqual(trimLeft(Buffer.alloc(32, 0x00)), Buffer.alloc(1, 0x00));
    assert.bufferEqual(trimLeft(Buffer.alloc(0)), Buffer.alloc(1, 0x00));
    assert.bufferEqual(trimLeft(a), b);
  });

  it('should trim buffers (LE)', () => {
    const a = Buffer.from('34a300ae5955cff22b79f37e86bbc811b3670000', 'hex');
    const b = Buffer.from('34a300ae5955cff22b79f37e86bbc811b367', 'hex');

    assert.bufferEqual(trimRight(), Buffer.alloc(1, 0x00));
    assert.bufferEqual(trimRight(null), Buffer.alloc(1, 0x00));
    assert.bufferEqual(trimRight(Buffer.alloc(32, 0x00)), Buffer.alloc(1, 0x00));
    assert.bufferEqual(trimRight(Buffer.alloc(0)), Buffer.alloc(1, 0x00));
    assert.bufferEqual(trimRight(a), b);
  });

  it('should pad buffers (BE)', () => {
    const a = Buffer.from('0000e5180064264fb915227539ab9173d2077a2896', 'hex');
    const b = Buffer.from('e5180064264fb915227539ab9173d2077a2896', 'hex');

    assert.bufferEqual(padLeft(b, a.length), a);
    assert.bufferEqual(padLeft(a, b.length), b);
    assert.throws(() => padLeft(a, b.length - 1));
  });

  it('should pad buffers (LE)', () => {
    const a = Buffer.from('34a300ae5955cff22b79f37e86bbc811b3670000', 'hex');
    const b = Buffer.from('34a300ae5955cff22b79f37e86bbc811b367', 'hex');

    assert.bufferEqual(padRight(b, a.length), a);
    assert.bufferEqual(padRight(a, b.length), b);
    assert.throws(() => padRight(a, b.length - 1));
  });
});
