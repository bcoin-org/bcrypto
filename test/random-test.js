/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const random = require('../lib/random');
const bytes = Buffer.allocUnsafe(32);

for (let i = 0; i < 32; i++)
  bytes[i] = i;

describe('Random', function() {
  it('should generate random bytes', () => {
    const rand = Buffer.from(bytes);
    random.randomFill(rand, 0, 32);
    assert.notBufferEqual(rand, bytes);
  });

  it('should generate random bytes without args', () => {
    const rand = Buffer.from(bytes);
    random.randomFill(rand);
    assert.notBufferEqual(rand, bytes);
  });
});
