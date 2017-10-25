/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const {SHA3} = require('../');

const vectors = [
  ['', 'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a'],
  [
    'The quick brown fox jumps over the lazy dog',
    '69070dda01975c8c120c3aada1b282394e7f032fa9cf32f4cb2259a0897dfc04'
  ],
  [
    'The quick brown fox jumps over the lazy dog.',
    'a80f839cd4f83f6c3dafc87feae470045e4eb0d366397d5c6ce34ba1739f734d'
  ],
  [
    'The MD5 message-digest algorithm is a widely used cryptographic'
    + ' hash function producing a 128-bit (16-byte) hash value, typically'
    + ' expressed in text format as a 32 digit hexadecimal number. MD5'
    + ' has been utilized in a wide variety of cryptographic applications,'
    + ' and is also commonly used to verify data integrity.',
    'fa198893674a0bf9fb35980504e8cefb250aabd2311a37e5d2205f07fb023d36'
  ],
  [
    Buffer.alloc(1000000, 'a').toString('ascii'),
    '5c8875ae474a3634ba4fd55ec85bffd661f32aca75c6d699d0cdcb6c115891c1'
  ]
];

function testHash(msg, expect) {
  msg = Buffer.from(msg, 'utf8');
  expect = Buffer.from(expect, 'hex');

  const hash = SHA3.digest(msg);

  assert.bufferEqual(hash, expect);

  const ctx = new SHA3();
  ctx.init();

  const ch = Buffer.allocUnsafe(1);

  for (let i = 0; i < msg.length; i++) {
    ch[0] = msg[i];
    ctx.update(ch);
  }

  assert.bufferEqual(ctx.final(), expect);
}

describe('SHA3', function() {
  for (const [msg, expected] of vectors) {
    it(`should get SHA3 hash of ${expected}`, () => {
      testHash(msg, expected);
    });
  }
});
