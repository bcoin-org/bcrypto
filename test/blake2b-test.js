/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const {Blake2b} = require('../');
const js = require('../lib/js/blake2b');
const random = require('../lib/random');

let native = null;

try {
  native = require('../lib/native/blake2b');
} catch (e) {
  ;
}

const vectors = [
  [
    '',
    '786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419'
    + 'd25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce'
  ],
  [
    'abc',
    'ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1'
    + '7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923'
  ],
  [
    'The quick brown fox jumps over the lazy dog',
    'a8add4bdddfd93e4877d2746e62817b116364a1fa7bc148d95090bc7333b3673'
    + 'f82401cf7aa2e4cb1ecd90296e3f14cb5413f8ed77be73045b13914cdcd6a918'
  ]
];

function testHash(msg, expect, size = 64) {
  msg = Buffer.from(msg, 'utf8');
  expect = Buffer.from(expect, 'hex');

  const hash = Blake2b.digest(msg, size);

  assert.bufferEqual(hash, expect);

  const ctx = new Blake2b();
  ctx.init(size);

  const ch = Buffer.allocUnsafe(1);

  for (let i = 0; i < msg.length; i++) {
    ch[0] = msg[i];
    ctx.update(ch);
  }

  assert.bufferEqual(ctx.final(), expect);
}

describe('Blake2b', function() {
  for (const [msg, expected] of vectors) {
    it(`should get Blake2b hash of ${expected}`, () => {
      testHash(msg, expected, 64);
    });
  }

  const msg = Buffer.from(''
    + '1a50a77131edc769030c08a8f6405eb4f02537cead9f21de0910242626843'
    + '063e8935a618292be979a23829426d922f3c67f96ebb61dd922b41cd8b40e3cd'
    + '6021e94403074551de72d40427232b990c47804eea4169dec4ca38f96e2b5c10'
    + 'bd9ca6ccc85b30e5a457f231fdf2f1352729fce65492cf9a86016527cb160dbe1c8',
    'hex');

  const expected = Buffer.from(
    '99e1efa672a5bcf314b7334df4304fb12a5bf57cf4f1ff9e0fc15567b7ca1c55',
    'hex');

  it(`should get Blake2b hash of ${expected.toString('hex')}`, () => {
    assert.bufferEqual(Blake2b.digest(msg, 32), expected);
  });

  if (!native)
    return;

  it('should calculate Blake2b with keys', () => {
    for (let i = 0; i < 1000; i++) {
      const preimage = random.randomBytes((Math.random() * 2049) >>> 0);
      const key = random.randomBytes(((Math.random() * 64) >>> 0) + 1);
      const size = Math.random() > 0.5 ? 20 : 32;
      const x = js.digest(preimage, size, key);
      const y = native.digest(preimage, size, key);

      assert.bufferEqual(x, y);
    }
  });
});

