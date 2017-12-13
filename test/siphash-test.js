/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const n64 = require('n64');
const assert = require('./util/assert');
const {siphash} = require('../lib/siphash');
const {siphash256} = require('../');

const vectors = [
  Buffer.from('310e0edd47db6f72', 'hex'), Buffer.from('fd67dc93c539f874', 'hex')
  ,
  Buffer.from('5a4fa9d909806c0d', 'hex'), Buffer.from('2d7efbd796666785', 'hex')
  ,
  Buffer.from('b7877127e09427cf', 'hex'), Buffer.from('8da699cd64557618', 'hex')
  ,
  Buffer.from('cee3fe586e46c9cb', 'hex'), Buffer.from('37d1018bf50002ab', 'hex')
  ,
  Buffer.from('6224939a79f5f593', 'hex'), Buffer.from('b0e4a90bdf82009e', 'hex')
  ,
  Buffer.from('f3b9dd94c5bb5d7a', 'hex'), Buffer.from('a7ad6b22462fb3f4', 'hex')
  ,
  Buffer.from('fbe50e86bc8f1e75', 'hex'), Buffer.from('903d84c02756ea14', 'hex')
  ,
  Buffer.from('eef27a8e90ca23f7', 'hex'), Buffer.from('e545be4961ca29a1', 'hex')
  ,
  Buffer.from('db9bc2577fcc2a3f', 'hex'), Buffer.from('9447be2cf5e99a69', 'hex')
  ,
  Buffer.from('9cd38d96f0b3c14b', 'hex'), Buffer.from('bd6179a71dc96dbb', 'hex')
  ,
  Buffer.from('98eea21af25cd6be', 'hex'), Buffer.from('c7673b2eb0cbf2d0', 'hex')
  ,
  Buffer.from('883ea3e395675393', 'hex'), Buffer.from('c8ce5ccd8c030ca8', 'hex')
  ,
  Buffer.from('94af49f6c650adb8', 'hex'), Buffer.from('eab8858ade92e1bc', 'hex')
  ,
  Buffer.from('f315bb5bb835d817', 'hex'), Buffer.from('adcf6b0763612e2f', 'hex')
  ,
  Buffer.from('a5c91da7acaa4dde', 'hex'), Buffer.from('716595876650a2a6', 'hex')
  ,
  Buffer.from('28ef495c53a387ad', 'hex'), Buffer.from('42c341d8fa92d832', 'hex')
  ,
  Buffer.from('ce7cf2722f512771', 'hex'), Buffer.from('e37859f94623f3a7', 'hex')
  ,
  Buffer.from('381205bb1ab0e012', 'hex'), Buffer.from('ae97a10fd434e015', 'hex')
  ,
  Buffer.from('b4a31508beff4d31', 'hex'), Buffer.from('81396229f0907902', 'hex')
  ,
  Buffer.from('4d0cf49ee5d4dcca', 'hex'), Buffer.from('5c73336a76d8bf9a', 'hex')
  ,
  Buffer.from('d0a704536ba93e0e', 'hex'), Buffer.from('925958fcd6420cad', 'hex')
  ,
  Buffer.from('a915c29bc8067318', 'hex'), Buffer.from('952b79f3bc0aa6d4', 'hex')
  ,
  Buffer.from('f21df2e41d4535f9', 'hex'), Buffer.from('87577519048f53a9', 'hex')
  ,
  Buffer.from('10a56cf5dfcd9adb', 'hex'), Buffer.from('eb75095ccd986cd0', 'hex')
  ,
  Buffer.from('51a9cb9ecba312e6', 'hex'), Buffer.from('96afadfc2ce666c7', 'hex')
  ,
  Buffer.from('72fe52975a4364ee', 'hex'), Buffer.from('5a1645b276d592a1', 'hex')
  ,
  Buffer.from('b274cb8ebf87870a', 'hex'), Buffer.from('6f9bb4203de7b381', 'hex')
  ,
  Buffer.from('eaecb2a30b22a87f', 'hex'), Buffer.from('9924a43cc1315724', 'hex')
  ,
  Buffer.from('bd838d3aafbf8db7', 'hex'), Buffer.from('0b1a2a3265d51aea', 'hex')
  ,
  Buffer.from('135079a3231ce660', 'hex'), Buffer.from('932b2846e4d70666', 'hex')
  ,
  Buffer.from('e1915f5cb1eca46c', 'hex'), Buffer.from('f325965ca16d629f', 'hex')
  ,
  Buffer.from('575ff28e60381be5', 'hex'), Buffer.from('724506eb4c328a95', 'hex')
];

function testHash(data, expected) {
  const key = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex');
  const [hi, lo] = siphash(data, key);
  const hash = n64.U64.fromBits(hi, lo).toRaw(Buffer);
  assert.bufferEqual(hash, expected);
}

describe('SipHash', function() {
  it('should perform siphash with no data', () => {
    const data = Buffer.alloc(0);
    const key = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex');
    assert.deepStrictEqual(siphash256(data, key), [1919933255, -586281423]);
  });

  it('should perform siphash with data', () => {
    const data = Buffer.from('0001020304050607', 'hex');
    const key = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex');
    assert.deepStrictEqual(siphash256(data, key), [-1812597383, -1701632926]);
  });

  it('should perform siphash with uint256', () => {
    const data = Buffer.from(
      '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
      'hex');
    const key = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex');
    assert.deepStrictEqual(siphash256(data, key), [1898402095, 1928494286]);
  });

  for (const [i, expected] of vectors.entries()) {
    it(`should get siphash of test case#${i}`, () => {
      let data = Buffer.from('');

      const k = Buffer.from('00', 'hex');
      for (let j=0; j<i; j++) {
        data = Buffer.concat([data, k]);
        k[0]++;
      }

      testHash(data, expected);
    });
  }
});
