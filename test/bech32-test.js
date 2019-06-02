// Parts of this software are based on "bech32".
// https://github.com/sipa/bech32
//
// Copyright (c) 2017 Pieter Wuille
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

'use strict';

const assert = require('bsert');
const bech32 = require('../lib/encoding/bech32');
const vectors = require('./data/bech32.json');

const validAddresses = [
  [
    'BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4',
    '0014751e76e8199196d454941c45d1b3a323f1433bd6'
  ],
  [
    'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7',
    '00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262'
  ],
  [
    'bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx',
    '8128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6'
  ],
  [
    'BC1SW50QA3JX3S',
    '9002751e'
  ],
  [
    'bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj',
    '8210751e76e8199196d454941c45d1b3a323'
  ],
  [
    'tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy',
    '0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433'
  ]
];

const invalidAddresses = [
  'tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty',
  'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5',
  'BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2',
  'bc1rw5uspcuh',
  'bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90',
  'bca0w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90234567789035',
  'BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P',
  'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7',
  'tb1pw508d6qejxtdg4y5r3zarqfsj6c3',
  'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv',
  'wtfbbqhelpnoshitwe2z5nuhllhu6z8pptu8m36clzge37dnfsdquht73wsx4cmwcwql322x3gmmwq2gjuxp6eaaus',
  'bcfbbqhelpnoshitwe2z7anje5j3wvz8hw3rxadzcppgghm0aec23ttfstphjegfx08hwk5uhmusa7j28yrk8cx4qj'
];

const invalidIs = [
  'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5',
  'bca0w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90234567789035',
  'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7',
  'wtfbbqhelpnoshitwe2z5nuhllhu6z8pptu8m36clzge37dnfsdquht73wsx4cmwcwql322x3gmmwq2gjuxp6eaaus',
  'bcfbbqhelpnoshitwe2z7anje5j3wvz8hw3rxadzcppgghm0aec23ttfstphjegfx08hwk5uhmusa7j28yrk8cx4qj'
];

const invalidTest = [
  'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5',
  'bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90',
  'bca0w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90234567789035',
  'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7',
  'wtfbbqhelpnoshitwe2z5nuhllhu6z8pptu8m36clzge37dnfsdquht73wsx4cmwcwql322x3gmmwq2gjuxp6eaaus',
  'bcfbbqhelpnoshitwe2z7anje5j3wvz8hw3rxadzcppgghm0aec23ttfstphjegfx08hwk5uhmusa7j28yrk8cx4qj'
];

function encode(hrp, version, hash) {
  const addr = bech32.encode(hrp, version, hash);

  decode(hrp, addr);

  return addr;
}

function decode(expect, addr) {
  const [hrp, version, hash] = bech32.decode(addr);

  if (hrp !== expect)
    throw new Error('Invalid bech32 prefix or data length.');

  if (version === 0 && hash.length !== 20 && hash.length !== 32)
    throw new Error('Malformed witness program.');

  if (version > 16)
    throw new Error('Malformed witness program.');

  return [hrp, version, hash];
}

function encodeManual(hrp, version, hash, lax) {
  const data = bech32.convertBits(hash, 8, 5, true);
  const addr = bech32.serialize(hrp, concat(version, data));

  decodeManual(hrp, addr, lax);

  return addr;
}

function decodeManual(expect, addr, lax = false) {
  const [hrp, data] = bech32.deserialize(addr);

  if (!lax) {
    if (hrp !== expect || data.length < 1 || data[0] > 16)
      throw new Error('Invalid bech32 prefix or data length.');
  }

  const hash = bech32.convertBits(data.slice(1), 5, 8, false);

  if (!lax) {
    if (hash.length < 2 || hash.length > 40)
      throw new Error('Invalid witness program size.');
  }

  if (!lax) {
    if (data[0] === 0 && hash.length !== 20 && hash.length !== 32)
      throw new Error('Malformed witness program.');
  }

  return [hrp, data[0], hash];
}

function program(version, hash) {
  const data = Buffer.allocUnsafe(2 + hash.length);
  data[0] = version ? version + 0x80 : 0;
  data[1] = hash.length;
  hash.copy(data, 2);
  return data;
}

function concat(version, hash) {
  const buf = Buffer.allocUnsafe(1 + hash.length);
  buf[0] = version;
  hash.copy(buf, 1);
  return buf;
}

describe('Bech32', function() {
  for (const [addr, script_] of validAddresses) {
    const script = Buffer.from(script_, 'hex');
    const text = addr.slice(0, 32) + '...';

    it(`should have valid address for ${text}`, () => {
      let expect = 'bc';
      let hrp, version, hash;

      try {
        [hrp, version, hash] = decode(expect, addr);
      } catch (e) {
        hrp = null;
      }

      if (hrp === null) {
        expect = 'tb';
        try {
          [hrp, version, hash] = decode(expect, addr);
        } catch (e) {
          hrp = null;
        }
      }

      assert(hrp !== null);
      assert.bufferEqual(program(version, hash), script);
      assert.strictEqual(encode(hrp, version, hash), addr.toLowerCase());
      assert.strictEqual(bech32.test(addr), true);
    });
  }

  for (const addr of invalidAddresses) {
    const text = addr.slice(0, 32) + '...';

    it(`should have invalid address for ${text}`, () => {
      assert.throws(() => decode('bc', addr));
      assert.throws(() => decode('tb', addr));
    });
  }

  for (const [addr, script_] of validAddresses) {
    const script = Buffer.from(script_, 'hex');
    const text = addr.slice(0, 32) + '...';

    it(`should have valid address for ${text}`, () => {
      let expect = 'bc';
      let hrp, version, hash;

      try {
        [hrp, version, hash] = decodeManual(expect, addr);
      } catch (e) {
        hrp = null;
      }

      if (hrp === null) {
        expect = 'tb';
        try {
          [hrp, version, hash] = decodeManual(expect, addr);
        } catch (e) {
          hrp = null;
        }
      }

      assert(hrp !== null);
      assert.bufferEqual(program(version, hash), script);
      assert.strictEqual(encodeManual(hrp, version, hash), addr.toLowerCase());
      assert.strictEqual(bech32.test(addr), true);
      assert.strictEqual(bech32.is(addr), true);
    });
  }

  for (const addr of invalidAddresses) {
    const text = addr.slice(0, 32) + '...';

    it(`should have invalid address for ${text}`, () => {
      assert.throws(() => decodeManual('bc', addr));
      assert.throws(() => decodeManual('tb', addr));
    });
  }

  for (const addr of invalidIs) {
    const text = addr.slice(0, 32) + '...';

    it(`should have invalid address for ${text}`, () => {
      assert.throws(() => bech32.deserialize(addr));
      assert.strictEqual(bech32.is(addr), false);
    });
  }

  for (const addr of invalidTest) {
    const text = addr.slice(0, 32) + '...';

    it(`should have invalid address for ${text}`, () => {
      assert.throws(() => bech32.decode(addr));
      assert.strictEqual(bech32.test(addr), false);
    });
  }

  for (const [hrp, version, hex, addr1] of vectors) {
    const text = addr1.slice(0, 32) + '...';
    const hash = Buffer.from(hex, 'hex');

    it(`should decode and reserialize ${text}`, () => {
      const [hrp_, version_, hash_] = bech32.decode(addr1);

      assert.strictEqual(hrp_, hrp);
      assert.strictEqual(version_, version);
      assert.bufferEqual(hash_, hash);

      const addr2 = bech32.encode(hrp, version, hash);

      assert.strictEqual(addr2, addr1.toLowerCase());
    });

    it(`should decode and reserialize ${text}`, () => {
      const [hrp_, version_, hash_] = decodeManual(hrp, addr1, true);

      assert.strictEqual(hrp_, hrp);
      assert.strictEqual(version_, version);
      assert.bufferEqual(hash_, hash);

      const addr2 = encodeManual(hrp, version, hash, true);

      assert.strictEqual(addr2, addr1.toLowerCase());
    });
  }
});
