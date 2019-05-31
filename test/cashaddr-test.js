// Copyright (c) 2018 the bcoin developers
//
// Parts of this software are based on "CashAddr".
// https://github.com/Bitcoin-ABC/bitcoin-abc
//
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
const base58 = require('../lib/encoding/base58');
const cashaddr = require('../lib/encoding/cashaddr');
const js = require('../lib/js/cashaddr');
const translationVectors = require('./data/cashaddrlegacy.json');
const sizeVectors = require('./data/cashaddrsizes.json');
const encodeVectors = require('./data/cashaddrinvalidencode.json');
const decodeVectors = require('./data/cashaddrinvaliddecode.json');
const edgeVectors = require('./data/cashaddredge.json');

function test(cashaddr) {
  describe('Encoding', () => {
    for (const test of sizeVectors) {
      const text = test.addr.slice(0, 32) + '...';

      it(`should encode address ${text} (${test.bytes} bytes)`, () => {
        const addr = cashaddr.encode(test.prefix, test.type,
                                     Buffer.from(test.hash, 'hex'));

        assert.strictEqual(addr, test.addr);
      });

      it(`should decode address ${text} (${test.bytes} bytes)`, () => {
        const [prefix, type, hash] = cashaddr.decode(test.addr, test.prefix);

        assert.strictEqual(prefix, test.prefix);
        assert.strictEqual(type, test.type);
        assert.bufferEqual(hash, Buffer.from(test.hash, 'hex'));
      });
    }
  });

  describe('Translation', () => {
    for (const translation of translationVectors.p2pkh) {
      const text = translation.legacy.slice(0, 32) + '...';

      it(`should translate base58 P2PKH for ${text}`, () => {
        const prefix = 'bitcoincash';
        const type = 0;
        const hash = base58.decode(translation.legacy).slice(1, -4);
        const addr = cashaddr.encode(prefix, type, hash);

        assert.strictEqual(addr, translation.cashaddr);
      });
    }

    for (const translation of translationVectors.p2sh) {
      const text = translation.legacy.slice(0, 32) + '...';

      it(`should translate base58 P2SH for ${text}`, () => {
        const prefix = 'bitcoincash';
        const type = 1;
        const hash = base58.decode(translation.legacy).slice(1, -4);
        const addr = cashaddr.encode(prefix, type, hash);

        assert.strictEqual(addr, translation.cashaddr);
      });
    }

    for (const addrinfo of translationVectors.p2pkh) {
      const text = addrinfo.cashaddr.slice(0, 32) + '...';

      it(`should decode P2PKH for ${text}`, () => {
        const addr = addrinfo.cashaddr;
        const [prefix, type, hash] = cashaddr.decode(addr);

        assert.strictEqual(prefix, 'bitcoincash');
        assert.strictEqual(type, 0);
        assert.bufferEqual(hash, Buffer.from(addrinfo.hash, 'hex'));
      });

      it(`should encode P2PKH for ${text}`, () => {
        const addr = cashaddr.encode('bitcoincash', 0,
                                     Buffer.from(addrinfo.hash, 'hex'));

        assert.strictEqual(addr, addrinfo.cashaddr);
      });
    }

    for (const addrinfo of translationVectors.p2sh) {
      const text = addrinfo.cashaddr.slice(0, 32) + '...';

      it(`should decode P2SH for ${text}`, () => {
        const addr = addrinfo.cashaddr;
        const [prefix, type, hash] = cashaddr.decode(addr);

        assert.strictEqual(prefix, 'bitcoincash');
        assert.strictEqual(type, 1);
        assert.bufferEqual(hash, Buffer.from(addrinfo.hash, 'hex'));
      });

      it(`should encode P2SH for ${text}`, () => {
        const addr = cashaddr.encode('bitcoincash', 1,
                                     Buffer.from(addrinfo.hash, 'hex'));

        assert.strictEqual(addr, addrinfo.cashaddr);
      });
    }

    for (const addrinfo of translationVectors.p2pkh) {
      const text = addrinfo.cashaddr.slice(0, 32) + '...';

      it(`should decode P2PKH with prefix ${text}`, () => {
        const addr = addrinfo.cashaddr.split(':')[1];
        const defaultPrefix = 'bitcoincash';
        const [prefix, type, hash] = cashaddr.decode(addr, defaultPrefix);

        assert.strictEqual(prefix, 'bitcoincash');
        assert.strictEqual(type, 0);
        assert.bufferEqual(hash, Buffer.from(addrinfo.hash, 'hex'));
      });

      it(`should decode P2PKH with default prefix ${text}`, () => {
        const addr = addrinfo.cashaddr.split(':')[1];
        const [prefix, type, hash] = cashaddr.decode(addr);

        assert.strictEqual(prefix, 'bitcoincash');
        assert.strictEqual(type, 0);
        assert.bufferEqual(hash, Buffer.from(addrinfo.hash, 'hex'));
      });
    }

    for (const addrinfo of translationVectors.p2sh) {
      const text = addrinfo.cashaddr.slice(0, 32) + '...';

      it(`should decode P2Sh with prefix ${text}`, () => {
        const addr = addrinfo.cashaddr.split(':')[1];
        const defaultPrefix = 'bitcoincash';
        const [prefix, type, hash] = cashaddr.decode(addr, defaultPrefix);

        assert.strictEqual(prefix, 'bitcoincash');
        assert.strictEqual(type, 1);
        assert.bufferEqual(hash, Buffer.from(addrinfo.hash, 'hex'));
      });

      it(`should decode P2Sh with default prefix ${text}`, () => {
        const addr = addrinfo.cashaddr.split(':')[1];
        const [prefix, type, hash] = cashaddr.decode(addr);

        assert.strictEqual(prefix, 'bitcoincash');
        assert.strictEqual(type, 1);
        assert.bufferEqual(hash, Buffer.from(addrinfo.hash, 'hex'));
      });
    }
  });

  describe('Invalid Encoding', () => {
    for (const test of encodeVectors) {
      it(`"${test.reason}" (${test.note})`, () => {
        let err;

        try {
          cashaddr.encode(test.prefix, test.type,
                          Buffer.from(test.hash, 'hex'));
        } catch(e) {
          err = e;
        }

        assert(err, 'Exception error missing.');
        assert.strictEqual(err.message, test.reason);
      });
    }
  });

  describe('Invalid Decoding', () => {
    for (const addrinfo of decodeVectors) {
      const text = addrinfo.addr.slice(0, 32) + '...';

      it(`"${addrinfo.reason}" w/ invalid address ${text}`, () => {
        let err;

        try {
          cashaddr.decode(addrinfo.addr, addrinfo.prefix);
        } catch(e) {
          err = e;
        }

        assert(err, 'Exception error missing.');
        assert.strictEqual(err.message, addrinfo.reason);
      });
    }
  });

  describe('Edge Cases', () => {
    for (const test of edgeVectors) {
      const text = test.addr.slice(0, 32) + '...';

      it(`encode ${test.note} with address: ${text}`, () => {
        const addr = cashaddr.encode(test.prefix, test.type,
                                     Buffer.from(test.hash, 'hex'));
        assert.strictEqual(addr, test.addr.toLowerCase());
      });

      it(`decode ${test.note} with address: ${text}`, () => {
        const [prefix, type, hash] = cashaddr.decode(
          test.addr, test.prefix.toLowerCase());

        assert.strictEqual(prefix.toLowerCase(), test.prefix.toLowerCase());
        assert.strictEqual(type, test.type);
        assert.bufferEqual(hash, Buffer.from(test.hash, 'hex'));
      });

      it(`round trip ${test.note} with address: ${text}`, () => {
        const addr = cashaddr.encode(test.prefix, test.type,
                                     Buffer.from(test.hash, 'hex'));

        assert.strictEqual(addr, test.addr.toLowerCase());

        const [prefix, type, hash] = cashaddr.decode(
          test.addr, test.prefix.toLowerCase());

        assert.strictEqual(prefix.toLowerCase(), test.prefix.toLowerCase());
        assert.strictEqual(type, test.type);
        assert.bufferEqual(hash, Buffer.from(test.hash, 'hex'));
      });
    }
  });
}

describe('Cash Address', function() {
  test.call(this, cashaddr);
});

describe('Cash Address (JS)', function() {
  test.call(this, js);
});
