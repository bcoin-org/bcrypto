'use strict';

const assert = require('bsert');
const Poly1305 = require('../lib/poly1305');
const vectors = require('./data/poly1305.json');

describe('Poly1305', function() {
  it('should perform poly1305 (1)', () => {
    const key = Buffer.allocUnsafe(32);
    const msg = Buffer.allocUnsafe(73);
    const tag = Buffer.from('ddb9da7ddd5e52792730ed5cda5f90a4', 'hex');

    for (let i = 0; i < key.length; i++)
      key[i] = i + 221;

    for (let i = 0; i < msg.length; i++)
      msg[i] = i + 121;

    const mac = Poly1305.auth(msg, key);

    assert(Poly1305.verify(mac, tag));
    assert.bufferEqual(mac, tag);

    mac[0] ^= 1;

    assert(!Poly1305.verify(mac, tag));
  });

  it('should perform poly1305 (2)', () => {
    const key = Buffer.from('85d6be7857556d337f4452fe42d506a'
                          + '80103808afb0db2fd4abff6af4149f51b', 'hex');
    const msg = Buffer.from('Cryptographic Forum Research Group', 'ascii');
    const tag = Buffer.from('a8061dc1305136c6c22b8baf0c0127a9', 'hex');
    const mac = Poly1305.auth(msg, key);

    assert(Poly1305.verify(mac, tag));

    mac[0] ^= 1;

    assert(!Poly1305.verify(mac, tag));
  });

  for (const [key_, msg_, tag_] of vectors) {
    const msg = Buffer.from(msg_, 'hex');
    const key = Buffer.from(key_, 'hex');
    const tag = Buffer.from(tag_, 'hex');
    const text = key_.slice(0, 32) + '...';

    it(`should perform poly1305 (${text})`, () => {
      const mac = Poly1305.auth(msg, key);

      assert(Poly1305.verify(mac, tag));
      assert.bufferEqual(mac, tag);

      mac[0] ^= 1;

      assert(!Poly1305.verify(mac, tag));
    });
  }
});
