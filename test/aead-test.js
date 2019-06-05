'use strict';

const assert = require('bsert');
const AEAD = require('../lib/aead');
const vectors = require('./data/aead.json');

describe('AEAD (ChaCha20+Poly1305)', function() {
  for (const [plain_, aad_, key_, nonce_, raw_, pk_] of vectors) {
    const input = Buffer.from(plain_, 'hex');
    const aad = Buffer.from(aad_, 'hex');
    const key = Buffer.from(key_, 'hex');
    const nonce = Buffer.from(nonce_, 'hex');
    const raw = Buffer.from(raw_, 'hex');
    const output = raw.slice(0, -16);
    const tag = raw.slice(-16);
    const pk = Buffer.from(pk_ || '', 'hex');
    const text = key_.slice(0, 32) + '...';

    it(`should do encrypt and decrypt (${text})`, () => {
      const data = Buffer.from(input);
      const ctx = new AEAD();

      ctx.init(key, nonce);

      if (ctx.chacha20 && pk.length > 0)
        assert.bufferEqual(ctx.polyKey, pk);

      ctx.aad(aad);
      ctx.encrypt(data);

      assert.bufferEqual(data, output);
      assert.bufferEqual(ctx.final(), tag);

      ctx.init(key, nonce);

      if (ctx.chacha20 && pk.length > 0)
        assert.bufferEqual(ctx.polyKey, pk);

      ctx.aad(aad);
      ctx.decrypt(data);

      assert.bufferEqual(data, input);
      assert.bufferEqual(ctx.final(), tag);
    });

    it(`should do one-shot encrypt and decrypt (${text})`, () => {
      const data = Buffer.from(input);
      const mac = AEAD.encrypt(key, nonce, data, aad);

      assert.bufferEqual(data, output);
      assert.bufferEqual(mac, tag);

      assert(AEAD.decrypt(key, nonce, data, tag, aad));
      assert.bufferEqual(data, input);

      AEAD.encrypt(key, nonce, data, aad);

      key[0] ^= 1;

      assert(!AEAD.decrypt(key, nonce, Buffer.from(data), tag, key));

      key[0] ^= 1;

      assert(AEAD.decrypt(key, nonce, Buffer.from(data), tag, aad));

      nonce[0] ^= 1;

      assert(!AEAD.decrypt(key, nonce, Buffer.from(data), tag, key));

      nonce[0] ^= 1;

      assert(AEAD.decrypt(key, nonce, Buffer.from(data), tag, aad));

      tag[0] ^= 1;

      assert(!AEAD.decrypt(key, nonce, Buffer.from(data), tag, key));

      tag[0] ^= 1;

      assert(AEAD.decrypt(key, nonce, Buffer.from(data), tag, aad));

      if (data.length > 0) {
        data[0] ^= 1;

        assert(!AEAD.decrypt(key, nonce, Buffer.from(data), tag, aad));

        data[0] ^= 1;

        assert(AEAD.decrypt(key, nonce, Buffer.from(data), tag, aad));
      }

      if (aad.length > 0) {
        aad[0] ^= 1;

        assert(!AEAD.decrypt(key, nonce, Buffer.from(data), tag, aad));

        aad[0] ^= 1;

        assert(AEAD.decrypt(key, nonce, Buffer.from(data), tag, aad));
      }
    });
  }
});
