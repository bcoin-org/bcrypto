'use strict';

const assert = require('bsert');
const box = require('../lib/box');
const x25519 = require('../lib/x25519');

describe('Box', function() {
  it('should seal and open box (crypto_secretbox_xsalsa20poly1305)', () => {
    const priv1 = Buffer.alloc(32, 1);
    const priv2 = Buffer.alloc(32, 2);
    const pub1 = x25519.publicKeyCreate(priv1);
    const pub2 = x25519.publicKeyCreate(priv2);
    const msg = Buffer.alloc(64, 3);
    const sealed = box.seal(msg, pub1, priv2);
    const opened = box.open(sealed, priv1);

    assert.bufferEqual(sealed.slice(0, 32), pub2);
    assert.bufferEqual(opened, msg);
  });
});
