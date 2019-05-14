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

    const expect = 'b0bdeb693eef197be42a41ee20039e052e87e5b2'
                 + 'dc8d44d77d9d26f075571684deb8521accd1ae72'
                 + '6edab1127f1c4588ea4658f81c12af1873af2a39'
                 + 'c626f128fa64c3d59008bfa7f8ef57a7b3bac09a';

    assert.bufferEqual(sealed.slice(0, 32), pub2);
    assert.bufferEqual(sealed.slice(32 + 24), expect, 'hex');
    assert.bufferEqual(opened, msg);
  });
});
