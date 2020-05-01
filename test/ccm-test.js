'use strict';

const assert = require('bsert');
const AES = require('../lib/js/ciphers/aes');
const {CCMCipher, CCMDecipher} = require('../lib/js/ciphers/modes');

describe('CCM', function() {
  it('should compute ccm (1)', () => {
    const key = Buffer.from('1234567890123456');
    const iv = Buffer.from('1234567890123');
    const pt = Buffer.from('12345678901234567');
    const ct = Buffer.from('3e21f2abd8fbad18787c25b897f394953f', 'hex');
    const tag = Buffer.from('75032cf4222d872a', 'hex');
    const aad = Buffer.alloc(0);
    const c = new CCMCipher(new AES(128));
    const d = new CCMDecipher(new AES(128));

    c.init(key, iv);
    c.initCCM(pt.length, tag.length, aad);

    d.init(key, iv);
    d.initCCM(ct.length, tag.length, aad);
    d.setAuthTag(tag);

    const ct0 = c.update(pt);

    c.final();

    const mac = c.getAuthTag();

    assert.bufferEqual(mac, tag);
    assert.bufferEqual(ct0, ct);

    const pt0 = d.update(ct);

    d.final();

    assert.bufferEqual(pt0, pt);
  });

  it('should compute ccm (2)', () => {
    const key = Buffer.from('1234567890123456');
    const iv = Buffer.from('1234567890123');
    const pt = Buffer.from('1234567890123456');
    const ct = Buffer.from('3e21f2abd8fbad18787c25b897f39495', 'hex');
    const tag = Buffer.from('ce3866fa1148c868', 'hex');
    const aad = Buffer.alloc(0);
    const c = new CCMCipher(new AES(128));
    const d = new CCMDecipher(new AES(128));

    c.init(key, iv);
    c.initCCM(pt.length, tag.length, aad);

    d.init(key, iv);
    d.initCCM(ct.length, tag.length, aad);
    d.setAuthTag(tag);

    const ct0 = c.update(pt);

    c.final();

    const mac = c.getAuthTag();

    assert.bufferEqual(mac, tag);
    assert.bufferEqual(ct0, ct);

    const pt0 = d.update(ct);

    d.final();

    assert.bufferEqual(pt0, pt);
  });
});
