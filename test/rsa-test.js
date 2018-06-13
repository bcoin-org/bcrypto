/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const SHA256 = require('../lib/sha256');
const rsa = require('../lib/rsa');
const {RSAPrivateKey, RSAPublicKey} = rsa;

const msg = Buffer.from('foobar', 'ascii');

describe('RSA', function() {
  this.timeout(15000);

  it('should generate keypair', () => {
    const privRaw = rsa.privateKeyGenerate(1024);
    const pubRaw = rsa.publicKeyCreate(privRaw);

    const priv = RSAPrivateKey.decode(privRaw);
    assert.bufferEqual(priv.encode(), privRaw);
    assert(rsa.privateVerify(priv));

    const pub = RSAPublicKey.decode(pubRaw);
    assert.bufferEqual(pub.encode(), pubRaw);
    assert(rsa.publicVerify(pub));

    const privPem = priv.toPEM();
    assert(typeof privPem === 'string');
    assert.deepStrictEqual(RSAPrivateKey.fromPEM(privPem), priv);

    const pubPem = pub.toPEM();
    assert(typeof pubPem === 'string');
    assert.deepStrictEqual(RSAPublicKey.fromPEM(pubPem), pub);
  });

  it('should sign and verify', () => {
    const priv = rsa.privateKeyGenerate(2048);
    const pub = rsa.publicKeyCreate(priv);

    assert(rsa.privateKeyVerify(priv));
    assert(rsa.publicKeyVerify(pub));

    const sig = rsa.sign(SHA256, msg, priv);
    const valid = rsa.verify(SHA256, msg, sig, pub);

    assert(valid);
  });

  it('should sign and verify (async)', async () => {
    const bits = rsa.native < 2 ? 1024 : 4096;
    const priv = await rsa.privateKeyGenerateAsync(bits);
    const pub = rsa.publicKeyCreate(priv);

    assert(rsa.privateKeyVerify(priv));
    assert(rsa.publicKeyVerify(pub));

    const sig = rsa.sign(SHA256, msg, priv);
    const valid = rsa.verify(SHA256, msg, sig, pub);

    assert(valid);
  });
});
