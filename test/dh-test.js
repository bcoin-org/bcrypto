'use strict';

const assert = require('bsert');
const fs = require('fs');
const dh = require('../lib/dh');
const pem = require('../lib/encoding/pem');
const pem1 = fs.readFileSync(`${__dirname}/data/dhparams.pem`, 'utf8');
const pem2 = fs.readFileSync(`${__dirname}/data/dhpriv1.pem`, 'utf8');
const pem3 = fs.readFileSync(`${__dirname}/data/dhpub1.pem`, 'utf8');
const pem4 = fs.readFileSync(`${__dirname}/data/dhpriv2.pem`, 'utf8');
const pem5 = fs.readFileSync(`${__dirname}/data/dhpub2.pem`, 'utf8');
const data1 = pem.fromPEM(pem1, 'DH PARAMETERS');
const data2 = pem.fromPEM(pem2, 'PRIVATE KEY');
const data3 = pem.fromPEM(pem3, 'PUBLIC KEY');
const data4 = pem.fromPEM(pem4, 'PRIVATE KEY');
const data5 = pem.fromPEM(pem5, 'PUBLIC KEY');

describe('DH', function() {
  this.timeout(30000);

  it('should generate and exchange', () => {
    const params = dh.paramsGenerate(1024, 2);
    const priv = dh.privateKeyCreate(params);
    const pub = dh.publicKeyCreate(priv);

    assert(dh.privateKeyVerify(priv));
    assert(dh.publicKeyVerify(pub));

    assert.deepStrictEqual(
      dh.privateKeyImport(dh.privateKeyExport(priv)),
      priv);

    assert.deepStrictEqual(
      dh.privateKeyImportPKCS8(dh.privateKeyExportPKCS8(priv)),
      priv);

    assert.deepStrictEqual(
      dh.privateKeyImportJWK(dh.privateKeyExportJWK(priv)),
      priv);

    assert.deepStrictEqual(
      dh.publicKeyImport(dh.publicKeyExport(pub)),
      pub);

    assert.deepStrictEqual(
      dh.publicKeyImportSPKI(dh.publicKeyExportSPKI(pub)),
      pub);

    assert.deepStrictEqual(
      dh.publicKeyImportJWK(dh.publicKeyExportJWK(pub)),
      pub);

    const alicePriv = priv;
    const alicePub = pub;
    const bobPriv = dh.privateKeyCreate(params);
    const bobPub = dh.publicKeyCreate(bobPriv);

    assert(dh.privateKeyVerify(alicePriv));
    assert(dh.publicKeyVerify(alicePub));
    assert(dh.privateKeyVerify(bobPriv));
    assert(dh.publicKeyVerify(bobPub));

    const aliceSecret = dh.derive(bobPub, alicePriv);
    const bobSecret = dh.derive(alicePub, bobPriv);
    const x = dh.exchange(alicePub.y, bobPriv);

    assert.bufferEqual(aliceSecret, bobSecret);
    assert.bufferEqual(x, bobSecret);
  });

  it('should exchange (vector)', () => {
    const params = dh.paramsImport(data1);
    const alicePriv = dh.privateKeyImport(data2);
    const alicePub = dh.publicKeyImport(data3);
    const bobPriv = dh.privateKeyImport(data4);
    const bobPub = dh.publicKeyImport(data5);

    assert(dh.paramsVerify(params));
    assert(dh.privateKeyVerify(alicePriv));
    assert(dh.publicKeyVerify(alicePub));
    assert(dh.privateKeyVerify(bobPriv));
    assert(dh.publicKeyVerify(bobPub));

    assert.deepStrictEqual(alicePriv.toParams(), params);
    assert.deepStrictEqual(alicePub.toParams(), params);
    assert.deepStrictEqual(bobPriv.toParams(), params);
    assert.deepStrictEqual(bobPub.toParams(), params);

    assert.bufferEqual(dh.paramsExport(params), data1);
    assert.bufferEqual(dh.privateKeyExport(alicePriv), data2);
    assert.bufferEqual(dh.publicKeyExport(alicePub), data3);
    assert.bufferEqual(dh.privateKeyExport(bobPriv), data4);
    assert.bufferEqual(dh.publicKeyExport(bobPub), data5);

    const aliceSecret = dh.derive(bobPub, alicePriv);
    const bobSecret = dh.derive(alicePub, bobPriv);
    const x = dh.exchange(alicePub.y, bobPriv);

    assert.bufferEqual(aliceSecret, bobSecret);
    assert.bufferEqual(x, bobSecret);

    // Generated with:
    //   const crypto = require('crypto');
    //   const d = crypto.createDiffieHellman(params.p, null, params.g, null);
    //   d.setPrivateKey(alicePriv.x, null);
    //   const s = d.computeSecret(bobPub.y, null, null);
    assert.bufferEqual(x, ''
      + '5908efe83e488000e4a842effe425caedc6acd77902d42d5fa'
      + '4cc839534e0c5d0606cdb419397041891611771dd8ae6dd2b8'
      + 'a676b0725c7adc76017851dadbfa1f62dc2642513e4d1692a3'
      + '81375f78b8cd8c76b608f4e48afac1d2bad9b72054639967fc'
      + 'c1976993e507679fa49f0f11180158c0ce30bb06b1a041014d'
      + '078cdf');
  });
});
