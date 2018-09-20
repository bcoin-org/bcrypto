/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */
/* eslint no-unused-vars: "off" */

'use strict';

const assert = require('./util/assert');
const fs = require('fs');
const Path = require('path');
const bio = require('bufio');
const dsa = require('../lib/dsa');
const asn1 = require('../lib/encoding/asn1');
const pkcs8 = require('../lib/encoding/pkcs8');

const DSA_PUB_PATH = Path.resolve(__dirname, 'data', 'testdsapub.pem');

const dsaPubPem = fs.readFileSync(DSA_PUB_PATH, 'utf8');

describe('PKCS8', function() {
  it('should parse PKCS8', () => {
    const pki = pkcs8.PublicKeyInfo.fromPEM(dsaPubPem);

    assert.strictEqual(pki.algorithm.algorithm.getKeyAlgorithmName(), 'DSA');
    assert.strictEqual(pki.algorithm.parameters.node.type, 16); // SEQ
    assert.strictEqual(pki.publicKey.type, 3); // BITSTRING
    assert.strictEqual(pki.publicKey.bits, 1056);

    const br = bio.read(pki.algorithm.parameters.node.value);
    const p = asn1.Integer.read(br);
    const q = asn1.Integer.read(br);
    const g = asn1.Integer.read(br);
    const y = asn1.Integer.decode(pki.publicKey.align());
    const key = new dsa.DSAPublicKey();

    key.setP(p.value);
    key.setQ(q.value);
    key.setG(g.value);
    key.setY(y.value);

    assert(dsa.publicKeyVerify(key));

    assert.strictEqual(pki.toPEM(), dsaPubPem);
  });
});
