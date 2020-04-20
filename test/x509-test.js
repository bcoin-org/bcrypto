'use strict';

const assert = require('bsert');
const fs = require('fs');
const Path = require('path');
const x509 = require('../lib/encoding/x509');
const pem = require('../lib/encoding/pem');

const file = Path.resolve(__dirname, 'data', 'certs.pem');
const data = fs.readFileSync(file, 'utf8');

describe('X509', function() {
  if (process.env.BMOCHA_VALGRIND)
    this.skip();

  let i = 0;

  for (const block of pem.decode(data)) {
    it(`should deserialize and reserialize certificate (${i++})`, () => {
      const crt1 = x509.Certificate.decode(block.data);
      const raw1 = crt1.encode();
      const crt2 = x509.Certificate.decode(raw1);
      const raw2 = crt2.encode();

      assert.deepStrictEqual(crt1, crt2);
      assert.bufferEqual(raw1, raw2);
      assert.bufferEqual(raw1, block.data);
    });

    it(`should read JSON and write JSON (${i++})`, () => {
      const crt1 = x509.Certificate.decode(block.data);
      const json1 = crt1.getJSON();

      const crt2 = x509.Certificate.fromJSON(json1);
      const raw2 = crt2.encode();
      const json2 = crt1.getJSON();

      assert.deepStrictEqual(json1, json2);
      assert.bufferEqual(raw2, block.data);
    });
  }
});
