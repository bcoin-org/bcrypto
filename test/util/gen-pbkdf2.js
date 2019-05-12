'use strict';

const fs = require('fs');
const crypto = require('crypto');

function testVector() {
  const passwd = crypto.randomBytes(Math.random() * 64 | 0);
  const salt = crypto.randomBytes(Math.random() * 32 | 0);
  const iter = crypto.randomRange(1, 5000);
  const len = crypto.randomRange(1, 64);
  const expect = crypto.pbkdf2Sync(passwd, salt, iter, len, 'sha256');

  return {
    passwd,
    salt,
    iter,
    len,
    expect
  };
}
const vectors = [];

for (let i = 0; i < 50; i++) {
  const {passwd, salt, iter, len, expect} = testVector();

  vectors.push([
    passwd.toString('hex'),
    salt.toString('hex'),
    iter,
    len,
    expect.toString('hex')
  ]);
}

fs.writeFileSync(`${__dirname}/../data/pbkdf2.json`,
  JSON.stringify(vectors, null, 2) + '\n');
