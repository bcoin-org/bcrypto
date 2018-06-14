/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const SHA256 = require('../lib/sha256');
const rfc6962 = require('../lib/rfc6962');
const random = require('../lib/random');

describe('RFC6962', function() {
  it('should create perfect tree', () => {
    const leaves = [];

    for (let i = 0; i < 32; i++)
      leaves.push(random.randomBytes(32));

    const root1 = rfc6962.createRoot(SHA256, leaves);

    const branch = rfc6962.createBranch(SHA256, 15, leaves);
    const root2 = rfc6962.deriveRoot(SHA256, leaves[15], branch, 15);

    assert.bufferEqual(root2, root1);
  });

  it('should create imperfect tree', () => {
    const leaves = [];

    for (let i = 0; i < 11; i++)
      leaves.push(random.randomBytes(32));

    const root1 = rfc6962.createRoot(SHA256, leaves);

    const branch2 = rfc6962.createBranch(SHA256, 3, leaves);
    const root2 = rfc6962.deriveRoot(SHA256, leaves[3], branch2, 3);

    assert.bufferEqual(root2, root1);

    const branch3 = rfc6962.createBranch(SHA256, 10, leaves);
    const root3 = rfc6962.deriveRoot(SHA256, leaves[10], branch3, 10);

    assert.bufferEqual(root3, root1);
  });

  it('should not be malleable', () => {
    const leaves = [];

    for (let i = 0; i < 11; i++)
      leaves.push(random.randomBytes(32));

    const root1 = rfc6962.createRoot(SHA256, leaves);

    leaves.push(leaves[10]);

    const root2 = rfc6962.createRoot(SHA256, leaves);

    assert.notBufferEqual(root2, root1);
  });
});
