/*!
 * cleanse.js - memzero for bcoin
 * Copyright (c) 2016-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const crypto = require('crypto');

/**
 * A maybe-secure memzero.
 * @param {Buffer} data
 */

module.exports = function cleanse(data) {
  crypto.randomFillSync(data, 0, data.length);
};
