/*!
 * poly1305.js - poly1305 for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 */

'use strict';

try {
  module.exports = require('./native/poly1305');
} catch (e) {
  module.exports = require('./node/poly1305');
}
