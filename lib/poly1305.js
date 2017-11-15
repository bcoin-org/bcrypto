/*!
 * poly1305.js - poly1305 for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 */

'use strict';

try {
  module.exports = require('./native/poly1305');
} catch (e) {
  if (process.env.NODE_BACKEND === 'js')
    module.exports = require('./js/poly1305');
  else
    module.exports = require('./node/poly1305');
}
