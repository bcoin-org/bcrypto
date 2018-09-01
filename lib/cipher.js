/*!
 * cipher.js - cipher for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 */

'use strict';

try {
  module.exports = require('./native/cipher');
} catch (e) {
  if (process.env.NODE_BACKEND === 'js')
    module.exports = require('./js/cipher');
  else
    module.exports = require('./node/cipher');
}
