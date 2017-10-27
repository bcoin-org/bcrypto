/*!
 * cleanse.js - cleanse for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 */

'use strict';

try {
  module.exports = require('./native/cleanse');
} catch (e) {
  if (process.env.BCRYPTO_USE_JS)
    module.exports = require('./js/cleanse');
  else
    module.exports = require('./node/cleanse');
}
