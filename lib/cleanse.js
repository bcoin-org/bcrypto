/*!
 * cleanse.js - cleanse for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 */

'use strict';

try {
  module.exports = require('./native/cleanse');
} catch (e) {
  module.exports = require('./node/cleanse');
}
