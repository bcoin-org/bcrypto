/*!
 * aes.js - aes for bcoin
 * Copyright (c) 2016-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const binding = require('./binding');

exports.encipher = binding.encipher;
exports.decipher = binding.decipher;
