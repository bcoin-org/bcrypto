/*!
 * siphash.js - siphash for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const binding = require('./binding');

exports = binding.siphash;
exports.siphash = binding.siphash;
exports.siphash256 = binding.siphash256;
exports.siphash32 = binding.siphash32;
exports.siphash64 = binding.siphash64;

module.exports = exports;
