/*!
 * siphash.js - siphash for bcoin
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const binding = require('./binding');

exports.siphash = binding.siphash;
exports.siphash256 = binding.siphash256; // compat
exports.siphash32 = binding.siphash32;
exports.siphash64 = binding.siphash64;
exports.siphash32k256 = binding.siphash32k256;
exports.siphash64k256 = binding.siphash64k256;
exports.sipmod = binding.sipmod;
