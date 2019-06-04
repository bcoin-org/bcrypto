/*!
 * cash32.js - cashaddr for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const binding = require('./binding').cash32;
const cash32 = exports;

cash32.native = 2;

cash32.serialize = function serialize(prefix, data) {
  return binding.serialize(prefix, data);
};

cash32.deserialize = function deserialize(str, defaultPrefix) {
  return binding.deserialize(str, defaultPrefix);
};

cash32.is = function is(str, defaultPrefix) {
  return binding.is(str, defaultPrefix);
};

cash32.convertBits = function convertBits(data, frombits, tobits, pad) {
  return binding.convertBits(data, frombits, tobits, pad);
};

cash32.encode = function encode(prefix, type, hash) {
  return binding.encode(prefix, type, hash);
};

cash32.decode = function decode(str, defaultPrefix = 'bitcoincash') {
  return binding.decode(str, defaultPrefix);
};

cash32.test = function test(str, defaultPrefix = 'bitcoincash') {
  return binding.test(str, defaultPrefix);
};
