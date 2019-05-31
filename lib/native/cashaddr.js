/*!
 * cashaddr.js - cashaddr for bcrypto
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const binding = require('./binding').cashaddr;
const cashaddr = exports;

cashaddr.native = 2;

cashaddr.serialize = function serialize(prefix, data) {
  return binding.serialize(prefix, data);
};

cashaddr.deserialize = function deserialize(str, defaultPrefix) {
  return binding.deserialize(str, defaultPrefix);
};

cashaddr.is = function is(str, defaultPrefix) {
  return binding.is(str, defaultPrefix);
};

cashaddr.convertBits = function convertBits(data, frombits, tobits, pad) {
  return binding.convertBits(data, frombits, tobits, pad);
};

cashaddr.encode = function encode(prefix, type, hash) {
  return binding.encode(prefix, type, hash);
};

cashaddr.decode = function decode(str, defaultPrefix = 'bitcoincash') {
  return binding.decode(str, defaultPrefix);
};

cashaddr.test = function test(str, defaultPrefix = 'bitcoincash') {
  return binding.test(str, defaultPrefix);
};
