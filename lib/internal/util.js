/*!
 * utils.js - utils for javascript
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

/* eslint spaced-comment: "off" */

'use strict';

const assert = require('bsert');

/*
 * Constants
 */

const ZERO = Buffer.alloc(1, 0x00);

/*
 * Util
 */

function countBits(buf) {
  assert(Buffer.isBuffer(buf));

  let i = 0;

  for (; i < buf.length; i++) {
    if (buf[i] !== 0x00)
      break;
  }

  let bits = (buf.length - i) * 8;

  if (bits === 0)
    return 0;

  bits -= 8;

  let oct = buf[i];

  while (oct) {
    bits += 1;
    oct >>>= 1;
  }

  return bits;
}

function trimZeroes(buf) {
  if (buf == null)
    return ZERO;

  assert(Buffer.isBuffer(buf));

  if (buf.length === 0)
    return ZERO;

  if (buf[0] !== 0x00)
    return buf;

  for (let i = 1; i < buf.length; i++) {
    if (buf[i] !== 0x00)
      return buf.slice(i);
  }

  return buf.slice(-1);
}

function *lines(str) {
  assert(typeof str === 'string');

  let i = 0;
  let j = 0;

  if (str.length > 0) {
    if (str.charCodeAt(0) === 0xfeff) {
      i += 1;
      j += 1;
    }
  }

  for (; i < str.length; i++) {
    const ch = str.charCodeAt(i);

    switch (ch) {
      case 0x0d /*'\r'*/:
      case 0x0a /*'\n'*/: {
        if (j !== i)
          yield trimRight(str.substring(j, i));

        if (ch === 0x0d && i + 1 < str.length) {
          if (str.charCodeAt(i + 1) === 0x0a)
            i += 1;
        }

        j = i + 1;

        break;
      }
    }
  }

  if (j !== i)
    yield trimRight(str.substring(j, i));
}

function trimRight(str) {
  assert(typeof str === 'string');

  for (let i = str.length - 1; i >= 0; i--) {
    const ch = str.charCodeAt(i);

    switch (ch) {
      case 0x09 /*'\t'*/:
      case 0x0b /*'\v'*/:
      case 0x20 /*' '*/:
        continue;
    }

    return str.substring(0, i + 1);
  }

  return str;
}

/*
 * Expose
 */

exports.countBits = countBits;
exports.trimZeroes = trimZeroes;
exports.lines = lines;
