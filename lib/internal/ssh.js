/*!
 * ssh.js - SSH keys for javascript
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('bsert');
const bio = require('bufio');
const base64 = require('./base64');
const {lines} = require('./util');
const keys = require('./keys');

/*
 * Constants
 */

const types = {
  'ssh-dss': 'dsa',
  'ssh-rsa': 'rsa',
  'ecdsa-sha2-nistp256': 'ecdsa',
  'ecdsa-sha2-nistp384': 'ecdsa',
  'ecdsa-sha2-nistp521': 'ecdsa'
};

const typesByVal = {
  'dsa': 'ssh-dss',
  'rsa': 'ssh-rsa'
};

const typesByCurve = {
  'p256': 'ecdsa-sha2-nistp256',
  'p384': 'ecdsa-sha2-nistp384',
  'p521': 'ecdsa-sha2-nistp521'
};

const curves = {
  'nistp256': 'p256',
  'nistp384': 'p384',
  'nistp521': 'p521'
};

const curvesByVal = {
  'p256': 'nistp256',
  'p384': 'nistp384',
  'p521': 'nistp521'
};

/*
 * SSH
 */

function sizePublicKey(key) {
  assert(key && typeof key === 'object');
  assert(typeof key.type === 'string');

  let size = 0;
  let type;

  if (key.type === 'ecdsa') {
    assert(typeof key.curve === 'string');
    assert(typesByCurve.hasOwnProperty(key.curve));
    assert(curvesByVal.hasOwnProperty(key.curve));

    type = typesByCurve[key.curve];
  } else {
    assert(typesByVal.hasOwnProperty(key.type));

    type = typesByVal[key.type];
  }

  switch (key.type) {
    case 'dsa': {
      size += 4;
      size += type.length;
      size += 4;
      size += key.p.length;
      size += 4;
      size += key.q.length;
      size += 4;
      size += key.g.length;
      size += 4;
      size += key.y.length;
      break;
    }

    case 'rsa': {
      size += 4;
      size += type.length;
      size += 4;
      size += key.e.length;
      size += 4;
      size += key.n.length;
      break;
    }

    case 'ecdsa': {
      const curve = curvesByVal[key.curve];

      size += 4;
      size += type.length;
      size += 4;
      size += curve.length;
      size += 4;
      size += key.point.length;

      break;
    }

    default: {
      throw new Error();
    }
  }

  return size;
}

function encodePublicKey(key) {
  const size = sizePublicKey(key);
  const bw = bio.write(size);

  let type;

  if (key.type === 'ecdsa')
    type = typesByCurve[key.curve];
  else
    type = typesByVal[key.type];

  switch (key.type) {
    case 'dsa': {
      bw.writeU32BE(type.length);
      bw.writeString(type, 'binary');
      bw.writeU32BE(key.p.length);
      bw.writeBytes(key.p);
      bw.writeU32BE(key.q.length);
      bw.writeBytes(key.q);
      bw.writeU32BE(key.g.length);
      bw.writeBytes(key.g);
      bw.writeU32BE(key.y.length);
      bw.writeBytes(key.y);
      break;
    }

    case 'rsa': {
      bw.writeU32BE(type.length);
      bw.writeString(type, 'binary');
      bw.writeU32BE(key.e.length);
      bw.writeBytes(key.e);
      bw.writeU32BE(key.n.length);
      bw.writeBytes(key.n);
      break;
    }

    case 'ecdsa': {
      const curve = curvesByVal[key.curve];
      bw.writeU32BE(type.length);
      bw.writeString(type, 'binary');
      bw.writeU32BE(curve.length);
      bw.writeString(curve, 'binary');
      bw.writeU32BE(key.point.length);
      bw.writeBytes(key.point);
      break;
    }

    default: {
      throw new Error();
    }
  }

  return bw.render();
}

function decodePublicKey(data, expect = null) {
  assert(Buffer.isBuffer(data));
  assert(!expect || typeof expect === 'string');

  const br = bio.read(data);
  const size = br.readU32BE();

  if (expect && size !== expect.length)
    throw new Error();

  const tag = br.readString(size, 'binary');

  if (expect && tag !== expect)
    throw new Error();

  if (!types.hasOwnProperty(tag))
    throw new Error();

  const type = types[tag];

  switch (type) {
    case 'dsa': {
      return {
        type,
        p: br.readBytes(br.readU32BE()),
        q: br.readBytes(br.readU32BE()),
        g: br.readBytes(br.readU32BE()),
        y: br.readBytes(br.readU32BE())
      };
    }

    case 'rsa': {
      return {
        type,
        e: br.readBytes(br.readU32BE()),
        n: br.readBytes(br.readU32BE())
      };
    }

    case 'ecdsa': {
      const name = br.readString(br.readU32BE(), 'binary');

      if (!curves.hasOwnProperty(name))
        throw new Error();

      return {
        type,
        curve: curves[name],
        point: br.readBytes(br.readU32BE())
      };
    }

    default: {
      throw new Error();
    }
  }
}

function serializePublicKey(key) {
  const data = encodePublicKey(key);

  let type;

  if (key.type === 'ecdsa')
    type = typesByCurve[key.curve];
  else
    type = typesByVal[key.type];

  return `${type} ${data.toString('base64')}`;
}

function parsePublicKey(str) {
  assert(typeof str === 'string');

  const parts = str.split(' ', 3);

  if (parts.length < 2)
    throw new Error();

  const [expect, rest] = parts;

  if (!types.hasOwnProperty(expect))
    throw new Error(`Unknown public key: ${expect}.`);

  const data = base64.decode(rest);

  return decodePublicKey(data, expect);
}

function parseKeys(str) {
  const keys = [];

  for (const line of lines(str)) {
    let key;

    try {
      key = parsePublicKey(line);
    } catch (e) {
      continue;
    }

    keys.push(key);
  }

  return keys;
}

/*
 * Expose
 */

exports.encodePublicKey = encodePublicKey;
exports.decodePublicKey = decodePublicKey;
exports.serializePublicKey = serializePublicKey;
exports.parsePublicKey = parsePublicKey;
exports.parsePrivateKey = keys.parsePrivateKey;
exports.parseKeys = parseKeys;
