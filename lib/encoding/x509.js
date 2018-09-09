/*!
 * x509.js - X509 for javascript
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on indutny/asn1.js:
 *   Copyright Fedor Indutny, 2013.
 *   https://github.com/indutny/asn1.js
 *
 * Resources:
 *   https://www.ietf.org/rfc/rfc2560.txt
 *   https://www.ietf.org/rfc/rfc5280.txt
 *   https://github.com/indutny/asn1.js/blob/master/rfc/2560/index.js
 *   https://github.com/indutny/asn1.js/blob/master/rfc/5280/index.js
 *   https://github.com/indutny/asn1.js/blob/master/lib/asn1/base/node.js
 *   https://github.com/indutny/asn1.js/blob/master/lib/asn1/encoders/der.js
 *   https://github.com/indutny/asn1.js/blob/master/lib/asn1/decoders/der.js
 */

'use strict';

const bio = require('bufio');
const asn1 = require('./asn1');
const pem = require('./pem');
const {types} = asn1;

/**
 * Certificate
 */

// Certificate  ::=  SEQUENCE  {
//      tbsCertificate       TBSCertificate,
//      signatureAlgorithm   AlgorithmIdentifier,
//      signature            BIT STRING  }

class Certificate extends asn1.Sequence {
  constructor() {
    super();
    this.raw = null;
    this.tbsCertificate = new TBSCertificate();
    this.signatureAlgorithm = new AlgorithmIdentifier();
    this.signature = new asn1.BitString();
  }

  getBodySize() {
    let size = 0;
    size += this.tbsCertificate.getSize();
    size += this.signatureAlgorithm.getSize();
    size += this.signature.getSize();
    return size;
  }

  writeBody(bw) {
    this.tbsCertificate.write(bw);
    this.signatureAlgorithm.write(bw);
    this.signature.write(bw);
    return bw;
  }

  readBody(br) {
    const offset = br.offset;

    this.tbsCertificate.read(br);
    this.signatureAlgorithm.read(br);
    this.signature.read(br);

    const size = br.offset - offset;
    this.raw = bio.readBytes(br.data, offset, size);

    return this;
  }

  clean() {
    return this.tbsCertificate.isNull()
        && this.signatureAlgorithm.isNull()
        && this.signature.isNull();
  }

  toPEM() {
    return pem.toPEM(this.encode(), 'CERTIFICATE');
  }

  fromPEM(str) {
    const data = pem.fromPEM(str, 'CERTIFICATE');
    return this.decode(data);
  }

  format() {
    return {
      tbsCertificate: this.tbsCertificate,
      signatureAlgorithm: this.signatureAlgorithm,
      signature: this.signature
    };
  }
}

/**
 * TBSCertificate
 */

// TBSCertificate  ::=  SEQUENCE  {
//      version         [0]  Version DEFAULT v1,
//      serialNumber         CertificateSerialNumber,
//      signature            AlgorithmIdentifier,
//      issuer               Name,
//      validity             Validity,
//      subject              Name,
//      subjectPublicKeyInfo SubjectPublicKeyInfo,
//      issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
//      subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
//      extensions      [3]  Extensions OPTIONAL }
//
// Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }

class TBSCertificate extends asn1.Sequence {
  constructor() {
    super();
    this.raw = null;
    this.version = new asn1.Integer().explicit(0x00).def(0);
    this.serialNumber = new asn1.Integer();
    this.signature = new AlgorithmIdentifier();
    this.issuer = new Names();
    this.validity = new Validity();
    this.subject = new Names();
    this.subjectPublicKeyInfo = new SubjectPublicKeyInfo();
    this.issuerUniqueID = new asn1.BitString().implicit(1).optional();
    this.subjectUniqueID = new asn1.BitString().implicit(2).optional();
    this.extensions = new Extensions().explicit(3).optional();
  }

  getBodySize() {
    let size = 0;
    size += this.version.getSize();
    size += this.serialNumber.getSize();
    size += this.signature.getSize();
    size += this.issuer.getSize();
    size += this.validity.getSize();
    size += this.subject.getSize();
    size += this.subjectPublicKeyInfo.getSize();
    size += this.issuerUniqueID.getSize();
    size += this.subjectUniqueID.getSize();
    size += this.extensions.getSize();
    return size;
  }

  writeBody(bw) {
    this.version.write(bw);
    this.serialNumber.write(bw);
    this.signature.write(bw);
    this.issuer.write(bw);
    this.validity.write(bw);
    this.subject.write(bw);
    this.subjectPublicKeyInfo.write(bw);
    this.issuerUniqueID.write(bw);
    this.subjectUniqueID.write(bw);
    this.extensions.write(bw);
    return bw;
  }

  readBody(br) {
    const offset = br.offset;

    this.version.read(br);
    this.serialNumber.read(br);
    this.signature.read(br);
    this.issuer.read(br);
    this.validity.read(br);
    this.subject.read(br);
    this.subjectPublicKeyInfo.read(br);
    this.issuerUniqueID.read(br);
    this.subjectUniqueID.read(br);
    this.extensions.read(br);

    const size = br.offset - offset;
    this.raw = bio.readBytes(br.data, offset, size);

    return this;
  }

  clean() {
    return this.version.isNull()
        && this.serialNumber.isNull()
        && this.signature.isNull()
        && this.issuer.isNull()
        && this.validity.isNull()
        && this.subject.isNull()
        && this.subjectPublicKeyInfo.isNull()
        && this.issuerUniqueID.isNull()
        && this.subjectUniqueID.isNull()
        && this.extensions.isNull();
  }

  toPEM() {
    return pem.toPEM(this.encode(), 'TBS CERTIFICATE');
  }

  fromPEM(str) {
    const data = pem.fromPEM(str, 'TBS CERTIFICATE');
    return this.decode(data);
  }

  format() {
    return {
      version: this.version,
      serialNumber: this.serialNumber,
      signature: this.signature,
      issuer: this.issuer,
      validity: this.validity,
      subject: this.subject,
      subjectPublicKeyInfo: this.subjectPublicKeyInfo,
      issuerUniqueID: this.issuerUniqueID,
      subjectUniqueID: this.subjectUniqueID,
      extensions: this.extensions
    };
  }
}

/**
 * AlgorithmIdentifier
 */

// AlgorithmIdentifier  ::=  SEQUENCE  {
//      algorithm               OBJECT IDENTIFIER,
//      parameters              ANY DEFINED BY algorithm OPTIONAL  }

class AlgorithmIdentifier extends asn1.Sequence {
  constructor(algorithm, parameters) {
    super();

    this.algorithm = new asn1.OID(algorithm);
    this.parameters = new asn1.Any().optional();

    if (parameters)
      this.parameters = this.parameters.set(parameters);
  }

  getBodySize() {
    let size = 0;
    size += this.algorithm.getSize();
    size += this.parameters.getSize();
    return size;
  }

  writeBody(bw) {
    this.algorithm.write(bw);
    this.parameters.write(bw);
    return bw;
  }

  readBody(br) {
    this.algorithm.read(br);
    this.parameters = this.parameters.read(br);
    return this;
  }

  clean() {
    return this.algorithm.isNull()
        && this.parameters.isNull();
  }

  format() {
    return {
      algorithm: this.algorithm,
      parameters: this.parameters
    };
  }
}

/**
 * Names
 */

class Names extends asn1.Sequence {
  constructor() {
    super();
    this.names = [];
  }

  getBodySize() {
    let size = 0;

    for (const name of this.names) {
      const set = new asn1.RawSet([name]);
      size += set.getSize();
    }

    return size;
  }

  writeBody(bw) {
    for (const name of this.names) {
      const set = new asn1.RawSet([name]);
      set.write(bw);
    }
    return bw;
  }

  readBody(br) {
    while (br.left()) {
      const set = asn1.RawSet.read(br);
      const name = Name.decode(set.value);
      this.names.push(name);
    }

    return this;
  }

  clean() {
    return this.names.length === 0;
  }

  format() {
    return this.names;
  }
}

/**
 * Name
 */

// Name ::= CHOICE { -- only one possibility for now --
//      rdnSequence  RDNSequence }
//
// RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
//
// RelativeDistinguishedName ::=
//      SET SIZE (1..MAX) OF AttributeTypeAndValue
//
// AttributeTypeAndValue ::= SEQUENCE {
//      type     AttributeType,
//      value    AttributeValue }
//
// AttributeType ::= OBJECT IDENTIFIER
//
// AttributeValue ::= ANY -- DEFINED BY AttributeType

class Name extends asn1.Sequence {
  constructor(id, value) {
    super();

    this.id = new asn1.OID(id);
    this.value = new asn1.Any();

    if (value)
      this.value = this.value.set(value);
  }

  getBodySize() {
    let size = 0;
    size += this.id.getSize();
    size += this.value.getSize();
    return size;
  }

  writeBody(bw) {
    this.id.write(bw);
    this.value.write(bw);
    return bw;
  }

  readBody(br) {
    this.id.read(br);
    this.value = this.value.read(br);
    return this;
  }

  clean() {
    return this.id.isNull()
        && this.value.isNull();
  }

  format() {
    return {
      id: this.id,
      value: this.value
    };
  }
}

/**
 * Validity
 */

// Validity ::= SEQUENCE {
//      notBefore      Time,
//      notAfter       Time  }

class Validity extends asn1.Sequence {
  constructor() {
    super();
    this.notBefore = new Time();
    this.notAfter = new Time();
  }

  getBodySize() {
    let size = 0;
    size += this.notBefore.getSize();
    size += this.notAfter.getSize();
    return size;
  }

  writeBody(bw) {
    this.notBefore.write(bw);
    this.notAfter.write(bw);
    return bw;
  }

  readBody(br) {
    this.notBefore.read(br);
    this.notAfter.read(br);
    return this;
  }

  clean() {
    return this.notBefore.isNull()
        && this.notAfter.isNull();
  }

  format() {
    return {
      notBefore: this.notBefore,
      notAfter: this.notAfter
    };
  }
}

/**
 * Time
 */

// Time ::= CHOICE {
//      utcTime        UTCTime,
//      generalTime    GeneralizedTime }

class Time extends asn1.Choice {
  constructor(options) {
    super(new asn1.UTCTime(), options);
  }

  choose() {
    return [
      types.UTCTIME,
      types.GENTIME
    ];
  }
}

// SubjectPublicKeyInfo  ::=  SEQUENCE  {
//      algorithm            AlgorithmIdentifier,
//      subjectPublicKey     BIT STRING  }

class SubjectPublicKeyInfo extends asn1.Sequence {
  constructor(algorithm, parameters, subjectPublicKey) {
    super();
    this.raw = null;
    this.algorithm = new AlgorithmIdentifier(algorithm, parameters);
    this.subjectPublicKey = new asn1.BitString(subjectPublicKey);
  }

  getBodySize() {
    let size = 0;
    size += this.algorithm.getSize();
    size += this.subjectPublicKey.getSize();
    return size;
  }

  writeBody(bw) {
    this.algorithm.write(bw);
    this.subjectPublicKey.write(bw);
    return bw;
  }

  readBody(br) {
    const offset = br.offset;

    this.algorithm.read(br);
    this.subjectPublicKey.read(br);

    const size = br.offset - offset;
    this.raw = bio.readBytes(br.data, offset, size);

    return this;
  }

  clean() {
    return this.algorithm.isNull()
        && this.subjectPublicKey.isNull();
  }

  toPEM() {
    return pem.toPEM(this.encode(), 'PUBLIC KEY');
  }

  fromPEM(str) {
    const data = pem.fromPEM(str, 'PUBLIC KEY');
    return this.decode(data);
  }

  format() {
    return {
      algorithm: this.algorithm,
      subjectPublicKey: this.subjectPublicKey
    };
  }
}

/**
 * Extensions
 */

class Extensions extends asn1.Sequence {
  constructor() {
    super();
    this.extensions = [];
  }

  getBodySize() {
    let size = 0;

    for (const ext of this.extensions)
      size += ext.getSize();

    return size;
  }

  writeBody(bw) {
    for (const ext of this.extensions)
      ext.write(bw);
    return bw;
  }

  readBody(br) {
    for (const ext of this.extensions)
      ext.read(br);
    return this;
  }

  clean() {
    return this.extensions.length === 0;
  }

  format() {
    return this.extensions;
  }
}

/**
 * Extension
 */

// Extension  ::=  SEQUENCE  {
//      extnID      OBJECT IDENTIFIER,
//      critical    BOOLEAN DEFAULT FALSE,
//      extnValue   OCTET STRING }

class Extension extends asn1.Sequence {
  constructor() {
    super();
    this.extnID = new asn1.OID();
    this.critical = new asn1.Bool().def(false);
    this.extnValue = new asn1.OctString();
  }

  getBodySize() {
    let size = 0;
    size += this.extnID.getSize();
    size += this.critical.getSize();
    size += this.extnValue.getSize();
    return size;
  }

  writeBody(bw) {
    this.extnID.write(bw);
    this.critical.write(bw);
    this.extnValue.write(bw);
    return bw;
  }

  readBody(br) {
    this.extnID.read(br);
    this.critical.read(br);
    this.extnValue.read(br);
    return this;
  }

  clean() {
    return this.extnID.isNull()
        && this.critical.isNull()
        && this.extnValue.isNull();
  }

  format() {
    return {
      extnID: this.extnID,
      critical: this.critical,
      extnValue: this.extnValue
    };
  }
}

/**
 * DigestInfo
 */

// See: https://www.ietf.org/rfc/rfc3447.txt
// Section 9.2
//
// DigestInfo ::= SEQUENCE {
//   digestAlgorithm AlgorithmIdentifier,
//   digest OCTET STRING
// }

class DigestInfo extends asn1.Sequence {
  constructor(algorithm, digest) {
    super();
    this.algorithm = new AlgorithmIdentifier(algorithm);
    this.algorithm.parameters = new asn1.Null();
    this.digest = new asn1.OctString(digest);
  }

  getBodySize() {
    let size = 0;
    size += this.algorithm.getSize();
    size += this.digest.getSize();
    return size;
  }

  writeBody(bw) {
    this.algorithm.write(bw);
    this.digest.write(bw);
    return bw;
  }

  readBody(br) {
    this.algorithm.read(br);
    this.digest.read(br);
    return this;
  }

  clean() {
    return this.algorithm.isNull()
        && this.digest.isNull();
  }

  format() {
    return {
      algorithm: this.algorithm,
      digest: this.digest
    };
  }
}

/*
 * Expose
 */

exports.Certificate = Certificate;
exports.TBSCertificate = TBSCertificate;
exports.AlgorithmIdentifier = AlgorithmIdentifier;
exports.Names = Names;
exports.Name = Name;
exports.Validity = Validity;
exports.Time = Time;
exports.SubjectPublicKeyInfo = SubjectPublicKeyInfo;
exports.Extensions = Extensions;
exports.Extension = Extension;
exports.DigestInfo = DigestInfo;
