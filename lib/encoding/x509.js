/*!
 * x509.js - X509 for javascript
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on indutny/asn1.js:
 *   Copyright Fedor Indutny, 2013.
 *   https://github.com/indutny/asn1.js
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/X.509
 *   https://tools.ietf.org/html/rfc4158
 *   https://www.ietf.org/rfc/rfc2560.txt
 *   https://www.ietf.org/rfc/rfc5280.txt
 *   https://github.com/indutny/asn1.js/blob/master/rfc/2560/index.js
 *   https://github.com/indutny/asn1.js/blob/master/rfc/5280/index.js
 *   https://github.com/indutny/asn1.js/blob/master/lib/asn1/base/node.js
 *   https://github.com/indutny/asn1.js/blob/master/lib/asn1/encoders/der.js
 *   https://github.com/indutny/asn1.js/blob/master/lib/asn1/decoders/der.js
 *   https://www.itu.int/rec/T-REC-X.509-201910-I
 *   https://www.openssl.org/docs/manmaster/man5/x509v3_config.html
 *   https://tools.ietf.org/html/rfc8017#appendix-A
 *   https://tools.ietf.org/html/rfc5280
 */

'use strict';

const assert = require('../internal/assert');
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
    this.tbsCertificate = new TBSCertificate();
    this.signatureAlgorithm = new AlgorithmIdentifier();
    this.signature = new asn1.BitString();
  }

  get isRaw() {
    return true;
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
    this.tbsCertificate.read(br);
    this.signatureAlgorithm.read(br);
    this.signature.read(br);
    return this;
  }

  clean() {
    return this.tbsCertificate.clean()
        && this.signatureAlgorithm.clean()
        && this.signature.clean();
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
      type: this.constructor.name,
      tbsCertificate: this.tbsCertificate,
      signatureAlgorithm: this.signatureAlgorithm,
      signature: this.signature
    };
  }

  getJSON() {
    return {
      tbsCertificate: this.tbsCertificate.getJSON(),
      signatureAlgorithm: this.signatureAlgorithm.getJSON(),
      signature: this.signature.getJSON()
    };
  }

  fromJSON(json) {
    this.tbsCertificate.fromJSON(json.tbsCertificate);
    this.signatureAlgorithm.fromJSON(json.signatureAlgorithm);
    this.signature.fromJSON(json.signature);

    return this;
  }

  static fromJSON(json) {
    return new this().fromJSON(json);
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
    this.version = new asn1.Unsigned().explicit(0).optional();
    this.serialNumber = new asn1.Integer();
    this.signature = new AlgorithmIdentifier();
    this.issuer = new RDNSequence();
    this.validity = new Validity();
    this.subject = new RDNSequence();
    this.subjectPublicKeyInfo = new SubjectPublicKeyInfo();
    this.issuerUniqueID = new asn1.BitString().implicit(1).optional();
    this.subjectUniqueID = new asn1.BitString().implicit(2).optional();
    this.extensions = new Extensions().explicit(3).optional();
  }

  get isRaw() {
    return true;
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
    return this;
  }

  clean() {
    return this.version.clean()
        && this.serialNumber.clean()
        && this.signature.clean()
        && this.issuer.clean()
        && this.validity.clean()
        && this.subject.clean()
        && this.subjectPublicKeyInfo.clean()
        && this.issuerUniqueID.clean()
        && this.subjectUniqueID.clean()
        && this.extensions.clean();
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
      type: this.constructor.name,
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

  getJSON() {
    return {
      version: this.version.getJSON(),
      serialNumber: this.serialNumber.getJSON(),
      signature: this.signature.getJSON(),
      issuer: this.issuer.getJSON(),
      validity: this.validity.getJSON(),
      subject: this.subject.getJSON(),
      subjectPublicKeyInfo: this.subjectPublicKeyInfo.getJSON(),
      issuerUniqueID: this.issuerUniqueID.getJSON(),
      subjectUniqueID: this.subjectUniqueID.getJSON(),
      extensions: this.extensions.getJSON()
    };
  }

  fromJSON(json) {
    let sn = json.serialNumber;
    if (typeof sn === 'string')
      sn = {value: sn, negative: false};

    this.version.fromJSON(json.version);
    this.serialNumber.fromJSON(sn);
    this.signature.fromJSON(json.signature);
    this.issuer.fromJSON(json.issuer);
    this.validity.fromJSON(json.validity);
    this.subject.fromJSON(json.subject);
    this.subjectPublicKeyInfo.fromJSON(json.subjectPublicKeyInfo);
    if (json.issuerUniqueID)
      this.issuerUniqueID.fromJSON(json.issuerUniqueID);
    if (json.subjectUniqueID)
      this.subjectUniqueID.fromJSON(json.subjectUniqueID);
    if (json.extensions)
      this.extensions.fromJSON(json.extensions);

    return this;
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
    this.parameters = new asn1.Any(parameters).optional();
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
    this.parameters.read(br);
    return this;
  }

  clean() {
    return this.algorithm.clean()
        && this.parameters.clean();
  }

  format() {
    return {
      type: this.constructor.name,
      algorithm: this.algorithm,
      parameters: this.parameters
    };
  }

  getJSON() {
    return {
      algorithm: this.algorithm.getJSON(),
      parameters: this.parameters.getJSON()
    };
  }

  fromJSON(json) {
    this.algorithm.fromJSON(json.algorithm);
    this.parameters.fromJSON(json.parameters);

    return this;
  }
}

/**
 * RDNSequence
 */

// Name ::= CHOICE { -- only one possibility for now --
//      rdnSequence  RDNSequence }
//
// RDNSequence ::= SEQUENCE OF RelativeDistinguishedName

class RDNSequence extends asn1.Sequence {
  constructor() {
    super();
    this.names = [];
  }

  getBodySize() {
    let size = 0;

    for (const rdn of this.names)
      size += rdn.getSize();

    return size;
  }

  writeBody(bw) {
    for (const rdn of this.names)
      rdn.write(bw);
    return bw;
  }

  readBody(br) {
    while (br.left()) {
      const rdn = RDN.read(br);
      this.names.push(rdn);
    }

    return this;
  }

  clean() {
    return this.names.length === 0;
  }

  format() {
    return {
      type: this.constructor.name,
      names: this.names
    };
  }

  getJSON() {
    const names = [];
    for (const name of this.names)
      names.push(name.getJSON());

    return names;
  }

  fromJSON(json) {
    assert(Array.isArray(json));
    for (const name of json)
      this.names.push(RDN.fromJSON(name));

    return this;
  }
}

/**
 * RDN
 */

// RelativeDistinguishedName ::=
//      SET SIZE (1..MAX) OF AttributeTypeAndValue
//

class RDN extends asn1.Set {
  constructor(id, value) {
    super();
    this.attributes = [new Attribute(id, value)];
  }

  getBodySize() {
    let size = 0;

    assert(this.attributes.length >= 1);

    for (const attr of this.attributes)
      size += attr.getSize();

    return size;
  }

  writeBody(bw) {
    assert(this.attributes.length >= 1);

    for (const attr of this.attributes)
      attr.write(bw);

    return bw;
  }

  readBody(br) {
    this.attributes[0].read(br);

    while (br.left()) {
      const attr = Attribute.read(br);
      this.attributes.push(attr);
    }

    return this;
  }

  clean() {
    return this.attributes.length === 1 && this.attributes[0].clean();
  }

  format() {
    return {
      type: this.constructor.name,
      attributes: this.attributes
    };
  }

  getJSON() {
    const attributes = [];
    for (const attr of this.attributes)
      attributes.push(attr.getJSON());

    return attributes;
  }

  fromJSON(json) {
    assert(Array.isArray(json));
    this.attributes = [];

    for (const attr of json)
      this.attributes.push(Attribute.fromJSON(attr));

    return this;
  }

  static fromJSON(json) {
    return new this().fromJSON(json);
  }
}

/**
 * Attribute
 */

// AttributeTypeAndValue ::= SEQUENCE {
//      type     AttributeType,
//      value    AttributeValue }
//
// AttributeType ::= OBJECT IDENTIFIER
//
// AttributeValue ::= ANY -- DEFINED BY AttributeType

class Attribute extends asn1.Sequence {
  constructor(id, value) {
    super();

    this.id = new asn1.OID(id);
    this.value = new asn1.Any(value);
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
    this.value.read(br);
    return this;
  }

  clean() {
    return this.id.clean()
        && this.value.clean();
  }

  format() {
    return {
      type: this.constructor.name,
      id: this.id,
      value: this.value
    };
  }

  getJSON() {
    return {
      id: this.id.getJSON(),
      value: this.value.getJSON()
    };
  }

  fromJSON(json) {
    this.id.fromJSON(json.id);
    this.value.fromJSON(json.value);

    return this;
  }

  static fromJSON(json) {
    return new this().fromJSON(json);
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
    return this.notBefore.clean()
        && this.notAfter.clean();
  }

  format() {
    return {
      type: this.constructor.name,
      notBefore: this.notBefore,
      notAfter: this.notAfter
    };
  }

  getJSON() {
    return {
      notBefore: this.notBefore.getJSON(),
      notAfter: this.notAfter.getJSON()
    };
  }

  fromJSON(json) {
    this.notBefore.fromJSON(json.notBefore);
    this.notAfter.fromJSON(json.notAfter);

    return this;
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

  choices() {
    return [
      types.UTCTIME,
      types.GENTIME
    ];
  }
}

/**
 * SubjectPublicKeyInfo
 */

// SubjectPublicKeyInfo  ::=  SEQUENCE  {
//      algorithm            AlgorithmIdentifier,
//      subjectPublicKey     BIT STRING  }

class SubjectPublicKeyInfo extends asn1.Sequence {
  constructor(algorithm, parameters, publicKey) {
    super();
    this.algorithm = new AlgorithmIdentifier(algorithm, parameters);
    this.publicKey = new asn1.BitString(publicKey);
  }

  get isRaw() {
    return true;
  }

  getBodySize() {
    let size = 0;
    size += this.algorithm.getSize();
    size += this.publicKey.getSize();
    return size;
  }

  writeBody(bw) {
    this.algorithm.write(bw);
    this.publicKey.write(bw);
    return bw;
  }

  readBody(br) {
    this.algorithm.read(br);
    this.publicKey.read(br);
    return this;
  }

  clean() {
    return this.algorithm.clean()
        && this.publicKey.clean();
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
      type: this.constructor.name,
      algorithm: this.algorithm,
      publicKey: this.publicKey
    };
  }

  getJSON() {
    let publicKey = this.publicKey;
    const OBJ =
      identifierToClass(this.algorithm.algorithm.getJSON());
    if (OBJ) {
      publicKey = new OBJ();
      publicKey.decode(this.publicKey.value);
    }

    return {
      algorithm: this.algorithm.getJSON(),
      publicKey: publicKey.getJSON()
    };
  }

  fromJSON(json) {
    this.algorithm.fromJSON(json.algorithm);

    const OBJ =
      identifierToClass(this.algorithm.algorithm.getJSON());
    if (OBJ) {
      const publicKey = new OBJ();
      publicKey.fromJSON(json.publicKey);
      this.publicKey.fromJSON({
        bits: publicKey.encode().length * 8,
        value: publicKey.encode().toString('hex')
      });
    } else {
      this.publicKey.fromJSON(json.publicKey);
    }

    return this;
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
    while(br.left()) {
      const ext = Extension.read(br);
      this.extensions.push(ext);
    }
    return this;
  }

  clean() {
    return this.extensions.length === 0;
  }

  format() {
    return {
      type: this.constructor.name,
      extensions: this.extensions
    };
  }

  getJSON() {
    const extensions = [];
    for (const ext of this.extensions)
      extensions.push(ext.getJSON());

    return extensions;
  }

  fromJSON(json) {
    assert(Array.isArray(json));
    for (const ext of json)
      this.extensions.push(Extension.fromJSON(ext));

    return this;
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
    this.critical = new asn1.Bool().optional();
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
    return this.extnID.clean()
        && this.critical.clean()
        && this.extnValue.clean();
  }

  format() {
    return {
      type: this.constructor.name,
      extnID: this.extnID,
      critical: this.critical,
      extnValue: this.extnValue
    };
  }

  getJSON() {
    let val = this.extnValue;
    const OBJ = identifierToClass(this.extnID.getJSON());
    if (OBJ) {
      val = new OBJ();
      val.decode(this.extnValue.value);
    }

    return {
      extnID: this.extnID.getJSON(),
      critical: this.critical.getJSON(),
      extnValue: val.getJSON()
    };
  }

  fromJSON(json) {
    this.extnID.fromJSON(json.extnID);
    this.critical.fromJSON(json.critical);

    const OBJ = identifierToClass(this.extnID.getJSON());
    if (OBJ) {
      const val = new OBJ();
      val.fromJSON(json.extnValue);
      this.extnValue.fromJSON(val.encode().toString('hex'));
    } else {
      this.extnValue.fromJSON(json.extnValue);
    }

    return this;
  }

  static fromJSON(json) {
    return new this().fromJSON(json);
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
    this.algorithm.parameters.optional(false);
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
    return this.algorithm.clean()
        && this.digest.clean();
  }

  format() {
    return {
      type: this.constructor.name,
      algorithm: this.algorithm,
      digest: this.digest
    };
  }

  getJSON() {
    return {
      algorithm: this.algorithm.getJSON(),
      digest: this.digest.getJSON()
    };
  }

  fromJSON(json) {
    this.algorithm.fromJSON(json.algorithm);
    this.digest.fromJSON(json.digest);

    return this;
  }
}

/**
 * BasicConstraints
 */

// basicConstraints EXTENSION ::= {
//   SYNTAX         BasicConstraintsSyntax
//   IDENTIFIED BY  id-ce-basicConstraints }
// BasicConstraintsSyntax ::= SEQUENCE {
//   cA                 BOOLEAN DEFAULT FALSE,
//   pathLenConstraint  INTEGER(0..MAX) OPTIONAL,
//   ... }

class BasicConstraints extends asn1.Sequence {
  constructor() {
    super();
    this.cA = new asn1.Bool().optional();
    this.pathLenConstraint = new asn1.Integer().optional();
  }

  getBodySize() {
    let size = 0;
    size += this.cA.getSize();
    size += this.pathLenConstraint.getSize();
    return size;
  }

  writeBody(bw) {
    this.cA.write(bw);
    this.pathLenConstraint.write(bw);
    return bw;
  }

  readBody(br) {
    this.cA.read(br);
    this.pathLenConstraint.read(br);
    return this;
  }

  clean() {
    return this.cA.clean()
        && this.pathLenConstraint.clean();
  }

  format() {
    return {
      cA: this.cA,
      pathLenConstraint: this.pathLenConstraint
    };
  }

  getJSON() {
    return {
      cA: this.cA.getJSON(),
      pathLenConstraint: this.pathLenConstraint.toNumber()
    };
  }

  fromJSON(json) {
    this.cA.fromJSON(json.cA);
    this.pathLenConstraint.fromNumber(json.pathLenConstraint);

    return this;
  }

  static fromJSON(json) {
    return new this().fromJSON(json);
  }
}

/**
 * RSAPublicKey
 */

// RSAPublicKey ::= SEQUENCE {
//    modulus           INTEGER,  -- n
//    publicExponent    INTEGER   -- e
// }

class RSAPublicKey extends asn1.Sequence {
  constructor() {
    super();
    this.modulus = new asn1.Integer();
    this.publicExponent = new asn1.Integer();
  }

  getBodySize() {
    let size = 0;
    size += this.modulus.getSize();
    size += this.publicExponent.getSize();
    return size;
  }

  writeBody(bw) {
    this.modulus.write(bw);
    this.publicExponent.write(bw);
    return bw;
  }

  readBody(br) {
    this.modulus.read(br);
    this.publicExponent.read(br);
    return this;
  }

  clean() {
    return this.modulus.clean()
        && this.publicExponent.clean();
  }

  format() {
    return {
      modulus: this.modulus,
      publicExponent: this.publicExponent
    };
  }

  getJSON() {
    return {
      modulus: this.modulus.getJSON().value,
      publicExponent: this.publicExponent.getJSON().value
    };
  }

  fromJSON(json) {
    this.modulus.fromJSON({value: json.modulus, negative: false});
    this.publicExponent.fromJSON({value: json.publicExponent, negative: false});

    return this;
  }

  static fromJSON(json) {
    return new this().fromJSON(json);
  }
}

/**
 * SubjectAltName
 */

// SubjectAltName ::= GeneralNames
// GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName

class SubjectAltName extends asn1.Sequence {
  constructor() {
    super();
    this.names = [];
  }

  getBodySize() {
    let size = 0;

    for (const name of this.names)
      size += name.getSize();

    return size;
  }

  writeBody(bw) {
    for (const name of this.names)
      name.write(bw);
    return bw;
  }

  readBody(br) {
    while (br.left()) {
      const name = GeneralName.read(br);
      this.names.push(name);
    }
    return this;
  }

  clean() {
    return this.names.length === 0;
  }

  format() {
    return {
      type: this.constructor.name,
      names: this.names
    };
  }

  getJSON() {
    const names = [];
    for (const name of this.names)
      names.push(name.getJSON());

    return names;
  }

  fromJSON(json) {
    assert(Array.isArray(json));
    for (const name of json)
      this.names.push(GeneralName.fromJSON(name));

    return this;
  }

  static fromJSON(json) {
    return new this().fromJSON(json);
  }
}

/**
 * GeneralName
 */

// GeneralName ::= CHOICE {
//     otherName                       [0]     OtherName,
//     rfc822Name                      [1]     IA5String,
//     dNSName                         [2]     IA5String,
//     x400Address                     [3]     ORAddress,
//     directoryName                   [4]     Name,
//     ediPartyName                    [5]     EDIPartyName,
//     uniformResourceIdentifier       [6]     IA5String,
//     iPAddress                       [7]     OCTET STRING,
//     registeredID                    [8]     OBJECT IDENTIFIER }

// OtherName ::= SEQUENCE {
//     type-id    OBJECT IDENTIFIER,
//     value      [0] EXPLICIT ANY DEFINED BY type-id }

// ORAddress ::= SEQUENCE {
//    built-in-standard-attributes BuiltInStandardAttributes,
//    built-in-domain-defined-attributes
//                    BuiltInDomainDefinedAttributes OPTIONAL,
//    -- see also teletex-domain-defined-attributes
//    extension-attributes ExtensionAttributes OPTIONAL }

// Name ::= CHOICE { -- only one possibility for now --
//   rdnSequence  RDNSequence }

// EDIPartyName ::= SEQUENCE {
//     nameAssigner            [0]     DirectoryString OPTIONAL,
//     partyName               [1]     DirectoryString }

class GeneralName extends asn1.Choice {
  constructor() {
    super(new asn1.Node());
    this.names = [];
    this.types = {
      OTHERNAME: 0,
      RFC822NAME: 1,
      DNSNAME: 2,
      X400ADDRESS: 3,
      DIRECTORYNAME: 4,
      EDIPARTYNAME: 5,
      UNIFORMRESOURCEIDENTIFIER: 6,
      IPADDRESS: 7,
      REGISTEREDID: 8
    };
  }

  choices() {
    return Object.values(this.types);
  }

  typeToClass(type) {
    assert((type >>> 0) === type);

    // See https://tools.ietf.org/html/rfc5280#appendix-A
    // for a confusing list of explicit/implicit types.
    // Also: https://serverfault.com/questions/1020712/
    // x509-asn1-are-subjectaltname-elements-explicit-or-implicit

    this.implicit(type);

    switch (type) {
      case this.types.OTHERNAME:
        return OtherName;
      case this.types.RFC822NAME:
        return RFC822Name;
      case this.types.DNSNAME:
        return DNSName;
      case this.types.X400ADDRESS:
        return X400Address;
      case this.types.DIRECTORYNAME:
        this.explicit(type);
        return DirectoryName;
      case this.types.EDIPARTYNAME:
        return EDIPartyName;
      case this.types.UNIFORMRESOURCEIDENTIFIER:
        return UniformResourceIdentifier;
      case this.types.IPADDRESS:
        return IPAddress;
      case this.types.REGISTEREDID:
        return RegisteredID;
      default:
        throw new Error(`Unknown type: ${type}.`);
    }
  }
}

/**
 * GeneralName types
 */

class OtherName extends asn1.Sequence {};
class RFC822Name extends asn1.IA5String {};
class DNSName extends asn1.IA5String {};
class X400Address extends asn1.Sequence {};
class DirectoryName extends RDNSequence {};
class EDIPartyName extends asn1.Sequence {};
class UniformResourceIdentifier extends asn1.IA5String {};
class IPAddress extends asn1.OctString {};
class RegisteredID extends asn1.OID {};

/**
 * KeyUsage
 */

// KeyUsage ::= BIT STRING {
//      digitalSignature        (0),
//      nonRepudiation          (1), -- recent editions of X.509 have
//                           -- renamed this bit to contentCommitment
//      keyEncipherment         (2),
//      dataEncipherment        (3),
//      keyAgreement            (4),
//      keyCertSign             (5),
//      cRLSign                 (6),
//      encipherOnly            (7),
//      decipherOnly            (8) }

class KeyUsage extends asn1.BitString {
  constructor() {
    super();
    this.value = Buffer.alloc(2);
  }

  getBitByProperty(property) {
    const properties = {
      'digitalSignature': 0,
      'nonRepudiation': 1,
      'keyEncipherment': 2,
      'dataEncipherment': 3,
      'keyAgreement': 4,
      'keyCertSign': 5,
      'cRLSign': 6,
      'encipherOnly': 7,
      'decipherOnly': 8
    };

    return properties[property];
  }

  getPropertyByBit(bit) {
    const bits = [
      'digitalSignature',
      'nonRepudiation',
      'keyEncipherment',
      'dataEncipherment',
      'keyAgreement',
      'keyCertSign',
      'cRLSign',
      'encipherOnly',
      'decipherOnly'
    ];

    return bits[bit];
  }

  getJSON() {
    const purpose = [];
    for (let i = 0; i <= this.bits; i++) {
      if (this.getBit(i))
        purpose.push(this.getPropertyByBit(i));
    }

    return purpose;
  }

  fromJSON(json) {
    assert(Array.isArray(json));
    for (const property of json) {
      const bit = this.getBitByProperty(property);

      if (bit + 1 > this.bits)
        this.bits = bit + 1;

      this.setBit(bit, true);
    }

    if (this.bits < 9)
      this.value = this.value.slice(0, -1);

    return this;
  }

  static fromJSON(json) {
    return new this().fromJSON(json);
  }
}

/**
 * Entity
 */

// Wrapper around RDNSequence for JSON construction
// of subject and issuer. Uses UTF8String for everything.

class Entity {
  static fromJSON(json) {
    const names = [];
    for (const key of Object.keys(json)) {
      const string = json[key];
      const attr = [{
        id: key,
        value: {
          type: 'Utf8String',
          node: string
        }
      }];
      names.push(attr);
    }

    return new RDNSequence().fromJSON(names);
  }
}
/**
 * Helpers
 */

function identifierToClass(oid) {
  assert(typeof oid === 'string');

  switch (oid) {
    case 'BasicConstraints':
      return BasicConstraints;
    case 'RSAPublicKey':
      return RSAPublicKey;
    case 'SubjectAltName':
      return SubjectAltName;
    case 'KeyUsage':
      return KeyUsage;
    default:
      return null;
  }
}

/*
 * Expose
 */

exports.Certificate = Certificate;
exports.TBSCertificate = TBSCertificate;
exports.AlgorithmIdentifier = AlgorithmIdentifier;
exports.RDNSequence = RDNSequence;
exports.RDN = RDN;
exports.Attribute = Attribute;
exports.Validity = Validity;
exports.Time = Time;
exports.SubjectPublicKeyInfo = SubjectPublicKeyInfo;
exports.Extensions = Extensions;
exports.Extension = Extension;
exports.DigestInfo = DigestInfo;
exports.BasicConstraints = BasicConstraints;
exports.RSAPublicKey = RSAPublicKey;
exports.SubjectAltName = SubjectAltName;
exports.KeyUsage = KeyUsage;
exports.Entity = Entity;
