/**
 * bcrypto.cc - fast native bindings to crypto functions.
 * Copyright (c) 2016-2019, Christopher Jeffrey (MIT License)
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <node.h>
#include <nan.h>
#include <torsion/util.h>

#include "common.h"
#include "aead.h"
#include "base58.h"
#include "bech32.h"
#include "blake2b.h"
#include "blake2s.h"
#include "cash32.h"
#include "chacha20.h"
#include "dsa.h"
#include "ecdh.h"
#include "ecdsa.h"
#include "eddsa.h"
#include "hash.h"
#include "hmac.h"
#include "keccak.h"
#include "murmur3.h"
#include "poly1305.h"
#include "pbkdf2.h"
#include "rsa.h"
#include "salsa20.h"
#include "scrypt.h"
#include "secp256k1.h"
#include "siphash.h"
#include "bcrypto.h"

NAN_METHOD(cleanse) {
  if (info.Length() < 1)
    return Nan::ThrowError("cleanse() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *data = (const uint8_t *)node::Buffer::Data(buf);
  size_t len = node::Buffer::Length(buf);

  cleanse((void *)data, len);
}

NAN_MODULE_INIT(init) {
  BAEAD::Init(target);
  BBase58::Init(target);
  BBech32::Init(target);
  BBLAKE2b::Init(target);
  BBLAKE2s::Init(target);
  BCash32::Init(target);
  BChaCha20::Init(target);
  Nan::Export(target, "cleanse", cleanse);
  BDSA::Init(target);
  BECDH::Init(target);
  BECDSA::Init(target);
  BEDDSA::Init(target);
  BHash::Init(target);
  BHMAC::Init(target);
  BKeccak::Init(target);
  BMurmur3::Init(target);
  BPoly1305::Init(target);
  BPBKDF2::Init(target);
  BRSA::Init(target);
  BSalsa20::Init(target);
  BScrypt::Init(target);
  BSecp256k1::Init(target);
  BSiphash::Init(target);
}

#if NODE_MAJOR_VERSION >= 10
NAN_MODULE_WORKER_ENABLED(bcrypto, init)
#else
NODE_MODULE(bcrypto, init)
#endif
