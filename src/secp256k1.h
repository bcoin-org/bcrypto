#ifndef _BCRYPTO_SECP256K1_HH
#define _BCRYPTO_SECP256K1_HH

#include <node.h>
#include <nan.h>
#include "secp256k1/include/secp256k1.h"

class BSecp256k1 : public Nan::ObjectWrap {
public:
  static NAN_METHOD(New);
  static void Init(v8::Local<v8::Object> &target);

  BSecp256k1();
  ~BSecp256k1();

  secp256k1_context *ctx;

private:
  static NAN_METHOD(privateKeyVerify);
  static NAN_METHOD(privateKeyExport);
  static NAN_METHOD(privateKeyImport);
  static NAN_METHOD(privateKeyMod);
  static NAN_METHOD(privateKeyNegate);
  static NAN_METHOD(privateKeyInverse);
  static NAN_METHOD(privateKeyTweakAdd);
  static NAN_METHOD(privateKeyTweakMul);

  static NAN_METHOD(publicKeyCreate);
  static NAN_METHOD(publicKeyConvert);
  static NAN_METHOD(publicKeyVerify);
  static NAN_METHOD(publicKeyTweakAdd);
  static NAN_METHOD(publicKeyTweakMul);
  static NAN_METHOD(publicKeyCombine);
  static NAN_METHOD(publicKeyNegate);

  static NAN_METHOD(signatureNormalize);
  static NAN_METHOD(signatureExport);
  static NAN_METHOD(signatureImport);
  static NAN_METHOD(signatureImportStrict);
  static NAN_METHOD(isLowS);
  static NAN_METHOD(isLowDER);

  static NAN_METHOD(sign);
  static NAN_METHOD(verify);
  static NAN_METHOD(verifyDER);
  static NAN_METHOD(recover);

  static NAN_METHOD(derive);

  static NAN_METHOD(schnorrSign);
  static NAN_METHOD(schnorrVerify);
};

#endif
