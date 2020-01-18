#ifndef _BCRYPTO_DSA_HH
#define _BCRYPTO_DSA_HH

#include <node.h>
#include <nan.h>

class BDSA {
public:
  static void Init(v8::Local<v8::Object> &target);

private:
  static NAN_METHOD(ParamsGenerate);
  static NAN_METHOD(ParamsGenerateAsync);
  static NAN_METHOD(ParamsVerify);
  static NAN_METHOD(PrivateKeyCreate);
  static NAN_METHOD(PrivateKeyRecover);
  static NAN_METHOD(PrivateKeyVerify);
  static NAN_METHOD(PublicKeyVerify);
  static NAN_METHOD(SignatureExport);
  static NAN_METHOD(SignatureImport);
  static NAN_METHOD(Sign);
  static NAN_METHOD(SignDER);
  static NAN_METHOD(Verify);
  static NAN_METHOD(VerifyDER);
  static NAN_METHOD(Derive);
};
#endif
