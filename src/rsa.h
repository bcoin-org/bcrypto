#ifndef _BCRYPTO_RSA_HH
#define _BCRYPTO_RSA_HH
#include <node.h>
#include <nan.h>

#if NODE_MAJOR_VERSION >= 10
class BRSA : public Nan::ObjectWrap {
public:
  static NAN_METHOD(New);
  static void Init(v8::Local<v8::Object> &target);

  BRSA();
  ~BRSA();

private:
  static NAN_METHOD(Generate);
  static NAN_METHOD(GenerateAsync);
  static NAN_METHOD(Validate);
  static NAN_METHOD(Compute);
  static NAN_METHOD(Sign);
  static NAN_METHOD(Verify);
  static NAN_METHOD(Encrypt);
  static NAN_METHOD(Decrypt);
};
#endif

#endif
