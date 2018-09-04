#ifndef _BCRYPTO_DSA_HH
#define _BCRYPTO_DSA_HH
#include <node.h>
#include <nan.h>

#if NODE_MAJOR_VERSION >= 10
class BDSA : public Nan::ObjectWrap {
public:
  static NAN_METHOD(New);
  static void Init(v8::Local<v8::Object> &target);

  BDSA();
  ~BDSA();

private:
  static NAN_METHOD(ParamsGenerate);
  static NAN_METHOD(ParamsGenerateAsync);
  static NAN_METHOD(PrivateKeyCreate);
  static NAN_METHOD(ComputeY);
  static NAN_METHOD(Sign);
  static NAN_METHOD(Verify);
};
#endif

#endif
