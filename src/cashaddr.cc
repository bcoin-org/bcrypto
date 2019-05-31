#include <assert.h>
#include <string.h>
#include <node.h>
#include <nan.h>

#include "common.h"
#include "cashaddr/cashaddr.h"
#include "cashaddr.h"

void
BCashAddr::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;
  v8::Local<v8::Object> obj = Nan::New<v8::Object>();

  Nan::Export(obj, "encode", BCashAddr::Encode);
  Nan::Export(obj, "decode", BCashAddr::Decode);
  Nan::Export(obj, "test", BCashAddr::Test);

  Nan::Set(target, Nan::New("cashaddr").ToLocalChecked(), obj);
}

NAN_METHOD(BCashAddr::Encode) {
  if (info.Length() < 3)
    return Nan::ThrowError("cashaddr.encode() requires arguments.");

  if (!info[0]->IsString())
    return Nan::ThrowTypeError("First argument must be a string.");

  Nan::Utf8String prefix_str(info[0]);

  if (!info[1]->IsNumber())
    return Nan::ThrowTypeError("Invalid cashaddr type.");

  v8::Local<v8::Object> hashbuf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(hashbuf))
    return Nan::ThrowTypeError("Third argument must be a buffer.");

  const char *prefix = (const char *)*prefix_str;
  int type = (int)Nan::To<int32_t>(info[1]).FromJust();

  const uint8_t *hash = (uint8_t *)node::Buffer::Data(hashbuf);
  size_t hash_len = node::Buffer::Length(hashbuf);

  char output[197];
  memset(&output, 0, 197);
  size_t olen = 0;

  bcrypto_cashaddr_error err = bcrypto_cashaddr_ERR_NULL;

  if (!bcrypto_cashaddr_encode(&err, output, prefix, type, hash, hash_len))
    return Nan::ThrowError(bcrypto_cashaddr_strerror(err));

  olen = strlen((char *)output);

  info.GetReturnValue().Set(
    Nan::New<v8::String>((char *)output, olen).ToLocalChecked());
}

NAN_METHOD(BCashAddr::Decode) {
  if (info.Length() < 2)
    return Nan::ThrowError("cashaddr.decode() requires arguments.");

  if (!info[0]->IsString())
    return Nan::ThrowTypeError("First argument must be a string.");

  if (!info[1]->IsString())
    return Nan::ThrowTypeError("Second argument must be a string.");

  Nan::Utf8String addr_(info[0]);
  const char *addr = (const char *)*addr_;

  Nan::Utf8String default_prefix_(info[1]);
  const char *default_prefix = (const char *)*default_prefix_;

  uint8_t hash[65];
  memset(hash, 0, 65);
  size_t hash_len;
  int type;
  char prefix[84];
  memset(prefix, 0, 84);
  size_t prefix_len;

  bcrypto_cashaddr_error err = bcrypto_cashaddr_ERR_NULL;

  if (!bcrypto_cashaddr_decode(&err, &type, hash, &hash_len, prefix, default_prefix, addr))
    return Nan::ThrowError(bcrypto_cashaddr_strerror(err));

  prefix_len = strlen((char *)&prefix[0]);

  v8::Local<v8::Object> ret = Nan::New<v8::Object>();

  Nan::Set(ret,
    Nan::New<v8::String>("prefix").ToLocalChecked(),
    Nan::New<v8::String>((char *)&prefix[0], prefix_len).ToLocalChecked());

  Nan::Set(ret,
    Nan::New<v8::String>("type").ToLocalChecked(),
    Nan::New<v8::Number>(type));

  Nan::Set(ret,
    Nan::New<v8::String>("hash").ToLocalChecked(),
    Nan::CopyBuffer((char *)&hash[0], hash_len).ToLocalChecked());

  info.GetReturnValue().Set(ret);
}

NAN_METHOD(BCashAddr::Test) {
  if (info.Length() < 2)
    return Nan::ThrowError("cashaddr.test() requires arguments.");

  if (!info[0]->IsString())
    return Nan::ThrowTypeError("First argument must be a string.");

  if (!info[1]->IsString())
    return Nan::ThrowTypeError("Second argument must be a string.");

  Nan::Utf8String addr_(info[0]);
  const char *addr = (const char *)*addr_;

  Nan::Utf8String default_prefix_(info[1]);
  const char *default_prefix = (const char *)*default_prefix_;

  bcrypto_cashaddr_error err = bcrypto_cashaddr_ERR_NULL;

  bool result = bcrypto_cashaddr_test(&err, default_prefix, addr);

  info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}
