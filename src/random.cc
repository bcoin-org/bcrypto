#include <assert.h>
#include <string.h>
#include <node.h>
#include <nan.h>

#include "random/random.h"
#include "random.h"

static Nan::Persistent<v8::FunctionTemplate> random_constructor;

BRandom::BRandom() {}

BRandom::~BRandom() {}

void
BRandom::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;

  v8::Local<v8::FunctionTemplate> tpl =
    Nan::New<v8::FunctionTemplate>(BRandom::New);

  random_constructor.Reset(tpl);

  tpl->SetClassName(Nan::New("Random").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  Nan::SetMethod(tpl, "randomFill", BRandom::RandomFill);

  v8::Local<v8::FunctionTemplate> ctor =
    Nan::New<v8::FunctionTemplate>(random_constructor);

  target->Set(Nan::New("random").ToLocalChecked(), ctor->GetFunction());
}

NAN_METHOD(BRandom::New) {
  return Nan::ThrowError("Could not create Random instance.");
}

NAN_METHOD(BRandom::RandomFill) {
  if (info.Length() < 3)
    return Nan::ThrowError("random.randomFill() requires arguments.");

  if (!node::Buffer::HasInstance(info[0]))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  v8::Local<v8::Object> bdata = info[0].As<v8::Object>();

  if (!info[1]->IsNumber())
    return Nan::ThrowTypeError("Second argument must be a number.");

  if (!info[2]->IsNumber())
    return Nan::ThrowTypeError("Third argument must be a number.");

  uint8_t *data = (uint8_t *)node::Buffer::Data(bdata);
  size_t len = node::Buffer::Length(bdata);

  uint32_t pos = info[1]->Uint32Value();
  uint32_t size = info[2]->Uint32Value();

  if ((len & 0x80000000) != 0
      || (pos & 0x80000000) != 0
      || (size & 0x80000000) != 0) {
    return Nan::ThrowError("Invalid range.");
  }

  if (pos + size > len)
    return Nan::ThrowError("Size exceeds length.");

  if (!bcrypto_random(&data[pos], size))
    return Nan::ThrowError("Could not get random bytes.");

  info.GetReturnValue().Set(bdata);
}
