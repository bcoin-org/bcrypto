#include "poly1305.h"

static Nan::Persistent<v8::FunctionTemplate> poly1305_constructor;

Poly1305::Poly1305() {
  memset(&ctx, 0, sizeof(poly1305_context));
}

Poly1305::~Poly1305() {}

void
Poly1305::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;

  v8::Local<v8::FunctionTemplate> tpl =
    Nan::New<v8::FunctionTemplate>(Poly1305::New);

  poly1305_constructor.Reset(tpl);

  tpl->SetClassName(Nan::New("Poly1305").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  Nan::SetPrototypeMethod(tpl, "init", Poly1305::Init);
  Nan::SetPrototypeMethod(tpl, "update", Poly1305::Update);
  Nan::SetPrototypeMethod(tpl, "final", Poly1305::Final);
  Nan::SetMethod(tpl, "auth", Poly1305::Auth);
  Nan::SetMethod(tpl, "verify", Poly1305::Verify);

  v8::Local<v8::FunctionTemplate> ctor =
    Nan::New<v8::FunctionTemplate>(poly1305_constructor);

  target->Set(Nan::New("Poly1305").ToLocalChecked(), ctor->GetFunction());
}

NAN_METHOD(Poly1305::New) {
  if (!info.IsConstructCall())
    return Nan::ThrowError("Could not create Poly1305 instance.");

  Poly1305 *poly = new Poly1305();
  poly->Wrap(info.This());
  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(Poly1305::Init) {
  Poly1305 *poly = ObjectWrap::Unwrap<Poly1305>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("poly1305.init() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *data = (uint8_t *)node::Buffer::Data(buf);
  size_t len = node::Buffer::Length(buf);

  if (len != 32)
    return Nan::ThrowError("Invalid key size.");

  poly1305_init(&poly->ctx, data);

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(Poly1305::Update) {
  Poly1305 *poly = ObjectWrap::Unwrap<Poly1305>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("poly1305.update() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *data = (uint8_t *)node::Buffer::Data(buf);
  size_t len = node::Buffer::Length(buf);

  poly1305_update(&poly->ctx, data, len);

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(Poly1305::Final) {
  Poly1305 *poly = ObjectWrap::Unwrap<Poly1305>(info.Holder());

  uint8_t mac[16];

  poly1305_finish(&poly->ctx, mac);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&mac[0], 16).ToLocalChecked());
}

NAN_METHOD(Poly1305::Auth) {
  if (info.Length() < 2)
    return Nan::ThrowError("poly1305.auth() requires arguments.");

  v8::Local<v8::Object> buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  v8::Local<v8::Object> kbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(kbuf))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  const uint8_t *data = (uint8_t *)node::Buffer::Data(buf);
  size_t len = node::Buffer::Length(buf);

  const uint8_t *kdata = (uint8_t *)node::Buffer::Data(kbuf);
  size_t klen = node::Buffer::Length(kbuf);

  if (klen != 32)
    return Nan::ThrowError("Invalid key size.");

  uint8_t mac[16];

  poly1305_auth(mac, data, len, kdata);

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)&mac[0], 16).ToLocalChecked());
}

NAN_METHOD(Poly1305::Verify) {
  if (info.Length() < 2)
    return Nan::ThrowError("poly1305.verify() requires arguments.");

  v8::Local<v8::Object> abuf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(abuf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  v8::Local<v8::Object> bbuf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(bbuf))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  const uint8_t *adata = (uint8_t *)node::Buffer::Data(abuf);
  size_t alen = node::Buffer::Length(abuf);

  const uint8_t *bdata = (uint8_t *)node::Buffer::Data(bbuf);
  size_t blen = node::Buffer::Length(bbuf);

  if (alen != 16)
    return Nan::ThrowError("Invalid mac size.");

  if (blen != 16)
    return Nan::ThrowError("Invalid mac size.");

  int32_t result = poly1305_verify(adata, bdata);

  info.GetReturnValue().Set(Nan::New<v8::Boolean>((bool)result));
}
