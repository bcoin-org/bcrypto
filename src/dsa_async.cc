#include <assert.h>
#include <node.h>
#include <nan.h>

#include "common.h"
#include "dsa/dsa.h"
#include "dsa_async.h"

BDSAWorker::BDSAWorker (
  int bits,
  Nan::Callback *callback
) : Nan::AsyncWorker(callback)
  , bits(bits)
{
  Nan::HandleScope scope;
  bcrypto_dsa_key_init(&key);
}

BDSAWorker::~BDSAWorker() {
  bcrypto_dsa_key_uninit(&key);
}

void
BDSAWorker::Execute() {
  if (!bcrypto_dsa_params_generate(&key, bits))
    SetErrorMessage("Could not generate key.");
}

void
BDSAWorker::HandleOKCallback() {
  Nan::HandleScope scope;

  v8::Local<v8::Array> ret = Nan::New<v8::Array>();
  Nan::Set(ret, 0, Nan::CopyBuffer((char *)key.pd, key.pl).ToLocalChecked());
  Nan::Set(ret, 1, Nan::CopyBuffer((char *)key.qd, key.ql).ToLocalChecked());
  Nan::Set(ret, 2, Nan::CopyBuffer((char *)key.gd, key.gl).ToLocalChecked());

  v8::Local<v8::Value> argv[] = { Nan::Null(), ret };

  callback->Call(2, argv, async_resource);
}
