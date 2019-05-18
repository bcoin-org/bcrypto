#include <assert.h>
#include <node.h>
#include <nan.h>

#include "common.h"
#include "rsa/rsa.h"
#include "rsa_async.h"

BRSAWorker::BRSAWorker (
  int bits,
  uint64_t exponent,
  Nan::Callback *callback
) : Nan::AsyncWorker(callback)
  , bits(bits)
  , exponent(exponent)
{
  Nan::HandleScope scope;
  bcrypto_rsa_key_init(&key);
}

BRSAWorker::~BRSAWorker() {
  bcrypto_rsa_key_uninit(&key);
}

void
BRSAWorker::Execute() {
  if (!bcrypto_rsa_privkey_generate(&key, bits, exponent))
    SetErrorMessage("Could not generate key.");
}

void
BRSAWorker::HandleOKCallback() {
  Nan::HandleScope scope;

  bcrypto_rsa_key_t *k = &key;

  v8::Local<v8::Array> ret = Nan::New<v8::Array>();
  Nan::Set(ret, 0, Nan::CopyBuffer((char *)k->nd, k->nl).ToLocalChecked());
  Nan::Set(ret, 1, Nan::CopyBuffer((char *)k->ed, k->el).ToLocalChecked());
  Nan::Set(ret, 2, Nan::CopyBuffer((char *)k->dd, k->dl).ToLocalChecked());
  Nan::Set(ret, 3, Nan::CopyBuffer((char *)k->pd, k->pl).ToLocalChecked());
  Nan::Set(ret, 4, Nan::CopyBuffer((char *)k->qd, k->ql).ToLocalChecked());
  Nan::Set(ret, 5, Nan::CopyBuffer((char *)k->dpd, k->dpl).ToLocalChecked());
  Nan::Set(ret, 6, Nan::CopyBuffer((char *)k->dqd, k->dql).ToLocalChecked());
  Nan::Set(ret, 7, Nan::CopyBuffer((char *)k->qid, k->qil).ToLocalChecked());

  v8::Local<v8::Value> argv[] = { Nan::Null(), ret };

  callback->Call(2, argv, async_resource);
}
