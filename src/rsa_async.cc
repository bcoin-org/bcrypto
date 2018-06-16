#include <assert.h>
#include <node.h>
#include <nan.h>

#if NODE_MAJOR_VERSION >= 10
#include "rsa/rsa.h"
#include "rsa_async.h"

BRSAWorker::BRSAWorker (
  int bits,
  int exp,
  Nan::Callback *callback
) : Nan::AsyncWorker(callback)
  , bits(bits)
  , exp(exp)
  , key(NULL)
{
  Nan::HandleScope scope;
}

BRSAWorker::~BRSAWorker() {}

void
BRSAWorker::Execute() {
  key = bcrypto_rsa_generate(bits, exp);

  if (key == NULL)
    SetErrorMessage("Could not generate key.");
}

void
BRSAWorker::HandleOKCallback() {
  Nan::HandleScope scope;

  bcrypto_rsa_key_t *k = key;
  assert(k);

  v8::Local<v8::Array> ret = Nan::New<v8::Array>();
  ret->Set(0, Nan::CopyBuffer((char *)&k->nd[0], k->nl).ToLocalChecked());
  ret->Set(1, Nan::CopyBuffer((char *)&k->ed[0], k->el).ToLocalChecked());
  ret->Set(2, Nan::CopyBuffer((char *)&k->dd[0], k->dl).ToLocalChecked());
  ret->Set(3, Nan::CopyBuffer((char *)&k->pd[0], k->pl).ToLocalChecked());
  ret->Set(4, Nan::CopyBuffer((char *)&k->qd[0], k->ql).ToLocalChecked());
  ret->Set(5, Nan::CopyBuffer((char *)&k->dpd[0], k->dpl).ToLocalChecked());
  ret->Set(6, Nan::CopyBuffer((char *)&k->dqd[0], k->dql).ToLocalChecked());
  ret->Set(7, Nan::CopyBuffer((char *)&k->qid[0], k->qil).ToLocalChecked());

  bcrypto_rsa_key_free(k);

  v8::Local<v8::Value> argv[] = { Nan::Null(), ret };

  callback->Call(2, argv, async_resource);
}
#endif
