#ifndef _BCRYPTO_AES_H
#define _BCRYPTO_AES_H
#include <node.h>
#include <nan.h>
#include "openssl/aes.h"

class AESCipher : public Nan::ObjectWrap {
public:
  static NAN_METHOD(New);
  static void Init(v8::Local<v8::Object> &target);

  AESCipher();
  ~AESCipher();

  uint32_t bits;
  bool chain;
  AES_KEY key;
  uint8_t prev[16];
  uint8_t block[16];
  uint32_t bpos;

private:
  static NAN_METHOD(Init);
  static NAN_METHOD(Update);
  static NAN_METHOD(Final);
};

class AESDecipher : public Nan::ObjectWrap {
public:
  static NAN_METHOD(New);
  static void Init(v8::Local<v8::Object> &target);

  AESDecipher();
  ~AESDecipher();

  uint32_t bits;
  bool chain;
  AES_KEY key;
  uint8_t prev[16];
  uint8_t block[16];
  uint8_t last[16];
  uint32_t bpos;

private:
  static NAN_METHOD(Init);
  static NAN_METHOD(Update);
  static NAN_METHOD(Final);
};
#endif
