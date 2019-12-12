#ifndef EXCEPTION_HANDLER_HH
#define EXCEPTION_HANDLER_HH

#include <string.h>
#include <napi.h>

class ExceptionHandler {
  public:
  static void CreateAndThrow(Napi::Env& env, const char* message);
  static void CreateAndThrow(Napi::Env& env, std::string& message);
  static void CreateAndThrow(Napi::Env& env, const char* message, int resultCode);
  static void CreateAndThrow(Napi::Env& env, std::string& message, int resultCode);
};

#endif
