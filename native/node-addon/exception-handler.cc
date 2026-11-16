#include "exception-handler.hh"

void ExceptionHandler::CreateAndThrow(Napi::Env& env, std::string& message) {
  if (env.IsExceptionPending()) {
    // Merge exceptions if an exception has already been thrown
    auto error = env.GetAndClearPendingException();
    message = error.Message() + "\n" + message;
  }
  Napi::Error::New(env, message).ThrowAsJavaScriptException();
}

void ExceptionHandler::CreateAndThrow(Napi::Env& env, const char* message) {
  std::string exMessage = message;
  CreateAndThrow(env, exMessage);
}

void ExceptionHandler::CreateAndThrow(Napi::Env& env, const char* message, int resultCode) {
  std::string exMessage = message;
  CreateAndThrow(env, exMessage, resultCode);
}

void ExceptionHandler::CreateAndThrow(Napi::Env& env, std::string& message, int resultCode) {
  message = message + std::to_string(resultCode);
  CreateAndThrow(env, message);
}
