#include "secur32-facade.hh"
#include "exception-handler.hh"
#include "auth-context.hh"

#include <Secext.h>
#include <Security.h>
#include <string.h>

std::map<unsigned long, std::shared_ptr<AuthContext>> Secur32Facade::acMap = std::map<unsigned long, std::shared_ptr<AuthContext>>();
unsigned long Secur32Facade::acKey = 0;

Napi::String Secur32Facade::GetLogonUserName(const Napi::CallbackInfo& info) {
  static char _userName[256] = "";
  Napi::Env env = info.Env();
  if (_userName[0]) {
    return Napi::String::New(env, _userName);
  }

  unsigned long userNameLength = 256;
  int result = ::GetUserNameExA(NameSamCompatible, _userName, &userNameLength);
  if (result < 0) {
  ExceptionHandler::CreateAndThrow(env, "Could not get user name of logged in user. Result: ", result);
    return Napi::String::New(env, "");
  }
  _userName[userNameLength] = '\0';
  auto name = Napi::String::New(env, _userName);

  return name;
}

unsigned int Secur32Facade::GetMaxTokenLength(char* packageName, Napi::Env* env) {
  static unsigned int _maxTokenLength = 0;

  if (_maxTokenLength != 0) {
    return _maxTokenLength;
  }

  PSecPkgInfoA	  	pkgInfo;
  int result = ::QuerySecurityPackageInfoA(packageName, &pkgInfo);
  if (result != 0) {
    ExceptionHandler::CreateAndThrow(*env, "Could not get SecurityPackageInfo. Result: ", result);
    return 0;
  }
  _maxTokenLength = pkgInfo->cbMaxToken;
  result = ::FreeContextBuffer(pkgInfo);
  if (result != 0) {
    ExceptionHandler::CreateAndThrow(*env, "Could not free context buffer. Result: ", result);
    return 0;
  }
  return _maxTokenLength;
}

void Secur32Facade::AcquireCredentialsHandle(char* packageName, CredHandle* credHandle, SECURITY_INTEGER* lifeTime, Napi::Env* env) {
  int result = ::AcquireCredentialsHandleA(NULL, packageName, SECPKG_CRED_OUTBOUND, NULL, NULL, NULL, NULL, credHandle, lifeTime);
  if (result < 0) {
    ExceptionHandler::CreateAndThrow(*env, "Could not acquire credentials handle. Result: ", result);
  }
}

void Secur32Facade::FreeCredentialsHandle(CredHandle* credHandle, Napi::Env* env) {
  int result = ::FreeCredentialsHandle(credHandle);
  if (result != 0 && env != 0) {
    ExceptionHandler::CreateAndThrow(*env, "Could not free credentials handle. Result: ", result);
  }
}

int Secur32Facade::InitializeSecurityContext(
  SecBufferDesc* inSecBufferDesc,
  SecBufferDesc* outSecBufferDesc,
  char* targetHostSpn,
  CredHandle* credHandle,
  struct _SecHandle* ctxHandle,
  unsigned long flags,
  SECURITY_INTEGER* lifeTime,
  Napi::Env* env)
{
  int result = 0;
  unsigned long ignored;

  if (inSecBufferDesc == NULL) {
    result = ::InitializeSecurityContextA(
      credHandle,
      NULL,
      targetHostSpn,
      flags,
      0,
      SECURITY_NATIVE_DREP,
      NULL,
      0,
      ctxHandle,
      outSecBufferDesc,
      &ignored,
      lifeTime
    );
  } else {
    result = ::InitializeSecurityContextA(
      credHandle,
      ctxHandle,
      targetHostSpn,
      flags,
      0,
      SECURITY_NATIVE_DREP,
      inSecBufferDesc,
      0,
      ctxHandle,
      outSecBufferDesc,
      &ignored,
      lifeTime
    );
  }
  if (result < 0) {
    ExceptionHandler::CreateAndThrow(*env, "Could not init security context. Result: ", result);
  }
  return result;
}

void Secur32Facade::FreeContextHandle(struct _SecHandle* ctxHandle, Napi::Env* env) {
  int result = ::DeleteSecurityContext(ctxHandle);
  if (result != 0 && env != 0) {
    ExceptionHandler::CreateAndThrow(*env, "Could not delete security context. Result: ", result);
  }
}

unsigned long Secur32Facade::GetDefaultFlags(std::string securityPackageName) {
  if (securityPackageName == "Negotiate" || securityPackageName == "Kerberos") {
    return ISC_REQ_MUTUAL_AUTH | ISC_REQ_SEQUENCE_DETECT;
  }
  return 0;
}

Napi::Number Secur32Facade::CreateAuthContext(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 4) {
    ExceptionHandler::CreateAndThrow(env, "Wrong number of arguments");
    return Napi::Number::New(env, 0);
  }

  if (!info[0].IsString() || !info[1].IsString() || !info[2].IsBuffer() || !(info[3].IsUndefined() || info[3].IsNumber())) {
    ExceptionHandler::CreateAndThrow(env, "Wrong argument types");
    return Napi::Number::New(env, 0);
  }
  auto securityPackageName = info[0].ToString();
  auto targetHost = info[1].ToString();
  auto applicationDataBuffer = info[2].As<Napi::Buffer<unsigned char>>();
  auto flags = info[3].IsNumber() ? (unsigned long)(info[3].ToNumber().Uint32Value()) : GetDefaultFlags(securityPackageName);

  auto ac = std::make_shared<AuthContext>();
  ac->Init(&(securityPackageName.Utf8Value()), &(targetHost.Utf8Value()), applicationDataBuffer, flags, &env);
  acKey++;
  acMap[acKey] = ac;
  return Napi::Number::New(env, acKey);
}

Napi::Number Secur32Facade::FreeAuthContext(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1) {
    ExceptionHandler::CreateAndThrow(env, "Wrong number of arguments");
    return Napi::Number::New(env, 0);
  }

  if (!info[0].IsNumber()) {
    ExceptionHandler::CreateAndThrow(env, "Wrong argument types");
    return Napi::Number::New(env, 0);
  }

  auto acKey = info[0].ToNumber().Uint32Value();
  size_t erased = 0;
  if (acMap.find(acKey) != acMap.end()) {
    acMap[acKey]->Cleanup(&env);
    erased = acMap.erase(acKey);
  }
  return Napi::Number::New(env, erased);
}

/**
 * Creates a NTLM type 1 authentication token
 */
Napi::Buffer<unsigned char> Secur32Facade::CreateAuthRequest(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1) {
    ExceptionHandler::CreateAndThrow(env, "Wrong number of arguments");
    return Napi::Buffer<unsigned char>::Buffer();
  }

  if (!info[0].IsNumber()) {
    ExceptionHandler::CreateAndThrow(env, "Wrong argument types");
    return Napi::Buffer<unsigned char>::Buffer();
  }

  auto acKey = info[0].ToNumber().Uint32Value();

  if (acMap.find(acKey) == acMap.end()) {
    ExceptionHandler::CreateAndThrow(env, "AuthContext not found");
    return Napi::Buffer<unsigned char>::Buffer();
  }

  auto ac = acMap[acKey];
  ac->InitContext(&env);
  return ac->OutToken(&env);
}

/**
 * Creates a NTLM type 3 authentication token
 */
Napi::Buffer<unsigned char> Secur32Facade::CreateAuthResponse(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 2) {
    ExceptionHandler::CreateAndThrow(env, "Wrong number of arguments");
    return Napi::Buffer<unsigned char>::Buffer();
  }

  if (!info[0].IsNumber() && !info[1].IsBuffer()) {
    ExceptionHandler::CreateAndThrow(env, "Wrong argument types");
    return Napi::Buffer<unsigned char>::Buffer();
  }

  auto acKey = info[0].ToNumber().Uint32Value();
  if (acMap.find(acKey) == acMap.end()) {
    ExceptionHandler::CreateAndThrow(env, "AuthContext not found");
    return Napi::Buffer<unsigned char>::Buffer();
  }

  auto inTokenBuffer = info[1].As<Napi::Buffer<unsigned char>>();
  auto ac = acMap[acKey];
  ac->HandleResponse(inTokenBuffer, &env);
  return ac->OutToken(&env);
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
  exports.Set(Napi::String::New(env, "getLogonUserName"),
              Napi::Function::New(env, Secur32Facade::GetLogonUserName));
  exports.Set(Napi::String::New(env, "createAuthContext"),
              Napi::Function::New(env, Secur32Facade::CreateAuthContext));
  exports.Set(Napi::String::New(env, "freeAuthContext"),
              Napi::Function::New(env, Secur32Facade::FreeAuthContext));
  exports.Set(Napi::String::New(env, "createAuthRequest"),
              Napi::Function::New(env, Secur32Facade::CreateAuthRequest));
  exports.Set(Napi::String::New(env, "createAuthResponse"),
              Napi::Function::New(env, Secur32Facade::CreateAuthResponse));
  return exports;
}

NODE_API_MODULE(WinSso, Init)
