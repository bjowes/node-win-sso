#include "secur32-facade.hh"
#include "exception-handler.hh"

#include <Secext.h>
#include <Security.h>
#include <string.h>

std::string Secur32Facade::_packageName = "NTLM";

Napi::String Secur32Facade::GetLogonUserName(const Napi::CallbackInfo& info) {
  static char _userName[256] = "";
  Napi::Env env = info.Env();
  if (_userName[0]) {
    return Napi::String::New(env, _userName);
  }

  unsigned long userNameLength = 256;
  int result = GetUserNameExA(NameSamCompatible, _userName, &userNameLength);
  if (result < 0) {
    ExceptionHandler::CreateAndThrow(env, "Could not get user name of logged in user. Result: ", result);
    return Napi::String::New(env, "");
  }
  _userName[userNameLength] = '\0';
  auto name = Napi::String::New(env, _userName);

  return name;
}

unsigned int Secur32Facade::GetMaxTokenLength(Napi::Env& env) {
  static unsigned int _maxTokenLength = 0;

  if (_maxTokenLength != 0) {
    return _maxTokenLength;
  }

  PSecPkgInfoA	  	pkgInfo;
  int result = QuerySecurityPackageInfoA((char*)(_packageName.c_str()), &pkgInfo);
  if (result != 0) {
    ExceptionHandler::CreateAndThrow(env, "Could not get SecurityPackageInfo. Result: ", result);
    return 0;
  }
  _maxTokenLength = pkgInfo->cbMaxToken;
  result = FreeContextBuffer(pkgInfo);
  if (result != 0) {
    ExceptionHandler::CreateAndThrow(env, "Could not free context buffer. Result: ", result);
    return 0;
  }
  return _maxTokenLength;
}

void Secur32Facade::AcquireCredentialsHandle(CredHandle* credHandle, SECURITY_INTEGER* lifeTime, Napi::Env& env) {
  int result = ::AcquireCredentialsHandleA(NULL, (char*)(_packageName.c_str()), SECPKG_CRED_OUTBOUND, NULL, NULL, NULL, NULL, credHandle, lifeTime);
  if (result < 0) {
    ExceptionHandler::CreateAndThrow(env, "Could not acquire credentials handle. Result: ", result);
  }
}

void Secur32Facade::FreeCredentialsHandle(CredHandle* credHandle, Napi::Env& env) {
  int result = ::FreeCredentialsHandle(credHandle);
  if (result != 0) {
    ExceptionHandler::CreateAndThrow(env, "Could not free credentials handle. Result: ", result);
  }
}

int Secur32Facade::InitializeSecurityContext(
  SecBufferDesc* inSecBufferDesc,
  SecBufferDesc* outSecBufferDesc,
  std::string* targetHost,
  CredHandle* credHandle,
  struct _SecHandle* ctxHandle,
  unsigned long* ctxAttributes,
  SECURITY_INTEGER* lifeTime,
  Napi::Env& env)
{
  int result = 0;
  if (inSecBufferDesc == NULL) {
    result = ::InitializeSecurityContextA(
      credHandle,
      NULL,
      NULL,
      0,
      0,
      SECURITY_NATIVE_DREP,
      NULL,
      0,
      ctxHandle,
      outSecBufferDesc,
      ctxAttributes,
      lifeTime
    );
  } else {
    char* spn = NULL;
    if (targetHost != NULL) {
      std::string spnPrep = "HTTP/" + *targetHost;
      spn = (char*)spnPrep.c_str();
    }
    result = ::InitializeSecurityContextA(
      credHandle,
      ctxHandle,
      spn,
      *ctxAttributes,
      0,
      SECURITY_NATIVE_DREP,
      inSecBufferDesc,
      0,
      ctxHandle,
      outSecBufferDesc,
      ctxAttributes,
      lifeTime
    );
  }
  if (result < 0) {
    ExceptionHandler::CreateAndThrow(env, "Could not init security context. Result: ", result);
  }
  return result;
}

void Secur32Facade::FreeContextHandle(struct _SecHandle* ctxHandle, Napi::Env& env) {
  int result = DeleteSecurityContext(ctxHandle);
  if (result != 0) {
    ExceptionHandler::CreateAndThrow(env, "Could not delete security context. Result: ", result);
  }
}

Napi::Buffer<unsigned char> Secur32Facade::CreateAuthRequest(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  SecBufferDesc outSecBufferDesc;
  SecBuffer outSecBuff;
  CredHandle credHandle;
  SECURITY_INTEGER lifeTime;
  struct _SecHandle ctxHandle;
  unsigned long ctxAttributes = 0;
  unsigned long maxTokenLength = Secur32Facade::GetMaxTokenLength(env);
  unsigned char* outToken = new unsigned char[maxTokenLength];

  outSecBufferDesc.ulVersion = 0;
  outSecBufferDesc.cBuffers = 1;
  outSecBufferDesc.pBuffers = &outSecBuff;

  outSecBuff.cbBuffer = maxTokenLength;
  outSecBuff.BufferType = SECBUFFER_TOKEN;
  outSecBuff.pvBuffer = outToken;

  Secur32Facade::AcquireCredentialsHandle(&credHandle, &lifeTime, env);
  if (env.IsExceptionPending()) {
    return Napi::Buffer<unsigned char>::Buffer();
  }

  // Here we use _packageName as target SPN since the target SPN is not used in this call
  int result = Secur32Facade::InitializeSecurityContext(NULL, &outSecBufferDesc, &_packageName, &credHandle, &ctxHandle, &ctxAttributes, &lifeTime, env);
  if (env.IsExceptionPending()) {
    Secur32Facade::FreeCredentialsHandle(&credHandle, env);
    return Napi::Buffer<unsigned char>::Buffer();
  }
  if (result != SEC_I_CONTINUE_NEEDED) {
    ExceptionHandler::CreateAndThrow(env, "Init security context did not return SEC_I_CONTINUE_NEEDED. Result: ", result);
    Secur32Facade::FreeCredentialsHandle(&credHandle, env);
    return Napi::Buffer<unsigned char>::Buffer();
  }

  Secur32Facade::FreeContextHandle(&ctxHandle, env);
  Secur32Facade::FreeCredentialsHandle(&credHandle, env);

  auto outTokenBuffer = Napi::Buffer<unsigned char>::Copy(env, outToken, outSecBuff.cbBuffer);
  delete outToken;
  return outTokenBuffer;
}

Napi::Buffer<unsigned char> Secur32Facade::CreateAuthResponse(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 3) {
    ExceptionHandler::CreateAndThrow(env, "Wrong number of arguments");
    return Napi::Buffer<unsigned char>::Buffer();
  }

  if (!info[0].IsBuffer() || !info[1].IsString() || !info[2].IsBuffer()) {
    ExceptionHandler::CreateAndThrow(env, "Wrong types of arguments");
    return Napi::Buffer<unsigned char>::Buffer();
  }

  SecBufferDesc outSecBufferDesc;
  SecBuffer outSecBuff;
  CredHandle credHandle;
  SECURITY_INTEGER lifeTime;
  struct _SecHandle ctxHandle;
  unsigned long ctxAttributes = 0;
  unsigned long maxTokenLength = Secur32Facade::GetMaxTokenLength(env);
  unsigned char* outToken = new unsigned char[maxTokenLength];

  outSecBufferDesc.ulVersion = 0;
  outSecBufferDesc.cBuffers = 1;
  outSecBufferDesc.pBuffers = &outSecBuff;

  outSecBuff.cbBuffer = maxTokenLength;
  outSecBuff.BufferType = SECBUFFER_TOKEN;
  outSecBuff.pvBuffer = outToken;

  AcquireCredentialsHandle(&credHandle, &lifeTime, env);
  if (env.IsExceptionPending()) {
    return Napi::Buffer<unsigned char>::Buffer();
  }

  std::string targetHost = info[1].ToString().Utf8Value();
  std::string* targetHostRef = NULL;
  if (targetHost.length() > 0) {
    targetHostRef = &targetHost;
  }

  int result = Secur32Facade::InitializeSecurityContext(NULL, &outSecBufferDesc, targetHostRef, &credHandle, &ctxHandle, &ctxAttributes, &lifeTime, env);
  if (env.IsExceptionPending()) {
    Secur32Facade::FreeCredentialsHandle(&credHandle, env);
    return Napi::Buffer<unsigned char>::Buffer();
  }
  if (result != SEC_I_CONTINUE_NEEDED) {
    ExceptionHandler::CreateAndThrow(env, "Init security context did not return SEC_I_CONTINUE_NEEDED. Result: ", result);
    Secur32Facade::FreeCredentialsHandle(&credHandle, env);
    return Napi::Buffer<unsigned char>::Buffer();
  }

  SecBufferDesc inSecBufferDesc;
  SecBuffer inSecBuffers[2];
  struct SecChannelBindingsCombined {
    struct _SEC_CHANNEL_BINDINGS secChannelBindings;
    unsigned char applicationData[128];
  };
  struct SecChannelBindingsCombined channelBindings;
  auto inTokenBuffer = info[0].As<Napi::Buffer<unsigned char>>();
  auto applicationDataBuffer = info[2].As<Napi::Buffer<unsigned char>>();
  inSecBufferDesc.ulVersion = 0;
  inSecBufferDesc.cBuffers = 1;
  inSecBufferDesc.pBuffers = inSecBuffers;

  inSecBuffers[0].cbBuffer = inTokenBuffer.Length();
  inSecBuffers[0].BufferType = SECBUFFER_TOKEN;
  inSecBuffers[0].pvBuffer = inTokenBuffer.Data();

  if (applicationDataBuffer.Length() > 0) {
    channelBindings.secChannelBindings.dwInitiatorAddrType = 0;
    channelBindings.secChannelBindings.cbInitiatorLength = 0;
    channelBindings.secChannelBindings.dwInitiatorOffset = 0;
    channelBindings.secChannelBindings.dwAcceptorAddrType = 0;
    channelBindings.secChannelBindings.cbAcceptorLength = 0;
    channelBindings.secChannelBindings.dwAcceptorOffset = 0;
    channelBindings.secChannelBindings.cbApplicationDataLength = applicationDataBuffer.Length();
    channelBindings.secChannelBindings.dwApplicationDataOffset = 32;
    memcpy(channelBindings.applicationData, applicationDataBuffer.Data(), applicationDataBuffer.Length());
    inSecBufferDesc.cBuffers++;
    inSecBuffers[1].cbBuffer = (32 + applicationDataBuffer.Length());
    inSecBuffers[1].BufferType = SECBUFFER_CHANNEL_BINDINGS;
    inSecBuffers[1].pvBuffer = &channelBindings;
  }

  outSecBuff.cbBuffer = maxTokenLength;

  result = Secur32Facade::InitializeSecurityContext(&inSecBufferDesc, &outSecBufferDesc, targetHostRef, &credHandle, &ctxHandle, &ctxAttributes, &lifeTime, env);
  if (env.IsExceptionPending()) {
    Secur32Facade::FreeContextHandle(&ctxHandle, env);
    Secur32Facade::FreeCredentialsHandle(&credHandle, env);
    return Napi::Buffer<unsigned char>::Buffer();
  }
  if (result != SEC_E_OK) {
    ExceptionHandler::CreateAndThrow(env, "Init security context did not return SEC_E_OK. Result: ", result);
    Secur32Facade::FreeContextHandle(&ctxHandle, env);
    Secur32Facade::FreeCredentialsHandle(&credHandle, env);
    return Napi::Buffer<unsigned char>::Buffer();
  }

  Secur32Facade::FreeContextHandle(&ctxHandle, env);
  Secur32Facade::FreeCredentialsHandle(&credHandle, env);

  auto outTokenBuffer = Napi::Buffer<unsigned char>::Copy(env, outToken, outSecBuff.cbBuffer);
  delete outToken;
  return outTokenBuffer;
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
  exports.Set(Napi::String::New(env, "getLogonUserName"),
              Napi::Function::New(env, Secur32Facade::GetLogonUserName));
  exports.Set(Napi::String::New(env, "createAuthRequest"),
              Napi::Function::New(env, Secur32Facade::CreateAuthRequest));
  exports.Set(Napi::String::New(env, "createAuthResponse"),
              Napi::Function::New(env, Secur32Facade::CreateAuthResponse));
  return exports;
}

NODE_API_MODULE(Secur32Facade, Init)


