#include "auth-context.hh"
#include "secur32-facade.hh"
#include "exception-handler.hh"

AuthContext::AuthContext() {
  credHandle = {};
  lifeTime = {};
  ctxHandle = {};
  flags = 0;
  maxTokenLength = 0;
  outToken = nullptr;
  outTokenLength = 0;
  credHandleAllocated = false;
  ctxHandleAllocated = false;
  channelBindings = {};
  channelBindingsLength = 0;
  targetHostnameSpn = nullptr;
};

AuthContext::~AuthContext() {
  // Napi::Env is not available in destructor, but we can still do cleanup without
  // reporting JS exceptions to Node
  Cleanup(0);
}

void AuthContext::Cleanup(Napi::Env* env) {
  if (credHandleAllocated) {
    Secur32Facade::FreeCredentialsHandle(&credHandle, env);
    credHandleAllocated = false;
  }
  if (ctxHandleAllocated) {
    Secur32Facade::FreeContextHandle(&ctxHandle, env);
    ctxHandleAllocated = false;
  }
  if (outToken) {
    delete outToken;
    outToken = nullptr;
  }
  if (targetHostnameSpn) {
    delete targetHostnameSpn;
    targetHostnameSpn = nullptr;;
  }
}

bool AuthContext::Init(std::string* securityPackageName, std::string* targetHost, Napi::Buffer<unsigned char>& applicationDataBuffer, unsigned long flags, Napi::Env* env) {
  this->flags = flags;
  auto packageNameLen = securityPackageName->copy(packageName, sizeof(packageName) - 1);
  packageName[packageNameLen] = '\0';
  targetHostname = *targetHost;
  if (targetHostname.length() > 0) {
    int len = targetHostname.length() + 5 + 1;
    targetHostnameSpn = new char[len];
    strncpy(targetHostnameSpn, ("HTTP/" + targetHostname).c_str(), len);
  }
  maxTokenLength = Secur32Facade::GetMaxTokenLength(packageName, env);
  SetupChannelBindings(applicationDataBuffer);
  Secur32Facade::AcquireCredentialsHandle(packageName, &credHandle, &lifeTime, env);
  if (env->IsExceptionPending()) {
    Cleanup(env);
    return false;
  }
  credHandleAllocated = true;
  return true;
}

void AuthContext::SetupChannelBindings(Napi::Buffer<unsigned char>& applicationDataBuffer) {
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
    channelBindingsLength = (32 + applicationDataBuffer.Length());
  }
}

bool AuthContext::InitContext(Napi::Env* env) {
  SecBufferDesc outSecBufferDesc;
  SecBuffer outSecBuff;
  outToken = new unsigned char[maxTokenLength];

  outSecBufferDesc.ulVersion = 0;
  outSecBufferDesc.cBuffers = 1;
  outSecBufferDesc.pBuffers = &outSecBuff;

  outSecBuff.cbBuffer = maxTokenLength;
  outSecBuff.BufferType = SECBUFFER_TOKEN;
  outSecBuff.pvBuffer = outToken;

  int result = Secur32Facade::InitializeSecurityContext(
    NULL, &outSecBufferDesc, targetHostnameSpn, &credHandle, &ctxHandle, flags, &lifeTime, env);
  if (env->IsExceptionPending()) {
    Cleanup(env);
    return false;
  }
  if (result != SEC_I_CONTINUE_NEEDED && result != SEC_E_OK) {
    ExceptionHandler::CreateAndThrow(*env, "Init security context did not return SEC_I_CONTINUE_NEEDED or SEC_E_OK. Result: ", result);
    Cleanup(env);
    return false;
  }
  ctxHandleAllocated = true;
  outTokenLength = outSecBuff.cbBuffer;
  return true;
}

bool AuthContext::HandleResponse(
  Napi::Buffer<unsigned char>& inTokenBuffer,
  Napi::Env* env) {
  SecBufferDesc outSecBufferDesc;
  SecBuffer outSecBuff;
  SecBufferDesc inSecBufferDesc;
  SecBuffer inSecBuffers[2];

  outSecBufferDesc.ulVersion = 0;
  outSecBufferDesc.cBuffers = 1;
  outSecBufferDesc.pBuffers = &outSecBuff;

  outSecBuff.cbBuffer = maxTokenLength;
  outSecBuff.BufferType = SECBUFFER_TOKEN;
  outSecBuff.pvBuffer = outToken;

  inSecBufferDesc.ulVersion = 0;
  inSecBufferDesc.cBuffers = 1;
  inSecBufferDesc.pBuffers = inSecBuffers;

  inSecBuffers[0].cbBuffer = inTokenBuffer.Length();
  inSecBuffers[0].BufferType = SECBUFFER_TOKEN;
  inSecBuffers[0].pvBuffer = inTokenBuffer.Data();

  if (channelBindingsLength > 0) {
    inSecBufferDesc.cBuffers++;
    inSecBuffers[1].cbBuffer = channelBindingsLength;
    inSecBuffers[1].BufferType = SECBUFFER_CHANNEL_BINDINGS;
    inSecBuffers[1].pvBuffer = &channelBindings;
  }

  auto result = Secur32Facade::InitializeSecurityContext(&inSecBufferDesc, &outSecBufferDesc, targetHostnameSpn, &credHandle, &ctxHandle, flags, &lifeTime, env);
  if (env->IsExceptionPending()) {
    Cleanup(env);
    return false;
  }
  if (result != SEC_I_CONTINUE_NEEDED && result != SEC_E_OK) {
    ExceptionHandler::CreateAndThrow(*env, "Init security context did not return SEC_I_CONTINUE_NEEDED or SEC_E_OK. Result: ", result);
    Cleanup(env);
    return false;
  }

  outTokenLength = outSecBuff.cbBuffer;
  return true;
}

Napi::Buffer<unsigned char> AuthContext::OutToken(Napi::Env* env) {
  if (outToken) {
    return Napi::Buffer<unsigned char>::Copy(*env, outToken, outTokenLength);
  } else {
    return Napi::Buffer<unsigned char>::Buffer();
  }
}
