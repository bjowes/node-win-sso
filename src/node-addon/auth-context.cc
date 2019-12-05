#import "auth-context.hh"

namespace WinSso {
  AuthContext::AuthContext() {
    credHandle = {};
    lifeTime = {};
    ctxHandle = {};
    ctxAttributes = 0;
    maxTokenLength = 0;
    outToken = 0;
    outTokenLength = 0;
    credHandleAllocated = false;
    ctxHandleAllocated = false;
    channelBindings = {};
    channelBindingsLength = 0;
  };

  AuthContext::~AuthContext() {
    Cleanup();
  }

  void AuthContext::Cleanup() {
    if (credHandleAllocated) {
      FreeCredentialsHandle(&credHandle, env);
      credHandleAllocated = false;
    }
    if (ctxHandleAllocated) {
      FreeContextHandle(&ctxHandle, env);
      ctxHandleAllocated = false;
    }
    if (outToken) {
      delete outToken;
      outToken = 0;
    }
  }

  bool AuthContext::Init(std::string* securityPackageName, std::string* targetHost, Napi::Buffer<unsigned char>& applicationDataBuffer, Napi::Env& env) {
    packageName = *securityPackageName;
    targetHostname = *targetHost;
    maxTokenLength = GetMaxTokenLength(packageName.c_str(), env);
    SetupChannelBindings(applicationDataBuffer);
    AcquireCredentialsHandle(packageName.c_str(), &credHandle, &lifeTime, env);
    if (env.IsExceptionPending()) {
      Cleanup();
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

  bool AuthContext::InitContext(Napi::Env& env) {
    SecBufferDesc outSecBufferDesc;
    SecBuffer outSecBuff;
    SecBufferDesc inSecBufferDesc;
    SecBuffer inSecBuffer;
    outToken = new unsigned char[maxTokenLength];

    outSecBufferDesc.ulVersion = 0;
    outSecBufferDesc.cBuffers = 1;
    outSecBufferDesc.pBuffers = &outSecBuff;

    outSecBuff.cbBuffer = maxTokenLength;
    outSecBuff.BufferType = SECBUFFER_TOKEN;
    outSecBuff.pvBuffer = outToken;

    inSecBufferDesc.ulVersion = 0;
    inSecBufferDesc.cBuffers = 0;

    if (channelBindingsLength > 0) {
      inSecBufferDesc.cBuffers++;
      inSecBufferDesc.pBuffers = &inSecBuffer;
      inSecBuffer.cbBuffer = channelBindingsLength;
      inSecBuffer.BufferType = SECBUFFER_CHANNEL_BINDINGS;
      inSecBuffer.pvBuffer = &channelBindings;
    }

    int result = InitializeSecurityContext(
      inSecBufferDesc.cBuffers ? &inSecBufferDesc : NULL, &outSecBufferDesc, &targetHostname, &credHandle, &ctxHandle, &ctxAttributes, &lifeTime, env);
    if (result != SEC_I_CONTINUE_NEEDED && result != SEC_E_OK) {
      std::string message = "Init security context did not return SEC_I_CONTINUE_NEEDED or SEC_E_OK. Result: ";
      message += std::to_string(result);
      Napi::Error::New(env, message).ThrowAsJavaScriptException();
      Cleanup();
      return false;
    }
    ctxHandleAllocated = true;
    outTokenLength = outSecBuff.cbBuffer;
    return true;
  }

  bool AuthContext::HandleResponse(
    Napi::Buffer<unsigned char>& inTokenBuffer,
    Napi::Buffer<unsigned char>& applicationDataBuffer,
    Napi::Env& env) {
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
      inSecBuffer.cbBuffer = channelBindingsLength;
      inSecBuffer.BufferType = SECBUFFER_CHANNEL_BINDINGS;
      inSecBuffer.pvBuffer = &channelBindings;
    }

    result = InitializeSecurityContext(&inSecBufferDesc, &outSecBufferDesc, &targetHostname, &credHandle, &ctxHandle, &ctxAttributes, &lifeTime, env);
    if (result != SEC_I_CONTINUE_NEEDED && result != SEC_E_OK) {
      std::string message = "Init security context did not return SEC_I_CONTINUE_NEEDED or SEC_E_OK. Result: ";
      message += std::to_string(result);
      Napi::Error::New(env, message).ThrowAsJavaScriptException();
      Cleanup();
      return false;
    }
    if (env.IsExceptionPending()) {
      Cleanup();
      return false;
    }

    outTokenLength = outSecBuff.cbBuffer;
    return true;
  }

  Napi::Buffer<unsigned char> AuthContext::OutToken(Napi::Env& env) {
    if (outToken) {
      return Napi::Buffer<unsigned char>::Copy(env, outToken, outTokenLength);
    } else {
      return Napi::Buffer<unsigned char>::Buffer();
    }
  }
}
