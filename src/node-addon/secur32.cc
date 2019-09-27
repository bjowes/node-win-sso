#define SECURITY_WIN32

#include <napi.h>

#include <windows.h>
#include <sspi.h>
#include <Secext.h>
#include <Security.h>
#include <string.h>

namespace WinSso {
  static char* _packageName = "NTLM";

  Napi::String GetUserName(const Napi::CallbackInfo& info) {
    static char _userName[256] = "";
    Napi::Env env = info.Env();
    if (_userName[0]) {
      return Napi::String::New(env, _userName);
    }

    unsigned long userNameLength = 256;
    int result = GetUserNameExA(NameSamCompatible, _userName, &userNameLength);
    if (result < 0) {
      Napi::Error::New(env, "Could not get user name of logged in user").ThrowAsJavaScriptException();
      return Napi::String::New(env, "");
    }
    _userName[userNameLength] = '\0';
    auto name = Napi::String::New(env, _userName);

    return name;
  }

  unsigned int GetMaxTokenLength(Napi::Env& env) {
    static unsigned int _maxTokenLength = 0;

    if (_maxTokenLength != 0) {
      return _maxTokenLength;
    }

    PSecPkgInfoA	  	pkgInfo;
    int result = QuerySecurityPackageInfoA(_packageName, &pkgInfo);
    if (result != 0) {
      Napi::Error::New(env, "Could not get SecurityPackageInfo").ThrowAsJavaScriptException();
      return 0;
    }
    _maxTokenLength = pkgInfo->cbMaxToken;
    result = FreeContextBuffer(pkgInfo);
    if (result != 0) {
      Napi::Error::New(env, "Could not free context buffer").ThrowAsJavaScriptException();
      return 0;
    }
    return _maxTokenLength;
  }

  void AcquireCredentialsHandle(CredHandle* credHandle, SECURITY_INTEGER* lifeTime, Napi::Env& env) {
    int result = AcquireCredentialsHandleA(NULL, _packageName, SECPKG_CRED_OUTBOUND, NULL, NULL, NULL, NULL, credHandle, lifeTime);
    if (result < 0) {
      std::string message = "Could not acquire credentials handle. Result: ";
      message += std::to_string(result);
      Napi::Error::New(env, message).ThrowAsJavaScriptException();
    }
  }

  void FreeCredentialsHandle(CredHandle* credHandle, Napi::Env& env) {
    int result = FreeCredentialsHandle(credHandle);
    if (result != 0) {
      std::string message = "Could not free credentials handle. Result: ";
      message += std::to_string(result);
      Napi::Error::New(env, message).ThrowAsJavaScriptException();
    }
  }

  int InitializeSecurityContext(
    SecBufferDesc* inSecBufferDesc,
    SecBufferDesc* outSecBufferDesc,
    std::string targetHost,
    CredHandle* credHandle,
    struct _SecHandle* ctxHandle,
    unsigned long* ctxAttributes,
    SECURITY_INTEGER* lifeTime,
    Napi::Env& env)
  {
    int result = 0;
    if (inSecBufferDesc == NULL) {
      result = InitializeSecurityContextA(
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
      std::string spn = "HTTP/" + targetHost;
      result = InitializeSecurityContextA(
        credHandle,
        ctxHandle,
        (char*)(spn.c_str()),
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
      std::string message = "Could not init security context. Result: ";
      message += std::to_string(result);
      Napi::Error::New(env, message).ThrowAsJavaScriptException();
    }
    return result;
  }

  void FreeContextHandle(struct _SecHandle* ctxHandle, Napi::Env& env) {
    int result = DeleteSecurityContext(ctxHandle);
    if (result != 0) {
      std::string message = "Could not delete security context. Result: ";
      message += std::to_string(result);
      Napi::Error::New(env, message).ThrowAsJavaScriptException();
    }
  }

  /**
   * Creates a NTLM type 1 authentication token
   */
  Napi::Buffer<unsigned char> CreateAuthRequest(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    SecBufferDesc outSecBufferDesc;
    SecBuffer outSecBuff;
    CredHandle credHandle;
    SECURITY_INTEGER lifeTime;
    struct _SecHandle ctxHandle;
    unsigned long ctxAttributes = 0;
    unsigned long maxTokenLength = GetMaxTokenLength(env);
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

    // Here we use _packageName as target SPN since the target SPN is not used in this call
    int result = InitializeSecurityContext(NULL, &outSecBufferDesc, _packageName, &credHandle, &ctxHandle, &ctxAttributes, &lifeTime, env);
    if (result != SEC_I_CONTINUE_NEEDED) {
      std::string message = "Init security context did not return SEC_I_CONTINUE_NEEDED. Result: ";
      message += std::to_string(result);
      Napi::Error::New(env, message).ThrowAsJavaScriptException();
      FreeCredentialsHandle(&credHandle, env);
      return Napi::Buffer<unsigned char>::Buffer();
    }

    FreeContextHandle(&ctxHandle, env);
    FreeCredentialsHandle(&credHandle, env);

    auto outTokenBuffer = Napi::Buffer<unsigned char>::Copy(env, outToken, outSecBuff.cbBuffer);
    delete outToken;
    return outTokenBuffer;
  }

  /**
   * Creates a NTLM type 3 authentication token
   */
  Napi::Buffer<unsigned char> CreateAuthResponse(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 3) {
      Napi::TypeError::New(env, "Wrong number of arguments")
          .ThrowAsJavaScriptException();
      return Napi::Buffer<unsigned char>::Buffer();
    }

    if (!info[0].IsBuffer() || !info[1].IsString() || !info[2].IsBuffer()) {
      Napi::TypeError::New(env, "Wrong arguments").ThrowAsJavaScriptException();
      return Napi::Buffer<unsigned char>::Buffer();
    }

    SecBufferDesc outSecBufferDesc;
    SecBuffer outSecBuff;
    CredHandle credHandle;
    SECURITY_INTEGER lifeTime;
    struct _SecHandle ctxHandle;
    unsigned long ctxAttributes = 0;
    unsigned long maxTokenLength = GetMaxTokenLength(env);
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

    int result = InitializeSecurityContext(NULL, &outSecBufferDesc, info[1].ToString(), &credHandle, &ctxHandle, &ctxAttributes, &lifeTime, env);
    if (result != SEC_I_CONTINUE_NEEDED) {
      std::string message = "Init security context did not return SEC_I_CONTINUE_NEEDED. Result: ";
      message += std::to_string(result);
      Napi::Error::New(env, message).ThrowAsJavaScriptException();
      FreeCredentialsHandle(&credHandle, env);
      return Napi::Buffer<unsigned char>::Buffer();
    }
    if (env.IsExceptionPending()) {
      FreeCredentialsHandle(&credHandle, env);
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

    result = InitializeSecurityContext(&inSecBufferDesc, &outSecBufferDesc, info[1].ToString(), &credHandle, &ctxHandle, &ctxAttributes, &lifeTime, env);
    if (result != SEC_E_OK) {
      std::string message = "Init security context did not return SEC_E_OK. Result: ";
      message += std::to_string(result);
      Napi::Error::New(env, message).ThrowAsJavaScriptException();
      FreeContextHandle(&ctxHandle, env);
      FreeCredentialsHandle(&credHandle, env);
      return Napi::Buffer<unsigned char>::Buffer();
    }
    if (env.IsExceptionPending()) {
      FreeContextHandle(&ctxHandle, env);
      FreeCredentialsHandle(&credHandle, env);
      return Napi::Buffer<unsigned char>::Buffer();
    }

    FreeContextHandle(&ctxHandle, env);
    FreeCredentialsHandle(&credHandle, env);

    auto outTokenBuffer = Napi::Buffer<unsigned char>::Copy(env, outToken, outSecBuff.cbBuffer);
    delete outToken;
    return outTokenBuffer;
  }

  Napi::Object Init(Napi::Env env, Napi::Object exports) {
    exports.Set(Napi::String::New(env, "getUserName"),
                Napi::Function::New(env, WinSso::GetUserName));
    exports.Set(Napi::String::New(env, "createAuthRequest"),
                Napi::Function::New(env, WinSso::CreateAuthRequest));
    exports.Set(Napi::String::New(env, "createAuthResponse"),
                Napi::Function::New(env, WinSso::CreateAuthResponse));
    return exports;
  }

  NODE_API_MODULE(WinSso, Init)
}

