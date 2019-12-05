#include <string.h>

#include "secur32.hh"
#include "auth-context.hh"

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

  unsigned int GetMaxTokenLength(char* packageName, Napi::Env& env) {
    static unsigned int _maxTokenLength = 0;

    if (_maxTokenLength != 0) {
      return _maxTokenLength;
    }

    PSecPkgInfoA	  	pkgInfo;
    int result = QuerySecurityPackageInfoA(packageName, &pkgInfo);
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

  void AcquireCredentialsHandle(char* packageName, CredHandle* credHandle, SECURITY_INTEGER* lifeTime, Napi::Env& env) {
    int result = AcquireCredentialsHandleA(NULL, packageName, SECPKG_CRED_OUTBOUND, NULL, NULL, NULL, NULL, credHandle, lifeTime);
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
    std::string* targetHost,
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
      char* spn = NULL;
      if (targetHost != NULL) {
        std::string spnPrep = "HTTP/" + *targetHost;
        spn = (char*)spnPrep.c_str();
      }
      result = InitializeSecurityContextA(
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

  static std::map<unsigned long, std::shared_ptr<AuthContext>> acMap = std::map<unsigned long, std::shared_ptr<AuthContext>>();
  static unsigned long acKey = 0;

  /**
   * Creates a ...
   */
  Napi::Number CreateAuthContext(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 3) {
      Napi::TypeError::New(env, "Wrong number of arguments")
          .ThrowAsJavaScriptException();
      return Napi::Number::New(env, 0);
    }

    if (!info[0].IsString() || !info[1].IsString() || !info[2].IsBuffer()) {
      Napi::TypeError::New(env, "Wrong arguments").ThrowAsJavaScriptException();
      return Napi::Number::New(env, 0);
    }
    auto securityPackageName = info[0].ToString();
    auto targetHost = info[1].ToString();
    auto applicationDataBuffer = info[2].As<Napi::Buffer<unsigned char>>();

    auto ac = std::make_shared<AuthContext>();
    ac.Init(securityPackageName, targetHost, applicationDataBuffer, env);
    acKey++;
    acMap[acKey] = ac;
    return Napi::Number::New(acKey);
  }

  Napi::Number FreeAuthContext(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 1) {
      Napi::TypeError::New(env, "Wrong number of arguments")
          .ThrowAsJavaScriptException();
      return Napi::Number::New(env, 0);
    }

    if (!info[0].IsNumber()) {
      Napi::TypeError::New(env, "Wrong arguments").ThrowAsJavaScriptException();
      return Napi::Number::New(env, 0);
    }

    auto acId = info[0].ToNumber();
    auto erased = acMap.erase(acId);
    return Napi::Number::New(erased);
  }

  /**
   * Creates a NTLM type 1 authentication token
   */
  Napi::Buffer<unsigned char> CreateAuthRequest(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 1) {
      Napi::TypeError::New(env, "Wrong number of arguments")
          .ThrowAsJavaScriptException();
      return Napi::Buffer<unsigned char>::Buffer();
    }

    if (!info[0].IsNumber()) {
      Napi::TypeError::New(env, "Wrong arguments").ThrowAsJavaScriptException();
      return Napi::Buffer<unsigned char>::Buffer();
    }

    auto acKey = info[0].ToNumber().Uint32Value();

    if (acMap.find(acKey) == mapOfWords.end()) {
      Napi::TypeError::New(env, "AuthContext not found").ThrowAsJavaScriptException();
      return Napi::Buffer<unsigned char>::Buffer();
    }

    auto ac = acMap[acKey]
    ac->InitContext(env);
    return ac->OutToken();
  }

  /**
   * Creates a NTLM type 3 authentication token
   */
  Napi::Buffer<unsigned char> CreateAuthResponse(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 2) {
      Napi::TypeError::New(env, "Wrong number of arguments")
          .ThrowAsJavaScriptException();
      return Napi::Buffer<unsigned char>::Buffer();
    }

    if (!info[0].IsNumber() && !info[1].IsBuffer()) {
      Napi::TypeError::New(env, "Wrong arguments").ThrowAsJavaScriptException();
      return Napi::Buffer<unsigned char>::Buffer();
    }

    auto acKey = info[0].ToNumber().Uint32Value();
    if (acMap.find(acKey) == mapOfWords.end()) {
      Napi::TypeError::New(env, "AuthContext not found").ThrowAsJavaScriptException();
      return Napi::Buffer<unsigned char>::Buffer();
    }

    auto inTokenBuffer = info[1].As<Napi::Buffer<unsigned char>>();
    auto ac = acMap[acKey]
    ac->HandleResponse(inTokenBuffer, env);
    return ac->OutToken();
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

