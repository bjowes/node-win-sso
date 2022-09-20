#ifndef SECUR32_FACADE_HH
#define SECUR32_FACADE_HH

#define SECURITY_WIN32

#include <napi.h>

#include <windows.h>
#include <sspi.h>
#include <map>

class AuthContext;

class Secur32Facade {
  private:
  static std::map<unsigned long, std::shared_ptr<AuthContext>> acMap;
  static unsigned long acKey;

  public:
  /**
   * Returns the full username (domain\username) of the user running the process
   */
  static Napi::String GetLogonUserName(const Napi::CallbackInfo& info);

  static Napi::Number Secur32Facade::CreateAuthContext(const Napi::CallbackInfo& info);
  static Napi::Number Secur32Facade::FreeAuthContext(const Napi::CallbackInfo& info);
  /**
   * Creates a NTLM type 1 authentication token
   */
  static Napi::Buffer<unsigned char> CreateAuthRequest(const Napi::CallbackInfo& info);

  /**
   * Creates a NTLM type 3 authentication token
   */
  static Napi::Buffer<unsigned char> CreateAuthResponse(const Napi::CallbackInfo& info);

  static unsigned int GetMaxTokenLength(char* packageName, Napi::Env* env);
  static void AcquireCredentialsHandle(char* packageName, CredHandle* credHandle, SECURITY_INTEGER* lifeTime, Napi::Env* env);
  static void FreeCredentialsHandle(CredHandle* credHandle, Napi::Env* env);
  static int InitializeSecurityContext(
    SecBufferDesc* inSecBufferDesc,
    SecBufferDesc* outSecBufferDesc,
    char* targetHost,
    CredHandle* credHandle,
    struct _SecHandle* ctxHandle,
    unsigned long flags,
    SECURITY_INTEGER* lifeTime,
    Napi::Env* env);
  static void FreeContextHandle(struct _SecHandle* ctxHandle, Napi::Env* env);
  static Napi::Object Init(Napi::Env env, Napi::Object exports);

  private:
  static unsigned long GetDefaultFlags(std::string securityPackageName);
};

#endif
