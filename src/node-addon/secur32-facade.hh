#define SECURITY_WIN32

#include <napi.h>

#include <windows.h>
#include <sspi.h>

class Secur32Facade {
  public:
  /**
   * Returns the full username (domain\username) of the user running the process
   */
  static Napi::String GetLogonUserName(const Napi::CallbackInfo& info);

  /**
   * Creates a NTLM type 1 authentication token
   */
  static Napi::Buffer<unsigned char> CreateAuthRequest(const Napi::CallbackInfo& info);

  /**
   * Creates a NTLM type 3 authentication token
   */
  static Napi::Buffer<unsigned char> CreateAuthResponse(const Napi::CallbackInfo& info);

  private:
  static std::string _packageName;

  static unsigned int GetMaxTokenLength(Napi::Env& env);
  static void AcquireCredentialsHandle(CredHandle* credHandle, SECURITY_INTEGER* lifeTime, Napi::Env& env);
  static void FreeCredentialsHandle(CredHandle* credHandle, Napi::Env& env);
  static int InitializeSecurityContext(
    SecBufferDesc* inSecBufferDesc,
    SecBufferDesc* outSecBufferDesc,
    std::string* targetHost,
    CredHandle* credHandle,
    struct _SecHandle* ctxHandle,
    unsigned long* ctxAttributes,
    SECURITY_INTEGER* lifeTime,
    Napi::Env& env);
  static void FreeContextHandle(struct _SecHandle* ctxHandle, Napi::Env& env);
  static Napi::Object Init(Napi::Env env, Napi::Object exports);
};
