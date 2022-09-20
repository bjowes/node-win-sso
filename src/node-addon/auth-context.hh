#ifndef AUTH_CONTEXT_HH
#define AUTH_CONTEXT_HH

#define SECURITY_WIN32

#include <napi.h>

#include <windows.h>
#include <sspi.h>
#include <Secext.h>
#include <Security.h>

class AuthContext {
  public:
  char packageName[128];
  std::string targetHostname;
  char* targetHostnameSpn;
  CredHandle credHandle;
  SECURITY_INTEGER lifeTime;
  struct _SecHandle ctxHandle;
  unsigned long flags;
  unsigned long maxTokenLength;
  unsigned char* outToken;
  unsigned long outTokenLength;

  private:
  struct SecChannelBindingsCombined {
    struct _SEC_CHANNEL_BINDINGS secChannelBindings;
    unsigned char applicationData[128];
  };
  struct SecChannelBindingsCombined channelBindings;
  unsigned long channelBindingsLength;

  bool credHandleAllocated;
  bool ctxHandleAllocated;

  public:
  AuthContext();
  virtual ~AuthContext();
  void Cleanup(Napi::Env* env);

  bool Init(std::string* packageName, std::string* targetHost, Napi::Buffer<unsigned char>& applicationDataBuffer, unsigned long flags, Napi::Env* env);
  bool InitContext(Napi::Env* env);
  bool HandleResponse(Napi::Buffer<unsigned char>& inTokenBuffer, Napi::Env* env);

  Napi::Buffer<unsigned char> OutToken(Napi::Env* env);

  private:
  void SetupChannelBindings(Napi::Buffer<unsigned char>& applicationDataBuffer);
};

#endif
