#ifndef WINSSO_SECUR32_HH
#define WINSSO_SECUR32_HH

#define SECURITY_WIN32

#include <napi.h>

#include <windows.h>
#include <sspi.h>
#include <Secext.h>
#include <Security.h>

namespace WinSso {

unsigned int GetMaxTokenLength(char* packageName, Napi::Env* env);

void AcquireCredentialsHandle(char* packageName, CredHandle* credHandle, SECURITY_INTEGER* lifeTime, Napi::Env* env);
void FreeCredentialsHandle(CredHandle* credHandle, Napi::Env* env);

int InitializeSecurityContext(
    SecBufferDesc* inSecBufferDesc,
    SecBufferDesc* outSecBufferDesc,
    std::string* targetHost,
    CredHandle* credHandle,
    struct _SecHandle* ctxHandle,
    unsigned long* ctxAttributes,
    SECURITY_INTEGER* lifeTime,
    Napi::Env* env);
void FreeContextHandle(struct _SecHandle* ctxHandle, Napi::Env* env);

}

#endif
