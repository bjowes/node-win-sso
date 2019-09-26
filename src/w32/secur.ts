
// Minimal wrappers for Secur32.dll to support NTLM authentication

'use strict';

import * as ffi from 'ffi-napi';
import { Types } from './types';

export const SecurConst = {
  EXTENDED_NAME_FORMAT_NameSamCompatible: 2,

  SECPKG_CRED_INBOUND: 1,
  SECPKG_CRED_OUTBOUND: 2,

  SEC_WINNT_AUTH_IDENTITY_ANSI: 1,

  ISC_REQ_CONFIDENTIALITY: 0x10,
  SECURITY_NATIVE_DREP: 0x10,

  SECBUFFER_TOKEN: 2,
  SECBUFFER_CHANNEL_BINDINGS: 14,

  SECPKG_ATTR_ENDPOINT_BINDINGS: 26
};

export enum InitializeSecurityContextA_Result {
  OK = 0,
  CONTINUE_NEEDED = 0x00090312,
  COMPLETE_NEEDED = 0x00090313, // TODO: Might need this for Negotiate later
  COMPLETE_AND_CONTINUE = 0x00090314
}

// Javascript bindings for native Win32 registry APIs
export const Secur = ffi.Library('Secur32', {
    /*
    BOOLEAN SEC_ENTRY GetUserNameExA(
        EXTENDED_NAME_FORMAT NameFormat,
        LPSTR                lpNameBuffer,
        PULONG               nSize
    );
    */
    GetUserNameExA: [Types.BYTE, [Types.EXTENDED_NAME_FORMAT, Types.LPSTR, Types.PULONG]],
    /*
    SECURITY_STATUS SEC_ENTRY QuerySecurityPackageInfoA(
      LPSTR        pszPackageName,
      PSecPkgInfoA *ppPackageInfo
    );
    */
    QuerySecurityPackageInfoA: [Types.LONG, [Types.LPSTR, Types.PPSEC_PKG_INFO]],
    /*
    SECURITY_STATUS SEC_ENTRY FreeContextBuffer(
      PVOID pvContextBuffer
    );
    */
    FreeContextBuffer: [Types.LONG, [Types.PSEC_PKG_INFO]],
    /*
    SECURITY_STATUS SEC_ENTRY AcquireCredentialsHandleA(
        LPSTR          pszPrincipal,
        LPSTR          pszPackage,
        unsigned long  fCredentialUse,
        void           *pvLogonId,
        void           *pAuthData,
        SEC_GET_KEY_FN pGetKeyFn,
        void           *pvGetKeyArgument,
        PCredHandle    phCredential,
        PTimeStamp     ptsExpiry
    );
    */
    AcquireCredentialsHandleA: [Types.LONG, [Types.LPSTR, Types.LPSTR, Types.ULONG, Types.PVOID, Types.PSEC_WINNT_AUTH_IDENTITY, Types.PVOID, Types.PVOID, Types.PCRED_HANDLE, Types.PTIMESTAMP]],
    /*
    KSECDDDECLSPEC SECURITY_STATUS SEC_ENTRY FreeCredentialsHandle(
      PCredHandle phCredential
    );
    */
    FreeCredentialsHandle: [Types.LONG, [Types.PCRED_HANDLE]],
    /*
    SECURITY_STATUS SEC_ENTRY InitializeSecurityContextA(
      PCredHandle    phCredential,
      PCtxtHandle    phContext,
      SEC_CHAR       *pszTargetName,
      unsigned long  fContextReq,
      unsigned long  Reserved1,
      unsigned long  TargetDataRep,
      PSecBufferDesc pInput,
      unsigned long  Reserved2,
      PCtxtHandle    phNewContext,
      PSecBufferDesc pOutput,
      unsigned long  *pfContextAttr,
      PTimeStamp     ptsExpiry
    );
    */
    InitializeSecurityContextA: [Types.LONG, [Types.PCRED_HANDLE, Types.PSEC_HANDLE, Types.LPSTR, Types.ULONG, Types.ULONG, Types.ULONG, Types.PSEC_BUFFER_DESC, Types.ULONG, Types.PSEC_HANDLE, Types.PSEC_BUFFER_DESC, Types.PULONG, Types.PTIMESTAMP]],
    /*
    KSECDDDECLSPEC SECURITY_STATUS SEC_ENTRY AcceptSecurityContext(
      PCredHandle    phCredential,
      PCtxtHandle    phContext,
      PSecBufferDesc pInput,
      unsigned long  fContextReq,
      unsigned long  TargetDataRep,
      PCtxtHandle    phNewContext,
      PSecBufferDesc pOutput,
      unsigned long  *pfContextAttr,
      PTimeStamp     ptsExpiry
    );
    */
    AcceptSecurityContext: [Types.LONG, [Types.PCRED_HANDLE, Types.PSEC_HANDLE, Types.PVOID, Types.ULONG, Types.ULONG, Types.PSEC_HANDLE, Types.PVOID, Types.PULONG, Types.PTIMESTAMP]],
    /*
    KSECDDDECLSPEC SECURITY_STATUS SEC_ENTRY DeleteSecurityContext(
      PCtxtHandle phContext
    );
    */
    DeleteSecurityContext: [Types.LONG, [Types.PSEC_HANDLE]],
    /* SECURITY_STATUS SEC_ENTRY QueryContextAttributesA(
      PCtxtHandle phContext,
      ULONG ulAttribute,
      void* pBuffer
    );
    */
    QueryContextAttributesA: [Types.LONG, [Types.PSEC_HANDLE, Types.ULONG, Types.PVOID]]
});
