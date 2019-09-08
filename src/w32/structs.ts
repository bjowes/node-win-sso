import * as ref from 'ref';
const RefStruct = require('ref-struct');

/* TIMESTAMP is SECURITY_INTEGER
typedef struct _SECURITY_INTEGER {
    unsigned long LowPart;
    long          HighPart;
  } SECURITY_INTEGER;
*/
export let TimeStamp = RefStruct({
    'LowPart': 'ulong',
    'HighPart': 'long'
  });

export let SecPkgInfoA = RefStruct({
  'fCapabilities': 'ulong',
  'wVersion': 'ushort',
  'wRPCID': 'ushort',
  'cbMaxToken': 'ulong',
  'Name': 'string',
  'Comment': 'string'
});

/*
typedef struct _CREDSSP_CRED {
  CREDSPP_SUBMIT_TYPE Type;
  PVOID               pSchannelCred;
  PVOID               pSpnegoCred;
} CREDSSP_CRED, *PCREDSSP_CRED;

typedef struct _SEC_WINNT_AUTH_IDENTITY {
  unsigned short __RPC_FAR *User;
  unsigned long            UserLength;
  unsigned short __RPC_FAR *Domain;
  unsigned long            DomainLength;
  unsigned short __RPC_FAR *Password;
  unsigned long            PasswordLength;
  unsigned long            Flags;
} SEC_WINNT_AUTH_IDENTITY, *PSEC_WINNT_AUTH_IDENTITY;
*/

export let SecWinNtAuthIdentity = RefStruct({
    'User': 'string',
    'UserLength': 'ulong',
    'Domain': 'string', //ref.refType('string'),
    'DomainLength': 'ulong',
    'Password': 'string', //ref.refType('string'),
    'PasswordLength': 'ulong',
    'Flags': 'ulong'
});

export let CredHandle = RefStruct({
    'dwLower': 'ulong',
    'dwUpper': 'ulong'
});

export let SecHandle = RefStruct({
  'dwLower': 'ulong',
  'dwUpper': 'ulong'
});

export let SecBuffer = RefStruct({
  'cbBuffer': 'ulong',
  'BufferType': 'ulong',
  'pvBuffer': 'pointer'
});

export let SecBufferDesc = RefStruct({
  'ulVersion': 'ulong',
  'cBuffers': 'ulong',
  'pBuffers': ref.refType(SecBuffer)
});

