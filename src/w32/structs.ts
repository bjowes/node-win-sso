import * as ref from 'ref-napi';
const RefStruct = require('ref-struct-di')(ref);

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

// Dummy structure to simulate an array of SecBuffer
export let SecBufferArray = RefStruct({
  'cbBuffer0': 'ulong',
  'BufferType0': 'ulong',
  'pvBuffer0': 'pointer',
  'cbBuffer1': 'ulong',
  'BufferType1': 'ulong',
  'pvBuffer1': 'pointer',
  'cbBuffer2': 'ulong',
  'BufferType2': 'ulong',
  'pvBuffer2': 'pointer',
  'cbBuffer3': 'ulong',
  'BufferType3': 'ulong',
  'pvBuffer3': 'pointer'
});

export let SecBufferDesc = RefStruct({
  'ulVersion': 'ulong',
  'cBuffers': 'ulong',
  'pBuffers': ref.refType(SecBufferArray)
});
//SecBufferDesc.defineProperty('pBuffers', SecBufferArray);

/* typedef struct _SEC_CHANNEL_BINDINGS {
  unsigned long dwInitiatorAddrType;
  unsigned long cbInitiatorLength;
  unsigned long dwInitiatorOffset;
  unsigned long dwAcceptorAddrType;
  unsigned long cbAcceptorLength;
  unsigned long dwAcceptorOffset;
  unsigned long cbApplicationDataLength;
  unsigned long dwApplicationDataOffset;
} SEC_CHANNEL_BINDINGS, *PSEC_CHANNEL_BINDINGS; */

export let SecChannelBindings = RefStruct({
  'dwInitiatorAddrType': 'ulong',
  'cbInitiatorLength': 'ulong',
  'dwInitiatorOffset': 'ulong',
  'dwAcceptorAddrType': 'ulong',
  'cbAcceptorLength': 'ulong',
  'dwAcceptorOffset': 'ulong',
  'cbApplicationDataLength': 'ulong',
  'dwApplicationDataOffset': 'ulong',
  /* These fields are just dummy fields to allocate space for a string
  'applicationData0': 'ulong',
  'applicationData1': 'ulong',
  'applicationData2': 'ulong',
  'applicationData3': 'ulong',
  'applicationData4': 'ulong',
  'applicationData5': 'ulong',
  'applicationData6': 'ulong',
  'applicationData7': 'ulong',
  'applicationData8': 'ulong',
  'applicationData9': 'ulong',
  */
});

/* typedef struct _SecPkgContext_Bindings {
  unsigned long        BindingsLength;
  SEC_CHANNEL_BINDINGS *Bindings;
} SecPkgContext_Bindings, *PSecPkgContext_Bindings; */

export let SecPkgContext_Bindings = RefStruct({
  'bindingsLength': 'ulong',
  'bindings': ref.refType(SecChannelBindings)
});
