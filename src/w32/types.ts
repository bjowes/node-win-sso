import * as ref from 'ref';
import { TimeStamp, SecWinNtAuthIdentity, CredHandle, SecPkgInfoA, SecHandle, SecBufferDesc } from './structs';

export const Types = {
    REGSAM: ref.types.ulong,
    DWORD: ref.types.uint32,
    LPDWORD: ref.refType(ref.types.uint32),
    LONG: ref.types.long,
    ULONG: ref.types.ulong,
    PULONG: ref.refType(ref.types.ulong),
    HWND: ref.refType(ref.types.void),
    BYTE: ref.types.uint8,
    LPBYTE: ref.refType(ref.types.uint8),
    HKEY: ref.refType(ref.types.void),
    PHKEY: ref.refType(ref.refType(ref.types.void)),
    PVOID: ref.refType('pointer'),
    HANDLE: ref.refType(ref.types.void),
    HINSTANCE: ref.refType(ref.types.void),
    LPCTSTR: ref.refType(ref.types.CString),
    STRING: ref.types.CString,
    LPSTR: ref.types.CString,
    INT: ref.types.int,
    LPVOID: ref.refType(ref.types.void),
    EXTENDED_NAME_FORMAT: ref.types.int,

    PTIMESTAMP: ref.refType(TimeStamp),
    PSEC_WINNT_AUTH_IDENTITY: ref.refType(SecWinNtAuthIdentity),
    PCRED_HANDLE: ref.refType(CredHandle),
    PSEC_PKG_INFO: ref.refType(SecPkgInfoA),
    PPSEC_PKG_INFO: ref.refType(ref.refType(SecPkgInfoA)),
    PSEC_HANDLE: ref.refType(SecHandle),
    PSEC_BUFFER_DESC: ref.refType(SecBufferDesc)

};
