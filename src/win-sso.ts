import * as ref from 'ref';

import { Secur, SecurConst, InitializeSecurityContextA_Result } from './w32/secur';
import { Types } from './w32/types';
import { TimeStamp, SecWinNtAuthIdentity, CredHandle, SecHandle, SecBufferDesc, SecBuffer } from './w32/structs';
import { debug } from './utils/debug.logger';

interface UserInfo {
    username: string;
    domain: string;
}

/**
 * Creates authentication tokens for NTLM handshake using the executing users credentials.
 */
export class WinSso {
  private readonly securityPackageName = ref.allocCString("NTLM", "ascii");
  private maxTokenLength: number;
  private userInfo: UserInfo;
  private credHandle: any;
  private lifeTime: any;
  private ctxHandle: any;
  private outToken: Buffer;
  private outSecBufferDesc: any;
  private ctxAttributesRef: any;

  constructor() {
    this.maxTokenLength = this.getMaxTokenLength();
    this.userInfo = this.getUserInfo();
    this.credHandle = new CredHandle();
    this.lifeTime = new TimeStamp();
    this.ctxHandle = new SecHandle();
    this.outToken = Buffer.alloc(this.maxTokenLength);
    this.outSecBufferDesc =
        this.createSecBufferDesc(this.outToken, this.maxTokenLength);
    this.ctxAttributesRef = ref.alloc(Types.ULONG, 0);
  }

  private createSecBufferDesc(buf: Buffer, length: number): any {
    let secBuffer = new SecBuffer({
      cbBuffer: length,
      BufferType: SecurConst.SECBUFFER_TOKEN,
      pvBuffer: buf
    });
    let secBufferDesc = new SecBufferDesc({
      ulVersion: 0,
      cBuffers: 1,
      pBuffers: secBuffer.ref()
    });
    return secBufferDesc;
  }

  private getSecBufferLength(secBufferDesc: any): number {
      return ref.deref(secBufferDesc.pBuffers).cbBuffer;
  }

  private getMaxTokenLength(): number {
    let secPkgInfoRefRef = ref.alloc(Types.PSEC_PKG_INFO);
    let result = Secur.QuerySecurityPackageInfoA(
      this.securityPackageName,
      secPkgInfoRefRef
    );
    if (result !== 0) {
      throw new Error(
        "Could not retrieve max token length. Result: " + result.toString(16)
      );
    }
    let secPkgInfoRef = ref.deref(secPkgInfoRefRef);
    let secPkgInfo = ref.deref(secPkgInfoRef);
    debug("Retrieved SecurityPackageInfo:", secPkgInfo);
    let maxTokenLength = secPkgInfo.cbMaxToken;
    result = Secur.FreeContextBuffer(secPkgInfoRef);
    if (result !== 0) {
      throw new Error(
        "Could not free context buffer. Result: " + result.toString(16)
      );
    }
    return maxTokenLength;
  }

  private getUserInfo(): UserInfo {
    let usernameBufferLength = 128; // Max username + domain + separators = 121 characters
    let lpNameBuffer = Buffer.alloc(usernameBufferLength);
    let lpSize = ref.alloc(Types.ULONG, usernameBufferLength);
    let result = Secur.GetUserNameExA(
      SecurConst.EXTENDED_NAME_FORMAT_NameSamCompatible,
      lpNameBuffer,
      lpSize
    );
    if (result !== 1) {
      throw new Error(
        "Could not retrieve username and domain. Result: " +
          result +
          ", lpSize: " +
          ref.deref(lpSize)
      );
    }
    let fullUser = ref.readCString(lpNameBuffer, 0);
    let userSplit = fullUser.split("\\");
    let userInfo = {} as UserInfo;
    if (userSplit.length === 2) {
      userInfo.domain = userSplit[0];
      userInfo.username = userSplit[1];
    } else if (userSplit.length === 1) {
      userInfo.username = userSplit[0];
    } else {
      throw new Error("Could not parse full username: " + fullUser);
    }
    debug("Retrived userInfo:", userInfo);
    return userInfo;
  }

  private acquireCredentialsHandle(): any {
    let authData = new SecWinNtAuthIdentity({
      User: this.userInfo.username,
      UserLength: this.userInfo.username.length,
      Domain: this.userInfo.domain,
      DomainLength: this.userInfo.domain.length || 0,
      Password: "",
      PasswordLength: 0,
      Flags: SecurConst.SEC_WINNT_AUTH_IDENTITY_ANSI
    });
    let result = Secur.AcquireCredentialsHandleA(
      ref.NULL,
      this.securityPackageName,
      SecurConst.SECPKG_CRED_OUTBOUND,
      ref.NULL,
      authData.ref(),
      ref.NULL,
      ref.NULL,
      this.credHandle.ref(),
      this.lifeTime.ref()
    );

    if (result < 0) {
      throw new Error(
        "Could not acquire credentials handle. Result: " + result.toString(16)
      );
    }
    debug('Acquired Credentials handle:', this.credHandle);
  }

  private initializeCredentialsHandle(inSecBufferDesc: any, targetHost: string): InitializeSecurityContextA_Result {
    let result = 0;
    let spn = ref.allocCString('http/' + targetHost, 'ascii');
    if (inSecBufferDesc === undefined) {
      result = Secur.InitializeSecurityContextA(
        this.credHandle.ref(),
        ref.NULL,
        spn,
        SecurConst.ISC_REQ_CONFIDENTIALITY,
        0,
        SecurConst.SECURITY_NATIVE_DREP,
        ref.NULL,
        0,
        this.ctxHandle.ref(),
        this.outSecBufferDesc.ref(),
        this.ctxAttributesRef,
        this.lifeTime.ref()
      );
    } else {
      result = Secur.InitializeSecurityContextA(
        this.credHandle.ref(),
        this.ctxHandle.ref(),
        spn,
        ref.deref(this.ctxAttributesRef),
        0,
        SecurConst.SECURITY_NATIVE_DREP,
        inSecBufferDesc.ref(),
        0,
        this.ctxHandle.ref(),
        this.outSecBufferDesc.ref(),
        this.ctxAttributesRef,
        this.lifeTime.ref()
      );
    }
    if (result < 0) {
      throw new Error(
        "Could not init security context. Result: " + result + ", " + result.toString(16)
      );
    }
    debug("ctxAttributes", ref.deref(this.ctxAttributesRef));
    return result;
  }

  private deleteSecurityContext() {
    let result = Secur.DeleteSecurityContext(this.ctxHandle.ref());
    if (result !== 0) {
      throw new Error(
        "Could not delete security context. Result: " + result.toString(16)
      );
    }
    delete this.ctxHandle;
  }

  private freeCredentialsHandle() {
    let result = Secur.FreeCredentialsHandle(this.credHandle.ref());
    if (result !== 0) {
      throw new Error(
        "Could not free credentials handle. Result: " + result.toString(16)
      );
    }
    delete this.credHandle;
  }

  /**
   * Creates a NTLM type 1 authentication token
   * This allocates unmanaged memory buffers, the destroy method must be called
   * to free them (on error or after authentication is completed)
   * @param targetHost {string} The FQDN hostname of the target
   * @returns {Buffer} Raw token buffer
   */
  createAuthRequest(targetHost: string): Buffer {
    this.acquireCredentialsHandle();
    this.initializeCredentialsHandle(undefined, targetHost);
    let token = this.outToken.slice(0, this.getSecBufferLength(this.outSecBufferDesc));
    debug('Created NTLM type 1 token', token.toString('base64'));
    return token;
  }

  /**
   * Creates a NTLM type 1 www-authentication header (Authentication Request).
   * This allocates unmanaged memory buffers, the destroy method must be called
   * to free them (on error or after authentication is completed)
   * @param targetHost {string} The FQDN hostname of the target
   * @returns {string} The NTLM type 1 header
   */
  createAuthRequestHeader(targetHost: string): string {
    let header = 'NTLM ' + this.createAuthRequest(targetHost).toString('base64');
    return header;
  }

  /**
   * Creates a NTLM type 3 authentication token
   * @param inTokenHeader {string} The www-authentication header received from the target (NTLM type 2 token)
   * @param targetHost {string} The FQDN hostname of the target
   * @returns {Buffer} Raw token buffer
   */
  createAuthResponse(inTokenHeader: string, targetHost: string): Buffer {
    debug('Received NTLM type 2', inTokenHeader);
    let ntlmMatch = /^NTLM ([^,\s]+)/.exec(inTokenHeader);

	  if (!ntlmMatch) {
      throw new Error(
        'Invalid input token, missing NTLM prefix: ' + inTokenHeader
      );
    }
    let inToken = Buffer.from(ntlmMatch[1], 'base64');

    // Clear output buffer
    this.outToken = Buffer.alloc(this.maxTokenLength);
    this.outSecBufferDesc =
        this.createSecBufferDesc(this.outToken, this.maxTokenLength);

    let inSecBufferDesc = this.createSecBufferDesc(inToken, inToken.length);
    let result = this.initializeCredentialsHandle(inSecBufferDesc, targetHost);
    if (result !== InitializeSecurityContextA_Result.OK) {
      throw new Error('Unexpected return code from InitializeCredentialsHandleA when generating type 3 message:' + result.toString(16));
    }
    let token = this.outToken.slice(0, this.getSecBufferLength(this.outSecBufferDesc));
    debug('Created NTLM type 3 token', token.toString('base64'));
    return token;
  }

  /**
   * Creates a NTLM type 3 www-authentication header (Challenge Response)
   * @param inTokenHeader {string} The www-authentication header received from the target (NTLM type 2 token)
   * @param targetHost {string} The FQDN hostname of the target
   * @returns {string} The NTLM type 3 header
   */
  createAuthResponseHeader(inTokenHeader: string, targetHost: string): string {
    let header = 'NTLM ' + this.createAuthResponse(inTokenHeader, targetHost).toString('base64');
    return header;
  }

  /**
   * Frees the unmanaged memory allocated for the authentication context.
   */
  destroy() {
    this.deleteSecurityContext();
    this.freeCredentialsHandle();
  }
}
