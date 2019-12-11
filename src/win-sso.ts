import { debug } from './utils/debug.logger';
import { PeerCertificate } from 'tls';
import path from 'path';

let winSsoAddon: any;
try {
  winSsoAddon = require('node-gyp-build')(path.join(__dirname, '..'));
  debug('Loaded win-sso native module');
} catch (err) {
  debug('Could not load win-sso native module');
}

/**
 * Creates authentication tokens for NTLM handshake using the executing users credentials.
 */
export class WinSso {

  private authContextId: number;
  private securityPackage: string;

  /**
   * Creates an authentication context for SSO
   * @param securityPackage {string} The name of the security package (NTLM or Negotiate)
   * @param targetHost {string | undefind} The FQDN hostname of the target (optional)
   * @param peerCert {PeerCertificate | undefined} The certificate of the target server (optional, for HTTPS channel binding)
   */
  constructor(securityPackage: string, targetHost: string | undefined, peerCert: PeerCertificate | undefined) {
    this.securityPackage = securityPackage;
    let applicationData: Buffer;
    if (peerCert) {
      applicationData = this.getChannelBindingsApplicationData(peerCert);
    } else {
      applicationData = Buffer.alloc(0);
    }
    this.authContextId = winSsoAddon.createAuthContext(securityPackage, targetHost, applicationData);
  }

  /**
   * Retrieves the username of the logged in user
   * @returns {string} user name including domain
   */
  static getUserName(): string {
    return winSsoAddon.getUserName();
  }

  private getChannelBindingsApplicationData(peerCert: PeerCertificate) {
    let cert: any = peerCert;
    let hash = cert.fingerprint256.replace(/:/g, '');
    let hashBuf = Buffer.from(hash, 'hex');
    let tlsServerEndPoint = 'tls-server-end-point:';
    let applicationDataBuffer = Buffer.alloc(tlsServerEndPoint.length + hashBuf.length);
    applicationDataBuffer.write(tlsServerEndPoint, 0, "ascii");
    hashBuf.copy(applicationDataBuffer, tlsServerEndPoint.length);
    return applicationDataBuffer;
  }

  /**
   * Releases all allocated resources for the authorization context.
   * Should be called when the context is no longer required, such as when the
   * socket was closed.
   */
  freeAuthContext() {
    winSsoAddon.freeAuthContext(this.authContextId);
  }


  /**
   * Creates a NTLM type 1 authentication token
   * This allocates unmanaged memory buffers, the destroy method must be called
   * to free them (on error or after authentication is completed)
   * @returns {Buffer} Raw token buffer
   */
  createAuthRequest(): Buffer {
    let token = winSsoAddon.createAuthRequest(this.authContextId);
    debug('Created ' + this.securityPackage + ' type 1 token', token.toString('base64'));
    return token;
  }

  /**
   * Creates a NTLM type 1 www-authentication header (Authentication Request).
   * This allocates unmanaged memory buffers, the destroy method must be called
   * to free them (on error or after authentication is completed)
   * @returns {string} The NTLM type 1 header
   */
  createAuthRequestHeader(): string {
    let header = this.securityPackage + ' ' + this.createAuthRequest().toString('base64');
    return header;
  }

  /**
   * Creates a NTLM type 3 authentication token
   * @param inTokenHeader {string} The www-authentication header received from the target (NTLM type 2 token)
   * @returns {Buffer} Raw token buffer
   */
  createAuthResponse(inTokenHeader: string): Buffer {
    debug('Received ' + this.securityPackage + ' type 2', inTokenHeader);
    let packageMatch = new RegExp('^' + this.securityPackage + '([^,\s]+)').exec(inTokenHeader);

	  if (!packageMatch) {
      throw new Error(
        'Invalid input token, missing ' + this.securityPackage + ' prefix: ' + inTokenHeader
      );
    }
    let inToken = Buffer.from(packageMatch[1], 'base64');
    let token = winSsoAddon.createAuthResponse(this.authContextId, inToken);
    debug('Created ' + this.securityPackage + ' type 3 token', token.toString('base64'));
    return token;
  }

  /**
   * Creates a NTLM type 3 www-authentication header (Challenge Response)
   * @param inTokenHeader {string} The www-authentication header received from the target (NTLM type 2 token)
   * @returns {string} The NTLM type 3 header
   */
  createAuthResponseHeader(inTokenHeader: string): string {
    let header = this.securityPackage + ' ' + this.createAuthResponse(inTokenHeader).toString('base64');
    return header;
  }
}
