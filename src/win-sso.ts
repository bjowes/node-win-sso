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

  /**
   * Retrieves the username of the logged in user
   * @returns {string} user name including domain
   */
  static getUserName(): string {
    return winSsoAddon.getUserName();
  }

  private static getChannelBindingsApplicationData(peerCert: PeerCertificate) {
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
   * Creates a NTLM type 1 authentication token
   * This allocates unmanaged memory buffers, the destroy method must be called
   * to free them (on error or after authentication is completed)
   * @returns {Buffer} Raw token buffer
   */
  static createAuthRequest(): Buffer {
    let token = winSsoAddon.createAuthRequest();
    debug('Created NTLM type 1 token', token.toString('base64'));
    return token;
  }

  /**
   * Creates a NTLM type 1 www-authentication header (Authentication Request).
   * This allocates unmanaged memory buffers, the destroy method must be called
   * to free them (on error or after authentication is completed)
   * @returns {string} The NTLM type 1 header
   */
  static createAuthRequestHeader(): string {
    let header = 'NTLM ' + this.createAuthRequest().toString('base64');
    return header;
  }

  /**
   * Creates a NTLM type 3 authentication token
   * @param inTokenHeader {string} The www-authentication header received from the target (NTLM type 2 token)
   * @param targetHost {string} The FQDN hostname of the target
   * @param peerCert {PeerCertificate | undefined} The certificate of the target server (optional, for HTTPS channel binding)
   * @returns {Buffer} Raw token buffer
   */
  static createAuthResponse(inTokenHeader: string, targetHost: string, peerCert: PeerCertificate | undefined): Buffer {
    debug('Received NTLM type 2', inTokenHeader);
    let ntlmMatch = /^NTLM ([^,\s]+)/.exec(inTokenHeader);

	  if (!ntlmMatch) {
      throw new Error(
        'Invalid input token, missing NTLM prefix: ' + inTokenHeader
      );
    }
    let inToken = Buffer.from(ntlmMatch[1], 'base64');
    let applicationData: Buffer;
    if (peerCert) {
      applicationData = this.getChannelBindingsApplicationData(peerCert);
    } else {
      applicationData = Buffer.alloc(0);
    }

    let token = winSsoAddon.createAuthResponse(inToken, targetHost, applicationData);
    debug('Created NTLM type 3 token', token.toString('base64'));
    return token;
  }

  /**
   * Creates a NTLM type 3 www-authentication header (Challenge Response)
   * @param inTokenHeader {string} The www-authentication header received from the target (NTLM type 2 token)
   * @param targetHost {string} The FQDN hostname of the target
   * @param peerCert {PeerCertificate | undefined} The certificate of the target server (optional, for HTTPS channel binding)
   * @returns {string} The NTLM type 3 header
   */
  static createAuthResponseHeader(inTokenHeader: string, targetHost: string, peerCert: PeerCertificate | undefined): string {
    let header = 'NTLM ' + this.createAuthResponse(inTokenHeader, targetHost, peerCert).toString('base64');
    return header;
  }
}
