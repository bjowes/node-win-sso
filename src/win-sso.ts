import { debug } from "./utils/debug.logger";
import { PeerCertificate } from "tls";
import path from "path";

let winSsoAddon: any;
try {
  winSsoAddon = require("node-gyp-build")(path.join(__dirname, ".."));
  debug("Loaded win-sso native module");
} catch (err) {
  debug("Could not load win-sso native module");
}

/**
 * Creates authentication tokens for NTLM or Negotiate handshake using the executing users credentials.
 */
export class WinSso {
  private static NEGOTIATE_NTLM2_KEY = 1 << 19;

  private authContextId: number;
  private securityPackage: string;

  /**
   * Creates an authentication context for SSO.
   * This allocates memory buffers, the freeAuthContext method should be called
   * to free them (on error or after authentication is no longer needed)
   *
   * @param {string} securityPackage The name of the security package (NTLM or Negotiate)
   * @param {string | undefined} targetHost The FQDN hostname of the target (optional for NTLM, required for Kerberos)
   * @param {PeerCertificate | undefined} peerCert The certificate of the target server
   * (optional, for HTTPS channel binding)
   * @param {number | undefined} flags Flags to set in the authentication context
   * If not set, NTML defaults to no flags, while Negotiate defaults to ISC_REQ_MUTUAL_AUTH | ISC_REQ_SEQUENCE_DETECT
   * (optional, allows customizing security features)
   */
  constructor(
    securityPackage: string,
    targetHost: string | undefined,
    peerCert: PeerCertificate | undefined,
    flags: number | undefined
  ) {
    this.securityPackage = securityPackage;
    let applicationData: Buffer;
    if (!targetHost) {
      targetHost = "";
    }
    if (peerCert) {
      applicationData = this.getChannelBindingsApplicationData(peerCert);
    } else {
      applicationData = Buffer.alloc(0);
    }
    this.authContextId = winSsoAddon.createAuthContext(
      securityPackage,
      targetHost,
      applicationData,
      flags
    );
  }

  /**
   * Retrieves the username of the logged in user
   *
   * @returns {string} user name including domain
   */
  static getLogonUserName(): string {
    return winSsoAddon.getLogonUserName();
  }

  /**
   * Transforms target TLS certificate into a channel binding application data buffer
   *
   * @param {PeerCertificate} peerCert Target TLS certificate
   * @returns {Buffer} Application data buffer
   */
  private getChannelBindingsApplicationData(peerCert: PeerCertificate): Buffer {
    const cert: any = peerCert;
    const hash = cert.fingerprint256.replace(/:/g, "");
    const hashBuf = Buffer.from(hash, "hex");
    const tlsServerEndPoint = "tls-server-end-point:";
    const applicationDataBuffer = Buffer.alloc(
      tlsServerEndPoint.length + hashBuf.length
    );
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
   * Creates an authentication request token
   *
   * @returns {Buffer} Raw token buffer
   */
  createAuthRequest(): Buffer {
    const token = winSsoAddon.createAuthRequest(this.authContextId);
    debug(
      "Created " + this.securityPackage + " authentication request token",
      token.toString("base64")
    );
    return token;
  }

  /**
   * Creates an authentication request header
   *
   * @returns {string} The www-authenticate header
   */
  createAuthRequestHeader(): string {
    const header =
      this.securityPackage + " " + this.createAuthRequest().toString("base64");
    return header;
  }

  /**
   * Creates an authentication response token
   *
   * @param {string} inTokenHeader The www-authentication header received from the target
   * in response to the authentication request
   * @returns {Buffer} Raw token buffer. May be empty if Negotiate handshake  is complete.
   */
  createAuthResponse(inTokenHeader: string): Buffer {
    debug("Received www-authentication response", inTokenHeader);
    const packageMatch = new RegExp(
      "^" + this.securityPackage + "\\s([^,\\s]+)"
    ).exec(inTokenHeader);

    if (!packageMatch) {
      throw new Error(
        "Invalid input token, missing " +
          this.securityPackage +
          " prefix: " +
          inTokenHeader
      );
    }
    const inToken = Buffer.from(packageMatch[1], "base64");
    try {
      const token = winSsoAddon.createAuthResponse(this.authContextId, inToken);
      if (token.length > 0) {
        debug(
          "Created " + this.securityPackage + " authentication response token",
          token.toString("base64")
        );
      } else {
        debug("No response token, authentication complete");
      }
      return token;
    } catch (err) {
      if (
        (err as Error).message ===
        "Could not init security context. Result: -2146893054"
      ) {
        // If incoming token is for NTLMv1, this error can occur when
        // LMCompatibilityLevel prevents the client to send NTLMv1 messages
        if (this.securityPackage === "NTLM" && this.isNtlmV1(inToken)) {
          throw new Error(
            "Could not create NTLM type 3 message. Incoming type 2 message uses NTLMv1, " +
              "it is likely that the client is prevented from sending such messages. " +
              "Update target host to use NTLMv2 (recommended) or adjust LMCompatibilityLevel on the client (insecure)"
          );
        }
      }
      throw err;
    }
  }

  // eslint-disable-next-line require-jsdoc
  private isNtlmV1(type2message: Buffer): boolean {
    if (type2message.length >= 24) {
      const inTokenFlags = type2message.readInt32BE(20);
      if ((inTokenFlags & WinSso.NEGOTIATE_NTLM2_KEY) === 0) {
        return true;
      }
    }
    return false;
  }

  /**
   * Creates an authentication response header
   *
   * @param {string} inTokenHeader The www-authentication header received from the target
   * in response to the authentication request
   * @returns {string} The www-authenticate header. May be an empty string if Negotiate handshake is complete.
   */
  createAuthResponseHeader(inTokenHeader: string): string {
    const tokenBuffer = this.createAuthResponse(inTokenHeader);
    if (tokenBuffer.length == 0) {
      return "";
    }
    const header = this.securityPackage + " " + tokenBuffer.toString("base64");
    return header;
  }
}
