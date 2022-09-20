# node-win-sso

NTLM and Negotiate single-sign-on for Node.js

## Introduction

When using web applications through popular browsers on Windows OS, the user can be logged in automatically to trusted sites that support Windows Authentication. This module allows Node.js applications to deliver a similar single-sign-on user experience, by utilizing native Win32 API calls.

## Installation

Only Windows OSs are supported. The module can be installed on any Node.js platform, but the native module won't be built.

```shell
npm install win-sso
```

## Usage

Usage of this module requires some knowledge of the NTLM or Negotiate handshake process. There are multiple sources for this on the web, a starting point for NTLM could be:

* https://www.innovation.ch/personal/ronald/ntlm.html

### Brief NTLM example

1. Client: Send http request to server (with FQDN `app.server.com`)
2. Server: Respond with 401 where the `www-authenticate` header includes NTLM
3. Client: Create WinSso instance for NTLM:
`let winSso = new WinSso('NTLM', 'app.server.com', undefined, false);`
4. Client: Get authentication request token:
`let authRequestToken = winSso.createAuthRequestHeader();`
5. Client: Resend the http request to the server, setting the `authorization` header to the value of the token
6. Server: Respond with 401 where the `www-authenticate` header contains the server response token
7. Client: Get authentication response token:
`let authResponseToken = winSso.createAuthResponseHeader(serverResponseToken);`
8. Client: Resend the http request to the server, setting the `authorization` header to the value of the token
9. Authentication complete, the server responds to the actual request.

The NTLM handshake always follows this pattern.

### Brief Negotiate example

1. Client: Send http request to server (with FQDN `app.server.com`)
2. Server: Respond with 401 where the `www-authenticate` header includes `Negotiate`
3. Client: Create WinSso instance for Negotiate:
`let winSso = new WinSso('Negotiate', 'app.server.com', undefined, false);`
4. Client: Get authentication request token:
`let authRequestToken = winSso.createAuthRequestHeader();`
5. Client: Resend the http request to the server, setting the `authorization` header to the value of the token
6. Server: Respond with 401 where the `www-authenticate` header contains the server response token
7. Client: Validate the server response token:
`let authResponseToken = winSso.createAuthResponseHeader(serverResponseToken);`
8. If the token returned from step 7 has length 0, the authentication is complete and the client may parse the response content. Otherwise, continue with step 9.
9. Client: Resend the http request to the server, setting the `authorization` header to the value of the token
10. Server: Respond to the actual request where the `www-authenticate` header contains the server response token
11. Got to step 7

The number of round trips for a Negotiate (Kerberos) handshake varies, so the number of cycles of step 8-11 could be 0, 1, 2 or more. Therefore step 7 must always be done even when the server does not responds with status code 401. This validates that authentication is indeed complete.

To clarify, Negotiate actually means NTLM or Kerberos. In the past NTLM may have been more common in Negotiate scenarios, but currently Negotiate nearly always means Kerberos. The example above is for Kerberos.

### Utility methods

#### osSupported(): boolean

Utility method to simplify the case where an application supports multiple platforms, but single-sign-on is only supported on Windows OSs. Returns true if the platform is win32. If this returns false, all the methods below will throw.

### WinSso

This class provides an interface to create and use an authentication context. Due to protocol details, one instance of this class should be created for each connection (socket) communicating with an endpoint where single-sign-on should be used. The class will free the resources it has allocated when it is destroyed, but it is still recommended to call the freeAuthContext() method when the instance will no longer be used.

#### WinSso(securityPackage: string, targetHost: string | undefined, peerCert: PeerCertificate | undefined, flags: number | undefined)

Class constructor.

* securityPackage: The name of the authentication method to use. Valid values are 'NTLM' and 'Negotiate'.
* targetHost (optional): The FQDN of the target host. This is used to build a SPN string in the authentication message for enhanced security.
* peerCert (optional): If the connection is http, pass undefined. If the connection is https, pass the peer certificate to add Channel Binding to the authentication message for enhanced security.
* flags: Flags to set in the authentication context. If not set, NTML defaults to no flags, while Negotiate defaults to ISC_REQ_MUTUAL_AUTH | ISC_REQ_SEQUENCE_DETECT

#### WinSso.getUserName(): string

Static method that returns the domain and username of the user executing the Node.js process, in the standard format `DOMAIN\username`. The credentials of this user will be used for single-sign-on.

#### WinSso.createAuthRequest(): Buffer

Returns the Authentication Request token as a buffer. For NTLM this is the NTLM type 1 message, for Negotiate this is the NegTokenInit message.

#### WinSso.createAuthRequestHeader(): string

Returns the Authentication Request header as a string. This is the token returned by WinSso.createAuthRequest() encoded as Base64, prefixed with the security package name. This is the expected format of the `Authorization` header in a http/https request to the target server to initiate the NTLM/Negotiate handshake.

#### WinSso.createAuthResponse(inTokenHeader: string): Buffer

Returns the Authentication Response token as a buffer. For NTLM this is the NTLM type 3 message, for Negotiate this is the NegTokenResp message. May be an empty Buffer if Negotiate handshake is complete.

* inTokenHeader: The content of the 'www-authenticate' header in the response to the Authentication Request.

This method throws if the response could not be created. One such scenario is if the server requires NTLMv1, and the client settings does not permit NTLMv1.

#### WinSso.createAuthResponseHeader(inTokenHeader: string): string

Returns the Authentication Response header as a string. This is the token returned by WinSso.createAuthResponse() encoded as Base64, prefixed with the security package name. This is the expected format of the `Authorization` header in a http/https request to the target server to finalize the NTLM/Negotiate handshake. May be an empty string if Negotiate handshake is complete.

* inTokenHeader: The content of the 'www-authenticate' header in the response to the Authentication Request.

This method throws if the response could not be created. One such scenario is if the server requires NTLMv1, and the client settings does not permit NTLMv1.

#### WinSso.freeAuthContext()

Releases all allocated resources for the authorization context. Resources are also released when the instance is destroyed, but it is still recommended to call this method when the context is no longer required, such as when an error ocurred or when the socket was closed.

### Credits

The idea of implementation is based on the work of @snowytoxa, who presented the concept of retrieving NTLM tokens for the current user without any admin privileges in 2014. The source for his project [selfhash](https://github.com/snowytoxa/selfhash/) shortened the development time significantly.
