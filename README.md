# node-win-sso

NTLM single-sign-on for Node.js

## Introduction

When using web applications through popular browsers on Windows OS, the user can be logged in automatically to trusted sites that support Windows Authentication. This module allows Node.js applications to deliver a similar single-sign-on user experience, by utilizing native Win32 API calls.

## Installation

Only Windows OSs are supported. The module can be installed on any Node.js platform, but the native module won't be built.

```shell
npm install win-sso
```

## Usage

Usage of this module requires some knowledge of the NTLM handshake process. There are multiple sources for this on the web, a starting point could be:

* https://www.innovation.ch/personal/ronald/ntlm.html

_Example code of a full handshake will be provided later_

The WinSso class is stateless and all methods are static. No manual cleanup required.

### osSupported(): boolean

Utility function to simplify the case where an application supports multiple platforms, but NTLM single-sign-on is only supported on Windows OSs. Returns true if the platform is win32. If this returns false, all the methods below will throw.

### WinSso.getUserName(): string

Returns the domain and username of the user executing the Node.js process, in the standard format `DOMAIN\username`. The credentials of this user will be used for single-sign-on.

### WinSso.createAuthRequest(): Buffer

Returns the Authentication Request token as a buffer. This is the NTLM type 1 message.

### WinSso.createAuthRequestHeader(): string

Returns the Authentication Request header as a string. This is the token returned by WinSso.createAuthRequest() encoded as Base64, prefixed with the string 'NTLM '. This is the expected format of the Authorization header in a http/https request to the target server to initiate the NTLM handshake.

### WinSso.createAuthResponse(inTokenHeader: string, targetHost: string | undefined, peerCert: PeerCertificate | undefined): Buffer

Returns the Authentication Response token as a buffer. This is the NTLM type 3 message.

* inTokenHeader: The content of the 'www-authenticate' header in the response to the Authentication Request. It contains the NTLM type 2 message.
* targetHost (optional): The FQDN of the target host. This is used to build a SPN string in the NTLM message for enhanced security.
* peerCert (optional): If the connection is http, pass undefined. If the connection is https, pass the peer certificate to add Channel Binding to the NTLM message for enhanced security.

### WinSso.createAuthResponseHeader(inTokenHeader: string, targetHost: string | undefined, peerCert: PeerCertificate | undefined): string

Returns the Authentication Response header as a string. This is the token returned by WinSso.createAuthResponse() encoded as Base64, prefixed with the string 'NTLM '. This is the expected format of the Authorization header in a http/https request to the target server to finalize the NTLM handshake.

* inTokenHeader: The content of the 'www-authenticate' header in the response to the Authentication Request. It contains the NTLM type 2 message.
* targetHost (optional): The FQDN of the target host. This is used to build a SPN string in the NTLM message for enhanced security.
* peerCert (optional): If the connection is http, pass undefined. If the connection is https, pass the peer certificate to add Channel Binding to the NTLM message for enhanced security.

### Limitations

Currently only NTLM authentication is supported.

### Credits

The idea of implementation is based on the work of @snowytoxa, who presented the concept of retrieving NTLM tokens for the current user without any admin privileges in 2014. The source for his project [selfhash](https://github.com/snowytoxa/selfhash/) shortened the development time significantly.
