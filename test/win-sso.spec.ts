import { WinSso } from "../src/win-sso";
import assert from "assert";
import os from "os";
//import ASN1 from 'asn1-parser';
const ASN1 = require("asn1-parser");

describe("WinSso", function () {
  before("Check OS", function () {
    if (os.platform() !== "win32") {
      this.skip();
    }
  });

  describe("getLogonUserName", function () {
    it("should return a username", function () {
      // Act
      let result = WinSso.getLogonUserName();

      // Assert
      assert.ok(result.length > 0);
      assert.ok(result.indexOf("\\") !== -1);
    });
  });

  describe("createAuthRequest", function () {
    describe("NTLM", function () {
      let winSso: WinSso;

      beforeEach(function () {
        winSso = new WinSso("NTLM", undefined, undefined);
      });

      afterEach(function () {
        winSso.freeAuthContext();
      });

      it("should return a token buffer", function () {
        // Act
        let result = winSso.createAuthRequest();

        // Assert
        assert.ok(result instanceof Buffer);
      });

      it("should not return an empty token buffer", function () {
        // Act
        let result = winSso.createAuthRequest();

        // Assert
        assert.ok(result.length > 0);
      });

      it("should provide a NTLM type 1 message", function () {
        // Act
        let result = winSso.createAuthRequest();

        // Assert
        let base64tokenHeader = result.slice(0, 12).toString("base64");
        let expectType1Header = Buffer.from(
          "NTLMSSP\0\x01\x00\x00\x00"
        ).toString("base64");
        assert.equal(base64tokenHeader, expectType1Header);
      });
    });

    describe("Negotiate", function () {
      let winSso: WinSso;

      beforeEach(function () {
        winSso = new WinSso("Negotiate", undefined, undefined);
      });

      afterEach(function () {
        winSso.freeAuthContext();
      });

      it("should return a token buffer", function () {
        // Act
        let result = winSso.createAuthRequest();

        // Assert
        assert.ok(result instanceof Buffer);
      });

      it("should not return an empty token buffer", function () {
        // Act
        let result = winSso.createAuthRequest();

        // Assert
        assert.ok(result.length > 0);
      });

      it("should provide a Negotiate type 1 message", function () {
        // Act
        let result = winSso.createAuthRequest();

        // Assert
        let dec = ASN1.ASN1.parse(result);
        assert.equal(dec.type, 0x60);
        assert.equal(dec.children.length, 2);
        assert.equal(dec.children[0].type, 6);
        assert.equal(dec.children[0].length, 6);
        // gss-api.OID - 1.3.6.1.5.5.2 (SPNEGO - Simple Protected Negotiation) - 0x2b0601050502
        let expectSpnego = Buffer.from("\x2b\x06\x01\x05\x05\x02").toString(
          "base64"
        );
        assert.equal(dec.children[0].value.toString("base64"), expectSpnego);
      });
    });
  });

  describe("createAuthRequestHeader", function () {
    describe("NTLM", function () {
      let winSso: WinSso;

      beforeEach(function () {
        winSso = new WinSso("NTLM", undefined, undefined);
      });

      afterEach(function () {
        winSso.freeAuthContext();
      });

      it("should return a token header", function () {
        // Act
        let result = winSso.createAuthRequestHeader();

        // Assert
        assert.ok(result.length > 0);
      });

      it("should prefix the token with 'NTLM '", function () {
        // Act
        let result = winSso.createAuthRequestHeader();

        // Assert
        assert.equal(result.indexOf("NTLM "), 0);
      });

      it("should provide a base64 encoded token from createAuthRequest", function () {
        // Act
        let result = winSso.createAuthRequestHeader();
        let token = winSso.createAuthRequest();
        let prefixLength = "NTLM ".length;

        // Assert
        assert.equal(result.substring(prefixLength), token.toString("base64"));
      });
    });

    describe("Negotiate", function () {
      let winSso: WinSso;

      beforeEach(function () {
        winSso = new WinSso("Negotiate", undefined, undefined);
      });

      afterEach(function () {
        winSso.freeAuthContext();
      });

      it("should return a token header", function () {
        // Act
        let result = winSso.createAuthRequestHeader();

        // Assert
        assert.ok(result.length > 0);
      });

      it("should prefix the token with 'Negotiate '", function () {
        // Act
        let result = winSso.createAuthRequestHeader();

        // Assert
        assert.equal(result.indexOf("Negotiate "), 0);
      });

      it("should provide a base64 encoded token from createAuthRequest", function () {
        // Act
        let result = winSso.createAuthRequestHeader();
        let token = winSso.createAuthRequest();
        let prefixLength = "Negotiate ".length;

        // Assert
        assert.equal(result.substring(prefixLength), token.toString("base64"));
      });
    });
  });

  describe("createAuthResponse", function () {
    const type2MessageHeader =
      "NTLM TlRMTVNTUAACAAAAFAAUADgAAAAFAIkCU3J2Tm9uY2UAAAAAAAAAAJYAlgBMAAAACgC6RwAAAA9VAFIAUwBBAC0ATQBJAE4ATwBSAAEAEABNAE8AUwBJAFMATABFAFkAAgAUAFUAUgBTAEEALQBNAEkATgBPAFIAAwAmAE0AbwBzAEkAcwBsAGUAeQAuAHUAcgBzAGEALgBtAGkAbgBvAHIABAAUAHUAcgBzAGEALgBtAGkAbgBvAHIABQAUAHUAcgBzAGEALgBtAGkAbgBvAHIABwAIAKUvIxkwMNUBAAAAAA==";
    const targetHost = "MosIsley.ursa.minor";
    let winSso: WinSso;

    beforeEach(function () {
      winSso = new WinSso("NTLM", targetHost, undefined);
    });

    afterEach(function () {
      winSso.freeAuthContext();
    });

    it("should return a token buffer", function () {
      winSso.createAuthRequest();

      // Act
      let result = winSso.createAuthResponse(type2MessageHeader);

      // Assert
      assert.ok(result instanceof Buffer);
      assert.ok(result.length > 0);
    });

    it("should not return an empty token buffer", function () {
      winSso.createAuthRequest();

      // Act
      let result = winSso.createAuthResponse(type2MessageHeader);

      // Assert
      assert.ok(result.length > 0);
    });

    it("should provide a NTLM type 3 message", function () {
      winSso.createAuthRequest();

      // Act
      let result = winSso.createAuthResponse(type2MessageHeader);

      // Assert
      let base64tokenHeader = result.slice(0, 12).toString("base64");
      let expectType3Header = Buffer.from("NTLMSSP\0\x03\x00\x00\x00").toString(
        "base64"
      );
      assert.equal(base64tokenHeader, expectType3Header);
    });

    it("should provide a NTLM type 3 message when passed a PeerCertificate", function () {
      // Arrange
      let fingerprint = "00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF";
      let fakeCert: any = {
        fingerprint256: fingerprint,
      };
      let winSsoCert = new WinSso("NTLM", targetHost, fakeCert);
      winSsoCert.createAuthRequest();

      // Act
      let result = winSsoCert.createAuthResponse(type2MessageHeader);
      winSsoCert.freeAuthContext();

      // Assert
      let base64tokenHeader = result.slice(0, 12).toString("base64");
      let expectType3Header = Buffer.from("NTLMSSP\0\x03\x00\x00\x00").toString(
        "base64"
      );
      assert.equal(base64tokenHeader, expectType3Header);
    });

    it("should provide a NTLM type 3 message with undefined targetHost", function () {
      winSso.createAuthRequest();

      // Act
      let result = winSso.createAuthResponse(type2MessageHeader);

      // Assert
      let base64tokenHeader = result.slice(0, 12).toString("base64");
      let expectType3Header = Buffer.from("NTLMSSP\0\x03\x00\x00\x00").toString(
        "base64"
      );
      assert.equal(base64tokenHeader, expectType3Header);
    });

    // This test accepts two scenarios - success or throws a specific error. The background is that
    // we don't know the client settings where the test is executed - it might allow NTLMv1
    it("should provide a NTLM type 3 message from NTLM v1 challenge, if NTLMv1 is allowed by client", function () {
      // Arrange
      let ntlmV1_type2MessageHeader =
        "NTLM TlRMTVNTUAACAAAAAAAAAAAoAAABggAAASNFZ4mrze8AAAAAAAAAAA==";
      const expectNtlmV1error =
        "Could not create NTLM type 3 message. Incoming type 2 message uses NTLMv1, it is likely that the client is prevented from sending such messages. Update target host to use NTLMv2 (recommended) or adjust LMCompatibilityLevel on the client (insecure)";

      try {
        // Act
        winSso.createAuthRequest();
        let result = winSso.createAuthResponse(ntlmV1_type2MessageHeader);

        // Assert
        let base64tokenHeader = result.slice(0, 12).toString("base64");
        let expectType3Header = Buffer.from(
          "NTLMSSP\0\x03\x00\x00\x00"
        ).toString("base64");
        assert.equal(base64tokenHeader, expectType3Header);
      } catch (err) {
        // Assert
        assert.equal((err as Error).message, expectNtlmV1error);
      }
    });

    it("should throw if inToken is not a NTLM type 2 message", function () {
      // Arrange
      let dummyToken = "NOT NTLM AT ALL";
      winSso.createAuthRequest();

      // Act & Assert
      assert.throws(() => winSso.createAuthResponse(dummyToken));
    });
  });

  describe("createAuthResponseHeader", function () {
    const type2MessageHeader =
      "NTLM TlRMTVNTUAACAAAAFAAUADgAAAAFAIkCU3J2Tm9uY2UAAAAAAAAAAJYAlgBMAAAACgC6RwAAAA9VAFIAUwBBAC0ATQBJAE4ATwBSAAEAEABNAE8AUwBJAFMATABFAFkAAgAUAFUAUgBTAEEALQBNAEkATgBPAFIAAwAmAE0AbwBzAEkAcwBsAGUAeQAuAHUAcgBzAGEALgBtAGkAbgBvAHIABAAUAHUAcgBzAGEALgBtAGkAbgBvAHIABQAUAHUAcgBzAGEALgBtAGkAbgBvAHIABwAIAKUvIxkwMNUBAAAAAA==";
    const targetHost = "MosIsley.ursa.minor";
    let winSso: WinSso;

    beforeEach(function () {
      winSso = new WinSso("NTLM", targetHost, undefined);
    });

    afterEach(function () {
      winSso.freeAuthContext();
    });

    it("should return a token header", function () {
      winSso.createAuthRequest();

      // Act
      let result = winSso.createAuthResponseHeader(type2MessageHeader);

      // Assert
      assert.ok(result.length > 0);
    });

    it("should prefix the token with 'NTLM '", function () {
      winSso.createAuthRequest();

      // Act
      let result = winSso.createAuthResponseHeader(type2MessageHeader);

      // Assert
      assert.equal(result.indexOf("NTLM "), 0);
    });

    it("should provide a base64 encoded token from createAuthResponse", function () {
      let winSso2 = new WinSso("NTLM", targetHost, undefined);
      winSso.createAuthRequest();
      winSso2.createAuthRequest();

      // Act
      let result = winSso.createAuthResponseHeader(type2MessageHeader);
      let token = winSso2.createAuthResponse(type2MessageHeader);
      winSso2.freeAuthContext();

      // Assert
      // Since the token will contain unique challenge and timestamp values the two calls
      // won't be completely identical. Just check the first 64 base64 characters.
      assert.equal(
        result.substring(5, 5 + 64),
        token.toString("base64").substring(0, 64)
      );
    });
  });
});
