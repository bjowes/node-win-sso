import { WinSso } from '../src/win-sso';
import chai from 'chai';
import os from 'os';

describe('WinSso', function() {

  before('Check OS', function() {
    if (os.platform() !== 'win32') {
      this.skip();
    }
  });

  describe('getUserName', function () {
    it('should return a username', function() {
      // Act
      let result = WinSso.getUserName();

      // Assert
      chai.expect(result.length).to.be.greaterThan(0);
      chai.expect(result).to.contain('\\');
    });
  });

  describe('createAuthRequest', function () {
    it('should return a token buffer', function() {
      // Act
      let result = WinSso.createAuthRequest();

      // Assert
      chai.expect(result).to.be.instanceOf(Buffer);
    });

    it('should not return an empty token buffer', function() {
      // Act
      let result = WinSso.createAuthRequest();

      // Assert
      chai.expect(result.length).to.be.greaterThan(0);
    });

    it('should provide a NTLM type 1 message', function() {
      // Act
      let result = WinSso.createAuthRequest();

      // Assert
      let base64tokenHeader = result.slice(0,12).toString('base64');
      let expectType1Header = Buffer.from("NTLMSSP\0\x01\x00\x00\x00").toString('base64');
      chai.expect(base64tokenHeader).to.equal(expectType1Header);
    });
  });

  describe('createAuthRequestHeader', function () {
    it('should return a token header', function() {
      // Act
      let result = WinSso.createAuthRequestHeader();

      // Assert
      chai.expect(result.length).to.be.greaterThan(0);
    });

    it('should prefix the token with \'NTLM \'', function() {
      // Act
      let result = WinSso.createAuthRequestHeader();

      // Assert
      chai.expect(result.indexOf('NTLM ')).to.equal(0);
    });

    it('should provide a base64 encoded token from createAuthRequest', function() {
      // Act
      let result = WinSso.createAuthRequestHeader();
      let token = WinSso.createAuthRequest();

      // Assert
      chai.expect(result.substring(5)).to.equal(token.toString('base64'));
    });
  });

  describe('createAuthResponse', function () {
    const type2MessageHeader = 'NTLM TlRMTVNTUAACAAAAFAAUADgAAAAFAIkCU3J2Tm9uY2UAAAAAAAAAAJYAlgBMAAAACgC6RwAAAA9VAFIAUwBBAC0ATQBJAE4ATwBSAAEAEABNAE8AUwBJAFMATABFAFkAAgAUAFUAUgBTAEEALQBNAEkATgBPAFIAAwAmAE0AbwBzAEkAcwBsAGUAeQAuAHUAcgBzAGEALgBtAGkAbgBvAHIABAAUAHUAcgBzAGEALgBtAGkAbgBvAHIABQAUAHUAcgBzAGEALgBtAGkAbgBvAHIABwAIAKUvIxkwMNUBAAAAAA==';
    const targetHost = 'MosIsley.ursa.minor';

    it('should return a token buffer', function() {
      // Act
      let result = WinSso.createAuthResponse(type2MessageHeader, targetHost, undefined);

      // Assert
      chai.expect(result).to.be.instanceOf(Buffer);
      chai.expect(result.length).to.be.greaterThan(0);
    });

    it('should not return an empty token buffer', function() {
      // Act
      let result = WinSso.createAuthResponse(type2MessageHeader, targetHost, undefined);

      // Assert
      chai.expect(result.length).to.be.greaterThan(0);
    });

    it('should provide a NTLM type 3 message', function() {
      // Act
      let result = WinSso.createAuthResponse(type2MessageHeader, targetHost, undefined);

      // Assert
      let base64tokenHeader = result.slice(0,12).toString('base64');
      let expectType1Header = Buffer.from("NTLMSSP\0\x03\x00\x00\x00").toString('base64');
      chai.expect(base64tokenHeader).to.equal(expectType1Header);
    });

    it('should provide a NTLM type 3 message when passed a PeerCertificate', function() {
      // Arrange
      let fingerprint = '00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF';
      let fakeCert: any = {
        fingerprint256: fingerprint
      };

      // Act
      let result = WinSso.createAuthResponse(type2MessageHeader, targetHost, fakeCert);

      // Assert
      let base64tokenHeader = result.slice(0,12).toString('base64');
      let expectType1Header = Buffer.from("NTLMSSP\0\x03\x00\x00\x00").toString('base64');
      chai.expect(base64tokenHeader).to.equal(expectType1Header);
    });

    it('should throw if inToken is not a NTLM type 2 message', function() {
      // Arrange
      let dummyToken = 'NOT NTLM AT ALL';

      // Act & Assert
      chai.expect(() => WinSso.createAuthResponse(dummyToken, targetHost, undefined)).to.throw();
    });
  });

  describe('createAuthResponseHeader', function () {
    const type2MessageHeader = 'NTLM TlRMTVNTUAACAAAAFAAUADgAAAAFAIkCU3J2Tm9uY2UAAAAAAAAAAJYAlgBMAAAACgC6RwAAAA9VAFIAUwBBAC0ATQBJAE4ATwBSAAEAEABNAE8AUwBJAFMATABFAFkAAgAUAFUAUgBTAEEALQBNAEkATgBPAFIAAwAmAE0AbwBzAEkAcwBsAGUAeQAuAHUAcgBzAGEALgBtAGkAbgBvAHIABAAUAHUAcgBzAGEALgBtAGkAbgBvAHIABQAUAHUAcgBzAGEALgBtAGkAbgBvAHIABwAIAKUvIxkwMNUBAAAAAA==';
    const targetHost = 'MosIsley.ursa.minor';

    it('should return a token header', function() {
      // Act
      let result = WinSso.createAuthResponseHeader(type2MessageHeader, targetHost, undefined);

      // Assert
      chai.expect(result.length).to.be.greaterThan(0);
    });

    it('should prefix the token with \'NTLM \'', function() {
      // Act
      let result = WinSso.createAuthResponseHeader(type2MessageHeader, targetHost, undefined);

      // Assert
      chai.expect(result.indexOf('NTLM ')).to.equal(0);
    });

    it('should provide a base64 encoded token from createAuthResponse', function() {
      // Act
      let result = WinSso.createAuthResponseHeader(type2MessageHeader, targetHost, undefined);
      let token = WinSso.createAuthResponse(type2MessageHeader, targetHost, undefined);

      // Assert
      // Since the token will contain unique challenge and timestamp values the two calls
      // won't be completely identical. Just check the first 64 base64 characters.
      chai.expect(result.substring(5, 5+64)).to.equal(token.toString('base64').substring(0,64));
    });
  });
});
