import { WinSso } from '../src/win-sso';
import chai from 'chai';

describe('WinSso', function() {
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
      chai.expect(result.length).to.be.greaterThan(0);
    });
  });

  describe('createAuthRequestHeader', function () {
    it('should return a token header', function() {
      // Act
      let result = WinSso.createAuthRequestHeader();

      // Assert
      chai.expect(result.length).to.be.greaterThan(0);
      chai.expect(result.indexOf('NTLM ')).to.equal(0);
    });
  });

  // TODO: createAuthResponse, createAuthResponseHeader
});
