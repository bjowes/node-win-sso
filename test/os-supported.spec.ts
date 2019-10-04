import { osSupported } from '../src/os-supported';
import chai from 'chai';
import os from 'os';

describe('osSupported', function() {

  it('should return true only on win32', function() {
    let currentOsIsWin32 = (os.platform() === 'win32');
    // Act
    let result = osSupported();

    // Assert
    chai.expect(result).to.equal(currentOsIsWin32);
  });
});
