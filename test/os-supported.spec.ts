import { osSupported } from "../src/os-supported";
import assert from "assert";
import os from "os";

describe("osSupported", function () {
  it("should return true only on win32", function () {
    let currentOsIsWin32 = os.platform() === "win32";
    // Act
    let result = osSupported();

    // Assert
    assert.equal(result, currentOsIsWin32);
  });
});
