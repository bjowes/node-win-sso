import { osSupported } from "../src/os-supported.ts";
import assert from "node:assert";
import os from "node:os";

describe("osSupported", function () {
  it("should return true only on win32", function () {
    let currentOsIsWin32 = os.platform() === "win32";
    // Act
    let result = osSupported();

    // Assert
    assert.equal(result, currentOsIsWin32);
  });
});
