import os from "os";

/**
 * Returns true if the current platform is supported by the win-sso module. Only Windows OSs are supported.
 * If false, all other methods in the module will throw.
 *
 * @returns {boolean} Is the os supported
 */
export function osSupported(): boolean {
  return os.platform() === "win32";
}
