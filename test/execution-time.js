
var addon = require('bindings')('win-sso');

let t2 = 'TlRMTVNTUAACAAAADAAMADgAAAA1goniSkJuVLRnpXMAAAAAAAAAAKwArABEAAAABgOAJQAAAA9NAFAAQQBVAFQAVgACAAwATQBQAEEAVQBUAFYAAQAWAFUAVABWAFcARQBCAFMAUgBWADAAOAAEABoAbQBwAGEAdQB0AHYALgBtAHAAYQAuAHMAZQADADIAdQB0AHYAdwBlAGIAcwByAHYAMAA4AC4AbQBwAGEAdQB0AHYALgBtAHAAYQAuAHMAZQAFABoAbQBwAGEAdQB0AHYALgBtAHAAYQAuAHMAZQAHAAgAA2np9oBm1QEAAAAA';
let t2Buf = Buffer.from(t2, "base64");
let cbBuf = Buffer.from('af0bef0102030405', "hex");
let cycles = 10000;
let hrstart = process.hrtime()

for (let i = 0; i < cycles; i++) {
  let res = addon.createAuthRequest();
  res = addon.createAuthResponse(t2Buf, 'nisse.com', cbBuf);
}

let hrend = process.hrtime(hrstart)

console.info('Execution time (hr): %ds %dms', hrend[0], hrend[1] / 1000000)
console.info('Average time per handshake (hr): %dms', ((hrend[0] * 1000) + (hrend[1] / 1000000)) / cycles);
