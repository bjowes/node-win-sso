const os = require('os');
const spawn = require('cross-spawn');

if (os.platform() === 'win32') {
  console.log('Windows OS detected. Building native module')
  spawn.sync('npm', ['run', 'native_build'], {
    input: 'win32 detected. Build native module.',
    stdio: 'inherit'
  });
} else {
  console.log('Unsupported OS detected. Native module requires Windows OS.');
}
