const os = require('os');
const spawn = require('cross-spawn');

if (os.platform() === 'win32') {
  console.log('Windows OS detected. Prebuilding native modules')
  spawn.sync('npm', ['run', 'native_prebuildify'], {
    input: 'Windows OS detected. Prebuilding native module.',
    stdio: 'inherit'
  });
} else {
  console.log('Unsupported OS detected. Native module requires Windows OS. Aborting prebuildify.');
}
