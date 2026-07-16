// NEGATIVE: Safe command execution
const { execFile } = require('child_process');

function safeRun(filename) {
    // Safe: execFile with fixed executable and array args
    execFile('ls', [filename], callback);
    execFile('cat', [filename], { shell: false }, callback);
}
