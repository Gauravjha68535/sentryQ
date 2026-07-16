// POSITIVE: Command injection
const { exec, execSync } = require('child_process');

function runCommand(req) {
    const cmd = req.query.cmd;
    // Unsafe: template literal in exec
    exec(`ls ${cmd}`);
    execSync(`ping ${req.body.host}`);
    // Unsafe: concatenation in exec
    exec("cat " + req.params.filename);
}
